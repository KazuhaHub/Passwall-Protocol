package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	CapabilityDestinationPolicy                = "policy.destination.v1"
	IssueDestinationPolicyRejected             = "destination_policy_rejected"
	IssueDestinationPolicySniffingInsufficient = "destination_policy_sniffing_insufficient"
)

// CollectLevel requests collection only when the agent advertises the matching
// capability. Empty disables collection; no raw connection-log level exists.
type CollectLevel string

const (
	CollectHits         CollectLevel = "hits"
	CollectHitsAndUsage CollectLevel = "hits_and_usage"
)

type RuleAction string

const (
	RuleAllow   RuleAction = "allow"
	RuleBlock   RuleAction = "block"
	RuleObserve RuleAction = "observe"
)

// DestinationPolicy is ordered desired state, not a new stream. Collections
// inside rules are sorted unique sets; Rules itself must never be sorted by ID.
// Collection revisions fence data from a prior off/on or downgrade transition.
type DestinationPolicy struct {
	Rules           []DestinationRule `json:"rules"`
	Exempt          []SubjectKey      `json:"exempt,omitempty"`
	Collect         CollectLevel      `json:"collect,omitempty"`
	CollectRevision uint64            `json:"collect_revision,omitempty"`
}

// DestinationRule matches (Domains OR CIDRs OR Private), AND the other fields.
// CatchAll is explicit and scoped: an empty failed list cannot become deny-all.
type DestinationRule struct {
	ID        string       `json:"id"`
	Action    RuleAction   `json:"action"`
	Subjects  []SubjectKey `json:"subjects,omitempty"`
	Domains   []string     `json:"domains,omitempty"`
	CIDRs     []string     `json:"cidrs,omitempty"`
	Ports     string       `json:"ports,omitempty"`
	Network   string       `json:"network,omitempty"`
	Protocols []string     `json:"protocols,omitempty"`
	Private   bool         `json:"private,omitempty"`
	CatchAll  bool         `json:"catch_all,omitempty"`
}

// PolicyStatus describes the candidate actually applied or rejected because of
// destination policy. Unrelated listener/process failures must not replace it.
// The receiver validates this subtree separately from control-plane input.
type PolicyStatus struct {
	Digest    string        `json:"digest"`
	State     string        `json:"state"`
	IssueCode string        `json:"issue_code,omitempty"`
	Listeners []ListenerKey `json:"listeners,omitempty"`
}

var destinationRuleID = regexp.MustCompile(`^[pg][0-9]{1,12}(x[0-9]{1,4})?$`)
var destinationHostname = regexp.MustCompile(`^[a-z0-9._-]+$`)
var destinationPorts = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$`)

// ValidateDestinationPolicy never sorts or rewrites input. Producers must
// canonicalize sets before hashing, and consumers must preserve rule order.
func ValidateDestinationPolicy(p *DestinationPolicy) error {
	if p == nil {
		return nil
	}
	if len(p.Rules) > MaxDestinationRules {
		return fmt.Errorf("policy exceeds %d rules", MaxDestinationRules)
	}
	switch p.Collect {
	case "":
		if p.CollectRevision != 0 {
			return fmt.Errorf("disabled collection must have revision zero")
		}
	case CollectHits, CollectHitsAndUsage:
		if p.CollectRevision == 0 {
			return fmt.Errorf("collection revision must be positive")
		}
	default:
		return fmt.Errorf("unsupported collection level")
	}
	domains, cidrs, subjects, rawBytes := 0, 0, len(p.Exempt), len(p.Collect)
	for _, subject := range p.Exempt {
		rawBytes += len(subject)
	}
	for _, r := range p.Rules {
		domains += len(r.Domains)
		cidrs += len(r.CIDRs)
		subjects += len(r.Subjects)
		rawBytes += len(r.ID) + len(r.Action) + len(r.Ports) + len(r.Network)
		for _, v := range r.Domains {
			rawBytes += len(v)
		}
		for _, v := range r.CIDRs {
			rawBytes += len(v)
		}
		for _, v := range r.Subjects {
			rawBytes += len(v)
		}
		for _, v := range r.Protocols {
			rawBytes += len(v)
		}
		if domains > MaxDestinationDomains || cidrs > MaxDestinationCIDRs || subjects > MaxDestinationSubjects || rawBytes > MaxDestinationPolicyBytes {
			return fmt.Errorf("destination policy exceeds collection or byte bounds")
		}
	}
	if subjects > MaxDestinationSubjects || rawBytes > MaxDestinationPolicyBytes {
		return fmt.Errorf("destination policy exceeds collection or byte bounds")
	}
	encoded, err := json.Marshal(p)
	if err != nil || len(encoded) > MaxDestinationPolicyBytes {
		return fmt.Errorf("policy encoded size exceeds %d bytes", MaxDestinationPolicyBytes)
	}
	if err := validatePolicySubjects(p.Exempt); err != nil {
		return fmt.Errorf("exempt: %w", err)
	}
	seen := make(map[string]struct{}, len(p.Rules))
	regexps := 0
	for index, r := range p.Rules {
		if !destinationRuleID.MatchString(r.ID) {
			return fmt.Errorf("rule %d has invalid ID", index)
		}
		if _, ok := seen[r.ID]; ok {
			return fmt.Errorf("duplicate rule ID")
		}
		seen[r.ID] = struct{}{}
		if r.Action != RuleAllow && r.Action != RuleBlock && r.Action != RuleObserve {
			return fmt.Errorf("rule %s has invalid action", r.ID)
		}
		if err := validatePolicySubjects(r.Subjects); err != nil {
			return fmt.Errorf("rule %s subjects: %w", r.ID, err)
		}
		hasMatch := len(r.Domains) > 0 || len(r.CIDRs) > 0 || r.Ports != "" || r.Network != "" || len(r.Protocols) > 0 || r.Private
		if r.CatchAll {
			if hasMatch || len(r.Subjects) == 0 {
				return fmt.Errorf("catch-all rule %s requires subjects and no match fields", r.ID)
			}
		} else if !hasMatch {
			return fmt.Errorf("rule %s has no match fields", r.ID)
		}
		if r.Network != "" && r.Network != "tcp" && r.Network != "udp" {
			return fmt.Errorf("rule %s has invalid network", r.ID)
		}
		if r.Ports != "" {
			if err := validateDestinationPorts(r.Ports); err != nil {
				return fmt.Errorf("rule %s ports: %w", r.ID, err)
			}
		}
		if !strictPolicySet(r.Domains) || !strictPolicySet(r.CIDRs) || !strictPolicySet(r.Protocols) {
			return fmt.Errorf("rule %s sets must be sorted and unique", r.ID)
		}
		if len(r.Protocols) > 0 && len(r.Domains) > 0 {
			return fmt.Errorf("rule %s cannot combine domains and protocols", r.ID)
		}
		for _, v := range r.Protocols {
			if v != "bittorrent" {
				return fmt.Errorf("rule %s has unsupported protocol", r.ID)
			}
		}
		for _, v := range r.Domains {
			prefix, value, ok := strings.Cut(v, ":")
			if !ok || value == "" || !utf8.ValidString(value) {
				return fmt.Errorf("rule %s has invalid domain entry", r.ID)
			}
			switch prefix {
			case "domain", "full":
				if !canonicalDestinationHostname(value) {
					return fmt.Errorf("rule %s has noncanonical hostname", r.ID)
				}
			case "keyword":
			case "regexp":
				regexps++
				if regexps > MaxDestinationRegexps {
					return fmt.Errorf("too many destination expressions")
				}
				if _, err := regexp.Compile(value); err != nil {
					return fmt.Errorf("rule %s has invalid expression", r.ID)
				}
			default:
				return fmt.Errorf("rule %s has unsupported domain prefix", r.ID)
			}
		}
		for _, v := range r.CIDRs {
			prefix, err := netip.ParsePrefix(v)
			if err != nil || prefix.Masked().String() != v {
				return fmt.Errorf("rule %s has noncanonical CIDR", r.ID)
			}
		}
	}
	return nil
}

func strictPolicySet[S ~string](values []S) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] >= values[i] {
			return false
		}
	}
	return true
}

func validatePolicySubjects(subjects []SubjectKey) error {
	if !strictPolicySet(subjects) {
		return fmt.Errorf("subjects must be sorted and unique")
	}
	for _, subject := range subjects {
		if _, err := subject.RowID(); err != nil {
			return err
		}
	}
	return nil
}

func canonicalDestinationHostname(value string) bool {
	return len(value) > 0 && len(value) <= 253 && destinationHostname.MatchString(value)
}

func validateDestinationPorts(value string) error {
	if !destinationPorts.MatchString(value) {
		return fmt.Errorf("invalid port grammar")
	}
	for _, part := range strings.Split(value, ",") {
		start, end, rangePort := strings.Cut(part, "-")
		low, err := strconv.Atoi(start)
		if err != nil || low < 1 || low > 65535 {
			return fmt.Errorf("port outside 1..65535")
		}
		if rangePort {
			high, err := strconv.Atoi(end)
			if err != nil || high < low || high > 65535 {
				return fmt.Errorf("invalid port range")
			}
		}
	}
	return nil
}

// ValidatePolicyStatus checks only this observation, allowing a receiver to
// discard malformed status without rejecting roster/config synchronization.
func ValidatePolicyStatus(s PolicyStatus) error {
	if s.State != "applied" && s.State != "rejected" {
		return fmt.Errorf("invalid policy state")
	}
	if s.Digest != "" {
		if err := validateDigest(s.Digest); err != nil {
			return err
		}
	} else if s.State != "applied" {
		return fmt.Errorf("rejected policy requires digest")
	}
	if len(s.Listeners) > MaxPolicyStatusListeners || !strictPolicySet(s.Listeners) {
		return fmt.Errorf("policy listeners must be bounded, sorted and unique")
	}
	for _, key := range s.Listeners {
		if _, err := key.RowID(); err != nil {
			return err
		}
	}
	if s.State == "applied" {
		if s.IssueCode != "" || len(s.Listeners) > 0 {
			return fmt.Errorf("applied policy cannot carry rejection details")
		}
		return nil
	}
	if len(s.IssueCode) > MaxIssueCodeBytes || (s.IssueCode != IssueDestinationPolicyRejected && s.IssueCode != IssueDestinationPolicySniffingInsufficient) {
		return fmt.Errorf("invalid policy rejection issue")
	}
	if len(s.Listeners) > 0 && s.IssueCode != IssueDestinationPolicySniffingInsufficient {
		return fmt.Errorf("listeners only describe sniffing insufficiency")
	}
	return nil
}

// PolicyDigest is SHA-256 of the canonical producer's policy JSON. It preserves
// execution order and never mutates input. Validate before using an untrusted
// policy. Nil is the pre-feature no-policy identity and has an empty digest.
func PolicyDigest(p *DestinationPolicy) string {
	if p == nil {
		return ""
	}
	encoded, _ := json.Marshal(p)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
