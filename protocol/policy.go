package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// CapabilityDestinationPolicy says the agent understands ConfigBody.Policy and
// reports PolicyStatus. PSP sends a policy only to an agent that advertised it,
// and an agent that did not simply never sees the field.
//
// IT IS NOT AN UPGRADE CAPABILITY. AgentUpgradeCapabilities names what an agent
// must declare to be offered a binary upgrade; this one is deliberately absent
// from that set, so an old agent is not held back from upgrading by lacking it,
// and declaring it does not make an agent eligible for anything but a policy.
const CapabilityDestinationPolicy = "policy.destination.v1"

// CapabilityDestinationGroups says the agent enforces group rules (g*, phase 4)
// exactly as the wire specification orders them: in particular a protocol
// block (BitTorrent) is evaluated before a group member allow on every engine,
// including sing-box, whose pre-sniff pass cannot see protocols. PSP sends
// group rules only to an agent that advertised it, and only such an agent is
// eligible to serve the members of an allowlist group.
//
// It is meaningful only alongside CapabilityDestinationPolicy, and like it it
// is not an upgrade capability. ValidateDestinationPolicy cannot see
// capabilities: a policy holding g* rules may be sent only to an agent that
// advertised this one, and PSP is where that is enforced.
const CapabilityDestinationGroups = "policy.destination.groups.v1"

// CapabilityDestinationResolve says the agent compiles DestinationPolicy.Resolve
// on EVERY engine it runs: an agent that declares it enforces on_demand on Xray
// and on sing-box alike, or refuses the policy.
//
// IT GATES SENDING, AND THE GATE IS MANDATORY. An agent ignores a field it does
// not know, so an agent without this capability that is sent Resolve on_demand
// would accept the policy and silently run it as AsIs, with IP rules that never
// judge a hostname. PSP must therefore send a non-AsIs Resolve only to an agent
// that declared it. ValidateDestinationPolicy cannot see capabilities.
//
// It is meaningful only alongside CapabilityDestinationPolicy, and like it it is
// not an upgrade capability.
const CapabilityDestinationResolve = "policy.destination.resolve.v1"

// ResolveMode is whether the core resolves a hostname before it tries the IP
// rules (CIDRs, Private) on it.
//
// Only AsIs and on_demand exist. The third mode Xray offers, IPIfNonMatch, runs
// every rule without addresses first and resolves only when none hit. That
// reorders rules: an IP-only block ahead of a report-only (observe) domain rule
// is skipped when the observe rule hits in the first pass, so report-only would
// change a verdict, and a CIDR block ahead of a group member's domain allow
// would be skipped too. It is refused on the wire, not merely unoffered.
type ResolveMode string

const (
	// ResolveAsIs is the default and is encoded as the absence of the field, so
	// a policy that does not use Resolve keeps the digest it always had. Nothing
	// resolves a hostname when routing: CIDRs and Private are tried on an address
	// target only.
	ResolveAsIs ResolveMode = ""
	// ResolveOnDemand resolves the target hostname the first time a rule asks for
	// its addresses, once per connection, and tries every later IP alternative on
	// the same set, in rule order. It is the reference matcher with the resolved
	// addresses as input. Caveats, which a caller must repeat to an operator:
	//   - Xray fails OPEN when that lookup fails (the IP rules miss) and sing-box
	//     fails CLOSED (the connection fails);
	//   - Xray resolves again when it dials, so the address matched need not be
	//     the address dialed (a rebinding or round-robin name); sing-box dials the
	//     addresses it matched;
	//   - an inbound with sniffing routeOnly:true cannot run it (the sniffed name
	//     replaces the real target for the lookup), and on Xray domainStrategy
	//     is router-wide, so the whole NODE stays AsIs; see SniffForResolvedIPs;
	//   - ANY resolved address matching a rule is a match: a block is
	//     conservative, a CIDR allow is permissive, since the dial may use
	//     another address.
	ResolveOnDemand ResolveMode = "on_demand"
)

// RuleAction is what a matching rule does.
type RuleAction string

const (
	RuleBlock RuleAction = "block"
	// RuleObserve is report-only: the connection is allowed and the hit is
	// recorded. PSP emits it only while a policy is in its report state.
	//
	// REPORT-ONLY UNDER-REPORTS RELATIVE TO ENFORCE, ON PURPOSE. Observe rules
	// run in the last phase, after the exempt list and every allow (global and
	// group), so a connection an exempt subject or an allow rule would have
	// let through is never recorded as a would-be block, while enforce mode
	// would have blocked some of those only if they had reached a block rule.
	// Report-only must never change a verdict, and putting an observe rule
	// ahead of an allow would make it do so; the count it gives is therefore a
	// lower bound.
	RuleObserve RuleAction = "observe"
	RuleAllow   RuleAction = "allow"
)

// CollectLevel is how much destination data the agent may report back.
type CollectLevel string

const (
	CollectOff          CollectLevel = ""
	CollectHits         CollectLevel = "hits"
	CollectHitsAndUsage CollectLevel = "hits_and_usage"
)

// DestinationPolicy is the destination rule set for one agent. Everything in it
// is already in canonical form (slices sorted and duplicate-free, CIDRs
// masked), because its canonical JSON is what PolicyDigest hashes and what the
// agent echoes back to say which policy it holds.
type DestinationPolicy struct {
	Rules   []DestinationRule `json:"rules"`
	Exempt  []SubjectKey      `json:"exempt,omitempty"`
	Collect CollectLevel      `json:"collect,omitempty"`
	// Resolve is how hostnames meet the IP rules; see ResolveMode. AsIs is "",
	// omitted from the encoding. Send a non-AsIs value only to an agent that
	// declared CapabilityDestinationResolve.
	Resolve ResolveMode `json:"resolve,omitempty"`
}

// DestinationRule is one rule. Fields are ANDed; within a group that has
// several alternatives (SourceCIDRs, or Domains/CIDRs/Private) they are ORed.
type DestinationRule struct {
	// ID is p<id>[x<k>], g<gid>[x<k>] or s<n>; see rulePhase for what the
	// prefix means for evaluation order.
	ID          string        `json:"id"`
	Action      RuleAction    `json:"action"`
	Subjects    []SubjectKey  `json:"subjects,omitempty"` // empty = everyone
	Inbounds    []ListenerKey `json:"inbounds,omitempty"` // empty = every inbound
	SourceCIDRs []string      `json:"source_cidrs,omitempty"`
	// Domains entries carry a prefix: domain:, full:, keyword: or regexp:.
	//
	// DOMAINS, CIDRS AND PRIVATE ARE ALTERNATIVES: a rule matches when the
	// destination satisfies ANY of them (a hostname can satisfy only Domains,
	// an address only CIDRs or Private). They are ANDed with the other fields
	// (Subjects, Inbounds, Ports, Network, Protocols). Xray's own routing rule
	// ANDs `domain` and `ip`, so a compiler targeting it must split a rule that
	// has both into separate core rules; compiling one core rule would match
	// nothing, since no destination is both a hostname and an address.
	//
	// A TARGET WITH A TRAILING DOT IS NOT NORMALISED. xray-core hands matchers
	// the host as written (lowercased), so "example.com." passes `domain:`,
	// `full:` and an anchored regexp. When the policy has a block rule with
	// Domains, the compiler therefore emits a node-internal rule between the
	// exempt list and the block rules that blocks every hostname ending in "."
	// (Xray: regexp:\.$ to the blocked outbound, ruleTag psp-trailing-dot).
	// MatchDestination models it as a step with Builtin BuiltinTrailingDot, and
	// BuiltinTrailingDot says why the host is blocked rather than normalised.
	Domains []string `json:"domains,omitempty"`
	// CIDRs is the destination address alternative; see Domains. An address
	// written IPv4-mapped is matched as IPv4, and so IPv4-mapped prefixes are
	// not valid here.
	//
	// UNDER AsIs (THE DEFAULT) IT IS TRIED ON AN ADDRESS ONLY. The core
	// routes with AsIs: nothing resolves a hostname first, so a hostname that
	// resolves into one of these ranges is not matched by this rule (see
	// NoteHostnameSkipsIPRules). Under ResolveOnDemand the core resolves the
	// hostname and this rule is tried on the resolved addresses as well, any one
	// of which is enough; see ResolveMode for what that costs and where it fails.
	// On Xray, freedom's default block of private destinations can still stop a
	// private address after resolution, but only for some inbound kinds and
	// only after the operator's own final rules; see NoteHostnameSkipsIPRules
	// for exactly when. sing-box has no such default.
	//
	// DOMAIN RULES JUDGE THE NAME THE CLIENT SENT. A dotless hostname such as
	// "intranet" can be expanded by the node's DNS search list (the `search`
	// line of resolv.conf, common under Docker and Kubernetes), so the
	// connection may go to intranet.corp.example while every domain rule saw only
	// "intranet" and never the expanded name.
	CIDRs     []string `json:"cidrs,omitempty"`     // destination
	Ports     string   `json:"ports,omitempty"`     // "25,465,587" or "6881-6889"
	Network   string   `json:"network,omitempty"`   // "tcp", "udp" or ""
	Protocols []string `json:"protocols,omitempty"` // only "bittorrent"
	// Private matches a private or reserved destination address, exactly the
	// table PrivateDestinationCIDRs returns. It is an alternative to Domains
	// and CIDRs; see Domains, and see CIDRs for when a hostname is matched by it.
	Private  bool `json:"private,omitempty"`
	CatchAll bool `json:"catch_all,omitempty"`
}

// The rule phases. Rules must appear in non-decreasing phase order, and the
// exempt list is evaluated between phase 1 and phase 3, so an exempt subject is
// still subject to a source deny (0) and an explicit global allow (1) decides
// before the exemption is consulted.
const (
	phaseSourceDeny = 0
	phaseAllow      = 1
	phaseExempt     = 2
	phaseBlock      = 3
	phaseGroup      = 4
	phaseObserve    = 5
)

// ruleID is the parsed form of DestinationRule.ID.
type ruleID struct {
	kind      byte // 's', 'p' or 'g'
	suffixed  bool // has an x<k> suffix
	gid       string
	validForm bool
}

// parseRuleID accepts ^[pgs][0-9]{1,12}(x[0-9]{1,4})?$ with no leading zero in
// either number, and nothing else. It is
// hand-written rather than a regexp so it costs nothing on a fuzz loop.
func parseRuleID(id string) ruleID {
	if len(id) < 2 || (id[0] != 'p' && id[0] != 'g' && id[0] != 's') {
		return ruleID{}
	}
	rest := id[1:]
	number, suffix, suffixed := strings.Cut(rest, "x")
	if !canonicalDigits(number, 12) {
		return ruleID{}
	}
	if suffixed && !canonicalDigits(suffix, 4) {
		return ruleID{}
	}
	return ruleID{kind: id[0], suffixed: suffixed, gid: number, validForm: true}
}

// canonicalDigits is 1..max decimal digits with no leading zero ("0" itself is
// fine). The id is hashed as text, so p1 and p01 would be two policies.
func canonicalDigits(s string, max int) bool {
	return digitsBetween(s, 1, max) && (len(s) == 1 || s[0] != '0')
}

func digitsBetween(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// rulePhase places a rule in the evaluation order. ok is false for an ID or
// action that has no place in it.
func rulePhase(rule DestinationRule) (phase int, ok bool) {
	id := parseRuleID(rule.ID)
	if !id.validForm {
		return 0, false
	}
	switch id.kind {
	case 's':
		switch rule.Action {
		case RuleBlock:
			return phaseSourceDeny, true
		case RuleObserve:
			return phaseObserve, true
		}
	case 'p':
		switch rule.Action {
		case RuleAllow:
			return phaseAllow, true
		case RuleBlock:
			return phaseBlock, true
		case RuleObserve:
			return phaseObserve, true
		}
	case 'g':
		switch rule.Action {
		case RuleAllow, RuleBlock, RuleObserve:
			return phaseGroup, true
		}
	}
	return 0, false
}

// ValidateDestinationPolicy is the check both peers run on a policy: the panel
// before it ships one, the node before it compiles one. A nil policy is valid
// (no policy). Any violation makes the WHOLE policy invalid; there is no
// partial application, because a node that drops the rules it dislikes
// enforces something nobody wrote.
func ValidateDestinationPolicy(policy *DestinationPolicy) error {
	if policy == nil {
		return nil
	}
	switch policy.Collect {
	case CollectOff, CollectHits, CollectHitsAndUsage:
	default:
		return fmt.Errorf("collect %q is not one of off, hits, hits_and_usage", policy.Collect)
	}
	switch policy.Resolve {
	case ResolveAsIs, ResolveOnDemand:
	case "if_non_match":
		return fmt.Errorf("resolve %q is not supported: it would reorder rules and let report-only change a verdict; use on_demand or omit resolve", policy.Resolve)
	default:
		return fmt.Errorf("resolve %q is not one of \"\" (omitted) and on_demand", policy.Resolve)
	}
	// Rules is never null in a policy that exists: null and [] are different
	// bytes and so different digests, and a decoder reads `"rules":null` as nil.
	// A policy with no rules says so with [].
	if policy.Rules == nil {
		return fmt.Errorf("rules must be a list; use [] for a policy with no rules")
	}
	if len(policy.Rules) > MaxPolicyRules {
		return fmt.Errorf("policy has %d rules, maximum is %d", len(policy.Rules), MaxPolicyRules)
	}
	if err := validatePolicyTotals(policy); err != nil {
		return err
	}
	// The size bound is on the canonical bytes, so it is measured on them. The
	// counts above already bound how much there is to encode.
	encoded, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("policy does not encode: %w", err)
	}
	if len(encoded) > MaxPolicyBytes {
		return fmt.Errorf("policy is %d bytes, maximum is %d", len(encoded), MaxPolicyBytes)
	}

	if err := validateKeys("exempt", policy.Exempt, SubjectKey.RowID); err != nil {
		return err
	}
	seenIDs := make(map[string]struct{}, len(policy.Rules))
	groups := groupOrder{closed: map[string]bool{}, subjects: map[SubjectKey]string{}}
	lastPhase := phaseSourceDeny
	for index, rule := range policy.Rules {
		if err := validateRule(rule); err != nil {
			return fmt.Errorf("rules[%d] (%q): %w", index, rule.ID, err)
		}
		if _, exists := seenIDs[rule.ID]; exists {
			return fmt.Errorf("rules[%d]: duplicate rule id %q", index, rule.ID)
		}
		seenIDs[rule.ID] = struct{}{}
		phase, _ := rulePhase(rule) // validateRule accepted it
		if phase < lastPhase {
			return fmt.Errorf("rules[%d] (%q): phase %d follows phase %d; rules must be in non-decreasing phase order", index, rule.ID, phase, lastPhase)
		}
		lastPhase = phase
		if err := groups.next(rule); err != nil {
			return fmt.Errorf("rules[%d] (%q): %w", index, rule.ID, err)
		}
	}
	return groups.finish()
}

// groupOrder enforces that the rules of one group are contiguous: its member
// allows first, then exactly one catch-all last. Phase order puts every group
// rule in one block, but within it nothing else would stop one group's
// catch-all from sitting before another group's members, and "block the rest
// for this group" would then swallow rules written for someone else.
//
// A group is its subjects, so they are held to one set: every member rule has
// exactly the subjects of its catch-all (a member allow for someone the
// catch-all does not cover would be an allow with nothing to be an exception
// to, and the reverse a block that its members do not except), and no subject
// is in two groups (two catch-alls over one person, and which one applies would
// depend on order).
type groupOrder struct {
	open     string                // gid with members seen and no catch-all yet
	members  []SubjectKey          // the subjects of the open gid's members
	closed   map[string]bool       // gids whose catch-all has been seen
	subjects map[SubjectKey]string // the group each subject belongs to
}

func (g *groupOrder) next(rule DestinationRule) error {
	id := parseRuleID(rule.ID)
	if id.kind != 'g' {
		// Anything but a group rule ends the block, and a group still open has
		// no catch-all.
		if g.open != "" {
			return fmt.Errorf("group g%s has members but no catch-all before this rule", g.open)
		}
		return nil
	}
	if g.closed[id.gid] {
		return fmt.Errorf("group g%s already ended with its catch-all", id.gid)
	}
	if g.open != "" && g.open != id.gid {
		return fmt.Errorf("group g%s is interleaved with g%s", id.gid, g.open)
	}
	if id.suffixed {
		if g.open == id.gid && !slices.Equal(g.members, rule.Subjects) {
			return fmt.Errorf("group g%s members must all have the same subjects", id.gid)
		}
		g.open, g.members = id.gid, rule.Subjects
		return nil
	}
	if g.open == id.gid && !slices.Equal(g.members, rule.Subjects) {
		return fmt.Errorf("group g%s catch-all must have the subjects of its members", id.gid)
	}
	for _, subject := range rule.Subjects {
		if other, taken := g.subjects[subject]; taken {
			return fmt.Errorf("subject %q is in group g%s and in g%s", subject, other, id.gid)
		}
		g.subjects[subject] = id.gid
	}
	g.closed[id.gid] = true
	g.open, g.members = "", nil
	return nil
}

func (g *groupOrder) finish() error {
	if g.open != "" {
		return fmt.Errorf("group g%s has members but no catch-all", g.open)
	}
	return nil
}

func validatePolicyTotals(policy *DestinationPolicy) error {
	var domains, regexps, cidrs, sources, inbounds int
	subjects := len(policy.Exempt)
	for _, rule := range policy.Rules {
		domains += len(rule.Domains)
		for _, entry := range rule.Domains {
			if strings.HasPrefix(entry, "regexp:") {
				regexps++
			}
		}
		cidrs += len(rule.CIDRs)
		sources += len(rule.SourceCIDRs)
		subjects += len(rule.Subjects)
		inbounds += len(rule.Inbounds)
	}
	for _, limit := range []struct {
		name       string
		have, most int
	}{
		{"domains", domains, MaxPolicyDomains},
		{"regexps", regexps, MaxPolicyRegexps},
		{"destination cidrs", cidrs, MaxPolicyCIDRs},
		{"source cidrs", sources, MaxPolicySourceCIDRs},
		{"subjects", subjects, MaxPolicySubjects},
		{"inbounds", inbounds, MaxPolicyInbounds},
	} {
		if limit.have > limit.most {
			return fmt.Errorf("policy has %d %s, maximum is %d", limit.have, limit.name, limit.most)
		}
	}
	return nil
}

func validateRule(rule DestinationRule) error {
	id := parseRuleID(rule.ID)
	if !id.validForm {
		return fmt.Errorf("id must match ^[pgs][0-9]{1,12}(x[0-9]{1,4})?$")
	}
	switch rule.Action {
	case RuleBlock, RuleObserve, RuleAllow:
	default:
		return fmt.Errorf("action %q is not one of block, observe, allow", rule.Action)
	}

	hasMatch := len(rule.Domains) > 0 || len(rule.CIDRs) > 0 || rule.Ports != "" ||
		rule.Network != "" || len(rule.Protocols) > 0 || rule.Private
	switch id.kind {
	case 's':
		if id.suffixed {
			return fmt.Errorf("a source rule has no x suffix")
		}
		if rule.Action == RuleAllow {
			return fmt.Errorf("a source rule is block or observe, not allow")
		}
		if len(rule.SourceCIDRs) == 0 {
			return fmt.Errorf("a source rule needs source_cidrs")
		}
		if hasMatch || len(rule.Subjects) > 0 || rule.CatchAll {
			return fmt.Errorf("a source rule carries source_cidrs and optional inbounds only")
		}
	case 'g':
		if len(rule.Inbounds) > 0 {
			return fmt.Errorf("a group rule carries no inbounds")
		}
		// A group is a set of subjects; a group rule with none would apply to
		// everyone, which is what a p rule is for.
		if len(rule.Subjects) == 0 {
			return fmt.Errorf("a group rule needs subjects")
		}
		if id.suffixed {
			if rule.Action != RuleAllow {
				return fmt.Errorf("a group member rule is allow only")
			}
		} else {
			if rule.Action == RuleAllow {
				return fmt.Errorf("a group catch-all is block or observe, not allow")
			}
			if !rule.CatchAll {
				return fmt.Errorf("a group rule without an x suffix must be catch_all")
			}
		}
		// The catch-all is the bare g<gid>; a member (g<gid>x<k>) is an ordinary
		// match rule, so one spelling means one thing.
		if id.suffixed && rule.CatchAll {
			return fmt.Errorf("a group member rule must not be catch_all")
		}
	}
	if id.kind != 's' && len(rule.SourceCIDRs) > 0 {
		return fmt.Errorf("source_cidrs appear only on source rules")
	}

	// A rule that matches on nothing would match every connection. That is
	// legitimate only when it says so, and only for a named set of subjects:
	// "block everything for everyone" is never something a policy should be able
	// to say by leaving fields out.
	if rule.CatchAll {
		if hasMatch || len(rule.Inbounds) > 0 || len(rule.SourceCIDRs) > 0 {
			return fmt.Errorf("a catch-all rule has no match fields, inbounds or source_cidrs")
		}
		if len(rule.Subjects) == 0 {
			return fmt.Errorf("a catch-all rule needs subjects")
		}
	} else if !hasMatch && len(rule.SourceCIDRs) == 0 {
		return fmt.Errorf("a rule with no match field must be catch_all")
	}

	if err := validateKeys("subjects", rule.Subjects, SubjectKey.RowID); err != nil {
		return err
	}
	if err := validateKeys("inbounds", rule.Inbounds, ListenerKey.RowID); err != nil {
		return err
	}
	if err := validateCIDRList("source_cidrs", rule.SourceCIDRs); err != nil {
		return err
	}
	if err := validateCIDRList("cidrs", rule.CIDRs); err != nil {
		return err
	}
	if err := validateSortedUnique("domains", rule.Domains); err != nil {
		return err
	}
	for _, entry := range rule.Domains {
		if err := validateDomainEntry(entry); err != nil {
			return fmt.Errorf("domain %q: %w", entry, err)
		}
	}
	if rule.Ports != "" {
		if _, err := parsePorts(rule.Ports); err != nil {
			return err
		}
	}
	switch rule.Network {
	case "", "tcp", "udp":
	default:
		return fmt.Errorf("network %q is not tcp, udp or empty", rule.Network)
	}
	if err := validateSortedUnique("protocols", rule.Protocols); err != nil {
		return err
	}
	for _, protocol := range rule.Protocols {
		if protocol != "bittorrent" {
			return fmt.Errorf("protocol %q is not bittorrent", protocol)
		}
	}
	// Fields are ANDed, so Protocols and Domains in one rule would read as "this
	// protocol AND these domains", while the intent of a policy that lists both
	// is nearly always "either" (block bittorrent, and block these hosts). That
	// is two rules, which PSP emits as x1 and x2. Refusing the combination keeps
	// the AND reading from being written by accident.
	if len(rule.Protocols) > 0 && len(rule.Domains) > 0 {
		return fmt.Errorf("protocols and domains cannot share a rule")
	}
	return nil
}

func validateSortedUnique[T ~string](name string, items []T) error {
	for index := 1; index < len(items); index++ {
		if items[index-1] >= items[index] {
			return fmt.Errorf("%s must be sorted ascending without duplicates (%q before %q)", name, items[index-1], items[index])
		}
	}
	return nil
}

func validateKeys[T ~string](name string, keys []T, rowID func(T) (int64, error)) error {
	if err := validateSortedUnique(name, keys); err != nil {
		return err
	}
	for _, key := range keys {
		if _, err := rowID(key); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func validateCIDRList(name string, cidrs []string) error {
	if err := validateSortedUnique(name, cidrs); err != nil {
		return err
	}
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("%s: %q: %w", name, cidr, err)
		}
		// One spelling per prefix: the list is sorted and hashed as text, so two
		// spellings of one network would be two different policies.
		// An IPv4-mapped prefix names the same hosts as a v4 one, but the core
		// matches a mapped address as v4, so a rule written this way would never
		// hit. One network, one spelling: write it as the IPv4 prefix.
		if prefix.Addr().Is4In6() {
			return fmt.Errorf("%s: %q is an IPv4-mapped IPv6 prefix; write the IPv4 prefix", name, cidr)
		}
		if prefix.Masked().String() != cidr {
			return fmt.Errorf("%s: %q is not canonical (want %q)", name, cidr, prefix.Masked().String())
		}
	}
	return nil
}

// validateHostname is the hostname form a policy entry and an audit row share:
// lowercase ASCII, no leading or trailing dot, every label 1..63 bytes. One
// function, so the destinations a policy matches and the ones a hit reports are
// spelled the same way.
func validateHostname(value string) error {
	if value == "" || len(value) > 253 {
		return fmt.Errorf("value must be 1..253 bytes")
	}
	if value[0] == '.' || value[len(value)-1] == '.' {
		return fmt.Errorf("value must not start or end with a dot")
	}
	for index := 0; index < len(value); index++ {
		c := value[index]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' {
			continue
		}
		return fmt.Errorf("value must be lowercase [a-z0-9._-]")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("every label must be 1..63 bytes")
		}
	}
	return nil
}

func validateDomainEntry(entry string) error {
	prefix, value, ok := strings.Cut(entry, ":")
	if !ok {
		return fmt.Errorf("missing domain:, full:, keyword: or regexp: prefix")
	}
	switch prefix {
	case "domain", "full":
		if err := validateHostname(value); err != nil {
			return err
		}
	case "keyword":
		if value == "" || len(value) > 253 {
			return fmt.Errorf("keyword must be 1..253 bytes")
		}
		if value != strings.ToLower(value) {
			return fmt.Errorf("keyword must be lowercase")
		}
	case "regexp":
		if value == "" {
			return fmt.Errorf("regexp is empty, which would match every host")
		}
		if len(value) > 1024 {
			return fmt.Errorf("regexp is longer than 1024 bytes")
		}
		if _, err := regexp.Compile(value); err != nil {
			return fmt.Errorf("regexp does not compile: %w", err)
		}
	default:
		return fmt.Errorf("unknown prefix %q", prefix)
	}
	return nil
}

// parsePorts parses ^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$ with every port
// in 1..65535 and every range ascending. Returned ranges are inclusive.
//
// The form is canonical, because the string is hashed as text: no leading zeros
// ("0080"), and a range of one port is written as that port ("80", not "80-80").
func parsePorts(spec string) ([][2]uint16, error) {
	var ranges [][2]uint16
	next := 1 // the lowest port the next entry may start at
	for _, part := range strings.Split(spec, ",") {
		low, high, isRange := strings.Cut(part, "-")
		first, ok := parsePort(low)
		if !ok {
			return nil, fmt.Errorf("ports %q: %q is not a port in 1..65535", spec, low)
		}
		last := first
		if isRange {
			if last, ok = parsePort(high); !ok {
				return nil, fmt.Errorf("ports %q: %q is not a port in 1..65535", spec, high)
			}
			if first > last {
				return nil, fmt.Errorf("ports %q: range %q runs backwards", spec, part)
			}
			if first == last {
				return nil, fmt.Errorf("ports %q: range %q has equal ends; write it as %q", spec, part, low)
			}
		}
		// Ascending and disjoint, so one set of ports has one spelling.
		if int(first) < next {
			return nil, fmt.Errorf("ports %q: %q is not above the entry before it", spec, part)
		}
		next = int(last) + 1
		ranges = append(ranges, [2]uint16{first, last})
	}
	return ranges, nil
}

func parsePort(s string) (uint16, bool) {
	if !digitsBetween(s, 1, 5) || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}

// PolicyDigest is the identity of a policy: sha256 of its canonical JSON, in
// lowercase hex. The struct field order is the canonical order and the slices
// are already sorted, so every implementation that marshals the same policy
// gets the same bytes. A nil policy has no digest.
//
// The digest is of the policy as marshalled, not as understood: a nil Rules and
// an empty one encode as null and [], and would hash differently. Validation
// removes the ambiguity by rejecting a non-nil policy whose Rules is nil, so
// the digest of a valid policy never depends on that choice.
func PolicyDigest(policy *DestinationPolicy) string {
	if policy == nil {
		return ""
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
