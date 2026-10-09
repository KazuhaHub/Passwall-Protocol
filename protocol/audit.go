package protocol

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

const (
	CapabilityAuditHits  = "audit.hits.v1"
	CapabilityAuditUsage = "audit.usage.v1"
)

// AuditObservation is one immutable, in-memory batch for one kind, deployed
// collection revision and UTC hour. Counter-only batches retain loss evidence.
// Retries preserve BatchID and every row. Restart loses all unacknowledged
// backlog, which may span the full replay window; sync success does not prove
// telemetry has committed to storage. This is not a reliable audit trail.
type AuditObservation struct {
	BatchID         string       `json:"batch_id"`
	Kind            string       `json:"kind"`
	Hour            int64        `json:"hour"`
	CollectRevision uint64       `json:"collect_revision"`
	Hits            []AuditHit   `json:"hits,omitempty"`
	Usage           []AuditUsage `json:"usage,omitempty"`
	Dropped         uint64       `json:"dropped"`
	Unmatched       uint64       `json:"unmatched"`
}

// AuditHit records the frozen action rather than a policy's current action.
// Trial hits are already collapsed on the node: exact group rule, empty subject,
// zero port, and site or (ip). Per-person trial data must never reach the wire.
type AuditHit struct {
	Hour    int64      `json:"hour"`
	RuleID  string     `json:"rule_id"`
	Action  string     `json:"action"`
	Subject SubjectKey `json:"subject"`
	Dest    string     `json:"dest"`
	Port    uint16     `json:"port"`
	Count   uint32     `json:"count"`
	FirstMS int64      `json:"first_ms"`
	LastMS  int64      `json:"last_ms"`
}

// AuditUsage carries the node's eTLD+1 result, or (ip), never an IP literal.
// Consumers validate the supplied site rather than recomputing public suffixes.
type AuditUsage struct {
	Hour    int64      `json:"hour"`
	Subject SubjectKey `json:"subject"`
	Site    string     `json:"site"`
	Count   uint32     `json:"count"`
}

// ValidateAuditObservation checks the isolated subtree. Receivers additionally
// check current collection revision and age using their injected clock.
func ValidateAuditObservation(o AuditObservation) error {
	if len(o.BatchID) != 32 || strings.IndexFunc(o.BatchID, func(c rune) bool {
		return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')
	}) >= 0 {
		return fmt.Errorf("audit batch_id must be 32 lowercase hexadecimal characters")
	}
	if o.Hour <= 0 || o.Hour%AuditHourMS != 0 {
		return fmt.Errorf("audit hour must be a positive whole UTC hour")
	}
	if o.CollectRevision == 0 {
		return fmt.Errorf("audit collect_revision must be positive")
	}
	switch o.Kind {
	case "block", "observe", "trial":
		if len(o.Usage) != 0 {
			return fmt.Errorf("hit batch must omit usage")
		}
	case "usage":
		if len(o.Hits) != 0 {
			return fmt.Errorf("usage batch must omit hits")
		}
	default:
		return fmt.Errorf("unsupported audit kind")
	}
	if len(o.Hits) > MaxAuditHits || len(o.Usage) > MaxAuditUsage {
		return fmt.Errorf("too many audit rows")
	}
	if len(o.Hits) == 0 && len(o.Usage) == 0 && o.Dropped == 0 && o.Unmatched == 0 {
		return fmt.Errorf("empty audit batch")
	}
	type hitKey struct {
		rule, action string
		subject      SubjectKey
		dest         string
		port         uint16
	}
	seenHits := make(map[hitKey]struct{}, len(o.Hits))
	for _, hit := range o.Hits {
		if err := validateAuditHit(hit, o.Kind, o.Hour); err != nil {
			return err
		}
		key := hitKey{hit.RuleID, hit.Action, hit.Subject, hit.Dest, hit.Port}
		if _, found := seenHits[key]; found {
			return fmt.Errorf("duplicate audit hit key")
		}
		seenHits[key] = struct{}{}
	}
	type usageKey struct {
		subject SubjectKey
		site    string
	}
	seenUsage := make(map[usageKey]struct{}, len(o.Usage))
	for _, usage := range o.Usage {
		if usage.Hour != o.Hour || usage.Count == 0 {
			return fmt.Errorf("invalid audit usage hour or count")
		}
		if _, err := usage.Subject.RowID(); err != nil {
			return fmt.Errorf("audit usage subject: %w", err)
		}
		if !canonicalAuditSite(usage.Site) {
			return fmt.Errorf("noncanonical audit usage site")
		}
		key := usageKey{usage.Subject, usage.Site}
		if _, found := seenUsage[key]; found {
			return fmt.Errorf("duplicate audit usage key")
		}
		seenUsage[key] = struct{}{}
	}
	encoded, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("encode audit observation: %w", err)
	}
	if len(encoded) > MaxAuditObservationBytes {
		return fmt.Errorf("audit observation too large")
	}
	return nil
}

func validateAuditHit(hit AuditHit, kind string, hour int64) error {
	if hit.Hour != hour || hit.Count == 0 || !destinationRuleID.MatchString(hit.RuleID) {
		return fmt.Errorf("invalid audit hit hour, count or rule id")
	}
	switch kind {
	case "block":
		if hit.Action != "block" {
			return fmt.Errorf("nonblock action in block batch")
		}
	case "observe":
		if hit.Action != "observe" || hit.RuleID[0] != 'p' {
			return fmt.Errorf("nonglobal observation in observe batch")
		}
	case "trial":
		if hit.Action != "observe" || hit.RuleID[0] != 'g' || strings.Contains(hit.RuleID, "x") || hit.Subject != "" || hit.Port != 0 || !canonicalAuditSite(hit.Dest) {
			return fmt.Errorf("trial hit must be anonymous group/site observation")
		}
	}
	if kind != "trial" {
		if _, err := hit.Subject.RowID(); err != nil {
			return fmt.Errorf("audit hit subject: %w", err)
		}
		if hit.Port == 0 || !canonicalAuditDest(hit.Dest) {
			return fmt.Errorf("invalid audit hit destination or port")
		}
	}
	// Compare differences only after ordering: Hour+one-hour may overflow at
	// the int64 boundary even when the supplied timestamps are inside the hour.
	if hit.FirstMS < hour || hit.LastMS < hit.FirstMS || hit.LastMS-hour >= AuditHourMS {
		return fmt.Errorf("audit hit timestamps must be ordered inside the batch hour")
	}
	return nil
}

func canonicalAuditDest(value string) bool {
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Zone() == "" && addr.String() == value
	}
	return canonicalDestinationHostname(value)
}

func canonicalAuditSite(value string) bool {
	if value == "(ip)" {
		return true
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	return canonicalDestinationHostname(value)
}
