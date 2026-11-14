package protocol

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// CapabilityAuditHits says the agent records destination-rule hits and will
// send them as NodeReport.Audit. It is declared only while the hit receiver is
// actually listening: a node that declared it and then recorded nothing would
// look, to the panel, exactly like a node with nothing to report.
//
// CapabilityAuditUsage says the agent also reports per-site usage, which is a
// browsing record per person and so a separate capability: a node may do the
// first and not the second. The reverse does not exist: usage is the second
// tier of recording and presupposes the first, so an observation that carries
// usage rows needs BOTH capabilities (ValidateNodeReport).
//
// NEITHER IS AN UPGRADE CAPABILITY. Like CapabilityDestinationPolicy and
// CapabilityHostTelemetry they are absent from AgentUpgradeCapabilities, so an
// agent that lacks them is not held back from upgrading.
const (
	CapabilityAuditHits  = "audit.hits.v1"
	CapabilityAuditUsage = "audit.usage.v1"
)

const (
	// AuditActionBlock and AuditActionObserve are AuditHit.Action. They are what
	// the rule did at the moment of the hit, not what it is now: one group is
	// observe while it is on trial and block once it is enforced, and an
	// operator can change a policy's action after the hits were recorded.
	//
	// "observe" on a policy (p*) or source rule (s*) means report-only: the
	// connection was allowed and WOULD HAVE BEEN BLOCKED. On a group (g*) it is
	// a trial row (see AuditHit).
	AuditActionBlock   = "block"
	AuditActionObserve = "observe"

	// AuditSiteIP stands in for the destination where it is an address and the
	// row is one that does not carry addresses: AuditUsage.Site always, and a
	// trial row's Dest. It is a literal and not a field because the point is
	// that the address is not there.
	AuditSiteIP = "(ip)"

	// AuditHourMS is the width of the bucket every row is aggregated into.
	AuditHourMS = 3600000
)

// AuditObservation is what a node saw happen to connections since the last
// batch it froze: which rules fired, for whom, towards what, and optionally
// which sites each person used.
//
// It carries no engine and no coverage. Whether a node is recording is
// something the panel works out for itself from capabilities and engine,
// because a quiet node sends nothing and silence cannot distinguish "recording
// and nothing happened" from "not recording". For the same reason it is
// present only when there are rows: an empty batch is never sent.
//
// NO SOURCE ADDRESS IS HERE AND NONE MAY BE ADDED. A source rule's hit names
// the subject and the destination the connection was going to, like any other
// hit; where the client connected from stays on the node.
//
// IT IS NOT DURABLE. A node that restarts loses what it had not yet sent, up to
// one sync interval. That is the price of not growing the node's schema: a
// remote upgrade, which restarts the agent, stays available and loses nothing
// that was already acknowledged.
//
// Like PolicyStatus it is validated by the receiver on its own, never through
// ValidateNodeReportBase: a bad batch costs the batch, not the report, because
// a node whose report fails validation does not receive its roster.
type AuditObservation struct {
	// BatchID is 16 random bytes in lowercase hex, one per frozen batch. A batch
	// that must be sent again is sent with the same ID and the same rows, and the
	// panel counts it once: a different ID for the same rows would count them
	// twice, and the same ID for different rows would drop the difference.
	BatchID string       `json:"batch_id"`
	Hits    []AuditHit   `json:"hits,omitempty"`
	Usage   []AuditUsage `json:"usage,omitempty"`
	// DroppedHits, DroppedTrial and DroppedUsage count events the node could not
	// aggregate because the table for that kind of row was full. They are three
	// counts and not one because the node folds trial rows and aggregates hits
	// and usage separately (the trial aggregator exists so that the flood of
	// fallback hits cannot crowd out real blocks), and the loss has to be
	// attributable the same way: a lost BLOCK hit must be distinguishable from
	// trial or usage overflow, which is expected on a busy node and not a gap in
	// the record of what was blocked.
	//
	// Unmatched counts events and rows it could not use: unparseable, no
	// account, or naming a rule it does not hold. All four accumulate on the
	// node and are carried by the next frozen batch, which resets them, so a
	// lossy stretch is visible instead of passing as a quiet one.
	DroppedHits  uint64 `json:"dropped_hits"`
	DroppedTrial uint64 `json:"dropped_trial"`
	DroppedUsage uint64 `json:"dropped_usage"`
	Unmatched    uint64 `json:"unmatched"`
}

// AuditHit is one aggregated rule hit: every connection in one hour that the
// same rule took the same action on, for the same subject towards the same
// destination and port.
//
// A TRIAL ROW is a group's (g*) observe hit, which is the fallback hit of an
// allowlist group on trial: what the group's members would have been refused
// had the list been enforced. It is folded on the node into group x site before
// it is aggregated, so Subject is empty, Port is zero and Dest is the
// registrable domain (or AuditSiteIP): the per-person, per-host version of this
// data never leaves the node. An enforced group's block is a real block and is
// not folded.
//
// Dest is normalised by the node and only checked here. Registrable domains are
// computed on the node and nowhere else: two implementations of the public
// suffix list at different versions would disagree, and this package has no
// dependencies to host one. Where there is no registrable domain (a
// single-label host such as "localhost", or a host that is itself a public
// suffix such as "github.io") a trial row's Dest, like a usage row's Site, is
// the normalised host itself.
type AuditHit struct {
	// Hour is the UTC hour, in milliseconds, in which the node received the
	// events.
	Hour int64 `json:"hour"`
	// RuleID is the policy rule's ID as the node was given it, so x<k> split
	// suffixes are present; the panel maps it back to the operator's rule.
	RuleID  string     `json:"rule_id"`
	Action  string     `json:"action"`
	Subject SubjectKey `json:"subject"`
	// Dest is a lowercase hostname or a canonical address, without a port.
	Dest    string `json:"dest"`
	Port    uint16 `json:"port"`
	Count   uint32 `json:"count"`
	FirstMS int64  `json:"first_ms"`
	LastMS  int64  `json:"last_ms"`
}

// AuditUsage is how many connections one person made to one site in one hour.
// Site is the registrable domain, and AuditSiteIP where the destination was an
// address: the address itself is not recorded.
type AuditUsage struct {
	Hour    int64      `json:"hour"`
	Subject SubjectKey `json:"subject"`
	Site    string     `json:"site"`
	Count   uint32     `json:"count"`
}

// ValidateAuditObservation checks an observation in isolation. The receiver
// runs it on the subtree after decoding it by itself, and a sender runs it
// before attaching the subtree, so a malformed batch is dropped as that and
// never reaches a report the panel would refuse whole.
//
// It checks shape, not freshness: whether Hour is plausible against the
// clock is the receiver's to say, because this package has no clock.
func ValidateAuditObservation(observation AuditObservation) error {
	if !validSampleID(observation.BatchID) {
		return fmt.Errorf("audit batch_id must be exactly %d lowercase hex characters", SampleIDBytes)
	}
	if len(observation.Hits) == 0 && len(observation.Usage) == 0 {
		return fmt.Errorf("an audit observation carries at least one hit or usage row; an empty batch is not sent")
	}
	if len(observation.Hits) > MaxAuditHits {
		return fmt.Errorf("audit observation has %d hits, maximum is %d", len(observation.Hits), MaxAuditHits)
	}
	if len(observation.Usage) > MaxAuditUsage {
		return fmt.Errorf("audit observation has %d usage rows, maximum is %d", len(observation.Usage), MaxAuditUsage)
	}
	// The counters are stored signed by every dialect the panel supports.
	// A fixed order, so the counter an error names does not change between runs.
	for _, counter := range []struct {
		name  string
		count uint64
	}{
		{"audit dropped_hits", observation.DroppedHits},
		{"audit dropped_trial", observation.DroppedTrial},
		{"audit dropped_usage", observation.DroppedUsage},
	} {
		if err := withinInt64(counter.name, counter.count); err != nil {
			return err
		}
	}
	if err := withinInt64("audit unmatched", observation.Unmatched); err != nil {
		return err
	}

	type hitKey struct {
		hour    int64
		rule    string
		action  string
		subject SubjectKey
		dest    string
		port    uint16
	}
	seenHits := make(map[hitKey]struct{}, len(observation.Hits))
	for index, hit := range observation.Hits {
		if err := ValidateAuditHit(hit); err != nil {
			return fmt.Errorf("audit hit %d: %w", index, err)
		}
		// Action is part of the key: a rule whose action changed within the hour
		// legitimately has two rows, and the hour's count for each is separate.
		key := hitKey{hit.Hour, hit.RuleID, hit.Action, hit.Subject, hit.Dest, hit.Port}
		if _, exists := seenHits[key]; exists {
			return fmt.Errorf("audit hit %d repeats the aggregation key of an earlier hit", index)
		}
		seenHits[key] = struct{}{}
	}

	type usageKey struct {
		hour    int64
		subject SubjectKey
		site    string
	}
	seenUsage := make(map[usageKey]struct{}, len(observation.Usage))
	for index, usage := range observation.Usage {
		if err := ValidateAuditUsage(usage); err != nil {
			return fmt.Errorf("audit usage %d: %w", index, err)
		}
		key := usageKey{usage.Hour, usage.Subject, usage.Site}
		if _, exists := seenUsage[key]; exists {
			return fmt.Errorf("audit usage %d repeats the aggregation key of an earlier row", index)
		}
		seenUsage[key] = struct{}{}
	}

	// Last, because the rows above are bounded in length and the encoding is
	// then bounded in cost. It is measured as the receiver measures it.
	encoded, err := json.Marshal(observation)
	if err != nil {
		return fmt.Errorf("audit observation does not encode: %w", err)
	}
	if len(encoded) > MaxAuditObservationBytes {
		return fmt.Errorf("audit observation encodes to %d bytes, maximum is %d", len(encoded), MaxAuditObservationBytes)
	}
	return nil
}

// ValidateAuditHit checks one row on its own: everything
// ValidateAuditObservation requires of a hit except that rows are unique. It is
// exported for the node, which checks each event as it enters the aggregator, so
// that a row the whole-batch check would refuse never gets that far and costs
// one counted event instead of a batch.
func ValidateAuditHit(hit AuditHit) error {
	if err := validateAuditHour(hit.Hour); err != nil {
		return err
	}
	// The same form as a policy's rule ID, so a hit can always be traced to the
	// rule that produced it, a source rule's included.
	id := parseRuleID(hit.RuleID)
	if !id.validForm {
		return fmt.Errorf("rule_id is not a rule ID")
	}
	// What a policy may contain bounds what can hit. A source rule has no x
	// suffix, and a group's x<k> rules are allows, which are not recorded: only
	// the group's catch-all, g<gid>, blocks or observes. (Action is already
	// block or observe below, which is all a p* or s* rule can be recorded as.)
	if id.kind == 's' && id.suffixed {
		return fmt.Errorf("rule_id: a source rule has no suffix")
	}
	if id.kind == 'g' && id.suffixed {
		return fmt.Errorf("rule_id: a group's suffixed rules are allows and never hit")
	}
	switch hit.Action {
	case AuditActionBlock, AuditActionObserve:
	default:
		return fmt.Errorf("action is not %s or %s", AuditActionBlock, AuditActionObserve)
	}
	if hit.Count < 1 {
		return fmt.Errorf("count must be at least 1")
	}
	if hit.FirstMS > hit.LastMS {
		return fmt.Errorf("first_ms is after last_ms")
	}
	// Written as differences from Hour so that an Hour near the top of the range
	// cannot overflow the bound being tested.
	for _, instant := range []int64{hit.FirstMS, hit.LastMS} {
		if instant < hit.Hour || instant-hit.Hour >= AuditHourMS {
			return fmt.Errorf("first_ms and last_ms must lie within the hour that starts at hour")
		}
	}

	if isAuditTrialRow(hit) {
		// The fold that keeps per-person, per-host data on the node: none of what
		// would identify a person or a connection may be present.
		if hit.Subject != "" {
			return fmt.Errorf("a trial row carries no subject")
		}
		if hit.Port != 0 {
			return fmt.Errorf("a trial row carries no port")
		}
		if hit.Dest == AuditSiteIP {
			return nil
		}
		if err := validateAuditSite(hit.Dest); err != nil {
			return fmt.Errorf("a trial row's dest must be a site or %s: %w", AuditSiteIP, err)
		}
		return nil
	}

	if err := validateAuditSubject(hit.Subject); err != nil {
		return err
	}
	if hit.Port < 1 {
		return fmt.Errorf("port must be 1..65535")
	}
	return validateAuditDest(hit.Dest)
}

// ValidateAuditUsage checks one usage row on its own; see ValidateAuditHit for
// why it is exported.
func ValidateAuditUsage(usage AuditUsage) error {
	if err := validateAuditHour(usage.Hour); err != nil {
		return err
	}
	if err := validateAuditSubject(usage.Subject); err != nil {
		return err
	}
	if usage.Count < 1 {
		return fmt.Errorf("count must be at least 1")
	}
	if usage.Site == AuditSiteIP {
		return nil
	}
	if err := validateAuditSite(usage.Site); err != nil {
		return fmt.Errorf("site must be a site or %s: %w", AuditSiteIP, err)
	}
	return nil
}

// isAuditTrialRow is the one shape that is not per person: a group's observe.
func isAuditTrialRow(hit AuditHit) bool {
	return hit.Action == AuditActionObserve && parseRuleID(hit.RuleID).kind == 'g'
}

func validateAuditHour(hour int64) error {
	if hour <= 0 || hour%AuditHourMS != 0 {
		return fmt.Errorf("hour must be a positive multiple of %d", AuditHourMS)
	}
	return nil
}

// validateAuditDest accepts what the node normalised a destination to: a
// hostname in the policy's own hostname form, or an address in the form netip
// prints it. An address with a zone is refused: it names an interface of the
// node's network and is not a destination.
func validateAuditDest(dest string) error {
	if len(dest) > 253 {
		return fmt.Errorf("dest exceeds 253 bytes")
	}
	if addr, err := netip.ParseAddr(dest); err == nil {
		if addr.Zone() != "" || addr.String() != dest {
			return fmt.Errorf("dest is an address that is not in canonical form")
		}
		// One address, one spelling: an IPv4 address reaches the node as IPv6
		// when the client is dual-stack, and the node unmaps it first, as a
		// policy's CIDRs are matched unmapped.
		if addr.Is4In6() {
			return fmt.Errorf("dest is an IPv4-mapped IPv6 address; unmap it")
		}
		return nil
	}
	if err := validateHostname(dest); err != nil {
		return fmt.Errorf("dest: %w", err)
	}
	return nil
}

// validateAuditSubject is RowID without its message: the error of RowID
// repeats the key, and the caller of a validator logs the error.
func validateAuditSubject(subject SubjectKey) error {
	if _, err := subject.RowID(); err != nil {
		return fmt.Errorf("subject is not a subject key")
	}
	return nil
}

// validateAuditSite is a hostname and never something that reads as an
// address: a site is a name, and an address is recorded as AuditSiteIP. An IPv4
// address is spelled like a hostname, so it has to be refused by what it parses
// as and not by its characters, and so do the spellings an address resolver
// would still take for one ("3.4", "1.2.3", "192.168.001.001", "2130706433",
// "0x7f000001"). What they share is a last label that is all digits or a 0x
// number, and no top-level domain is either, so that is the test; a name that
// merely contains digits ("1.example.com", "123.com", "xn--...") is a name.
//
// A single-label host ("localhost") and a host that is itself a public suffix
// ("github.io") have no registrable domain. The node then writes the
// normalised host itself, and that is what this accepts.
func validateAuditSite(site string) error {
	if _, err := netip.ParseAddr(site); err == nil {
		return fmt.Errorf("an address is recorded as %s", AuditSiteIP)
	}
	if err := validateHostname(site); err != nil {
		return err
	}
	last := site[strings.LastIndexByte(site, '.')+1:]
	if isDigits(last) || isHexNumber(last) {
		return fmt.Errorf("the last label is a number, which reads as an address")
	}
	return nil
}

func isDigits(label string) bool {
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return label != ""
}

// isHexNumber is a 0x prefix and at least one hex digit, the form an address
// resolver reads as a number.
func isHexNumber(label string) bool {
	rest, ok := strings.CutPrefix(label, "0x")
	if !ok || rest == "" {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return false
	}
	return true
}
