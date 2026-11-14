package protocol

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// auditHour is an hour boundary: 472222 whole hours after the epoch.
const auditHour = int64(472222) * AuditHourMS

const auditBatchID = "0123456789abcdef0123456789abcdef"

// auditObservation is a valid observation that carries every kind of row: a
// block hit, a report-only hit for a block policy and one for a source rule
// (what would have been blocked), a trial row, and usage rows for a hostname
// and for an address.
func auditObservation() AuditObservation {
	return AuditObservation{
		BatchID: auditBatchID,
		Hits: []AuditHit{
			{Hour: auditHour, RuleID: "p12x2", Action: AuditActionBlock, Subject: "usr_7", Dest: "tracker.example", Port: 6881, Count: 3, FirstMS: auditHour + 10, LastMS: auditHour + 900},
			{Hour: auditHour, RuleID: "p12", Action: AuditActionObserve, Subject: "usr_7", Dest: "203.0.113.9", Port: 25, Count: 1, FirstMS: auditHour + 5, LastMS: auditHour + 5},
			{Hour: auditHour, RuleID: "s3", Action: AuditActionObserve, Subject: "usr_8", Dest: "2001:db8::1", Port: 443, Count: 2, FirstMS: auditHour, LastMS: auditHour + AuditHourMS - 1},
			{Hour: auditHour, RuleID: "g5", Action: AuditActionBlock, Subject: "usr_9", Dest: "full.example.net", Port: 443, Count: 1, FirstMS: auditHour + 1, LastMS: auditHour + 1},
			{Hour: auditHour, RuleID: "g5", Action: AuditActionObserve, Subject: "", Dest: "example.net", Port: 0, Count: 40, FirstMS: auditHour + 1, LastMS: auditHour + 2},
			{Hour: auditHour, RuleID: "g5", Action: AuditActionObserve, Subject: "", Dest: AuditSiteIP, Port: 0, Count: 4, FirstMS: auditHour + 1, LastMS: auditHour + 2},
		},
		Usage: []AuditUsage{
			{Hour: auditHour, Subject: "usr_7", Site: "example.com", Count: 12},
			{Hour: auditHour, Subject: "usr_7", Site: AuditSiteIP, Count: 2},
			{Hour: auditHour + AuditHourMS, Subject: "usr_8", Site: "example.com", Count: 1},
		},
		DroppedHits: 5, DroppedTrial: 1, DroppedUsage: 3,
		Unmatched: 2,
	}
}

func auditReport(partial bool, capabilities []string) NodeReport {
	observation := auditObservation()
	return NodeReport{
		AgentID: "a1", ProtocolVersion: ProtocolVersion1, Partial: partial, Have: emptyHave(),
		Capabilities: capabilities, Audit: &observation,
	}
}

var bothAuditCapabilities = []string{CapabilityAuditHits, CapabilityAuditUsage}

func TestAuditCapabilitiesAreNotUpgradeCapabilities(t *testing.T) {
	if CapabilityAuditHits != "audit.hits.v1" || CapabilityAuditUsage != "audit.usage.v1" {
		t.Fatalf("capability names changed: %q %q", CapabilityAuditHits, CapabilityAuditUsage)
	}
	// Like host telemetry and the destination policy, lacking them says nothing
	// about whether the agent can take an upgrade.
	for _, upgrade := range AgentUpgradeCapabilities() {
		if upgrade == CapabilityAuditHits || upgrade == CapabilityAuditUsage {
			t.Fatalf("%s is an upgrade capability", upgrade)
		}
	}
}

// The golden strings below were produced by the v0.3.0 code, before Audit
// existed. Every agent that never sends an audit observation must keep
// producing exactly these bytes: a report is hashed and compared by more than
// one reader, and a field that appears when it has nothing to say would be a
// silent change to every report in the fleet.
func TestNodeReportWithoutAuditIsByteIdenticalToV030(t *testing.T) {
	report := NodeReport{
		AgentID: "a1", ProtocolVersion: ProtocolVersion1, ReportedAtMS: 1700000000000,
		AgentVersion: "v1.2.3", CoreEngine: "xray", CoreVersion: "v26.9.9", CoreState: "running",
		Capabilities: []string{CapabilityDestinationPolicy, CapabilityHostTelemetry},
		Have:         map[string]StreamState{"config": {ETag: "e3"}},
		Objects:      []ObjectStatus{{Stream: "config", Key: "lst_1", State: ObjectApplied}},
		Clients: []ClientCounters{{Key: "cli_1", Present: true, UpBytes: 1, DownBytes: 2, CounterEpoch: 3,
			Gate: GateArmed, LiveIPs: []string{"192.0.2.1"}}},
		ListenerCounters: []ListenerCounters{{Key: "lst_1", Present: true, UpBytes: 4, DownBytes: 5, CounterEpoch: 6}},
		Subjects:         []SubjectObservation{{Subject: "usr_1", IPLocalCount: 1}},
		Issues:           []Issue{{Code: IssueRosterAheadOfConfig, Key: "k"}},
		PolicyStatus:     &PolicyStatus{Digest: goodDigest, State: PolicyStateApplied},
	}
	const full = `{"agent_id":"a1","protocol_version":1,"reported_at_ms":1700000000000,"agent_version":"v1.2.3","core_engine":"xray","core_version":"v26.9.9","core_state":"running","capabilities":["policy.destination.v1","host.telemetry.v1"],"partial":false,"have":{"config":{"applied":{"epoch":0,"version":0},"etag":"e3"}},"objects":[{"stream":"config","key":"lst_1","state":"applied","since_version":{"epoch":0,"version":0}}],"listener_counters":[{"key":"lst_1","present":true,"up_bytes":4,"down_bytes":5,"counter_epoch":6}],"clients":[{"key":"cli_1","present":true,"up_bytes":1,"down_bytes":2,"counter_epoch":3,"gate":"armed","live_ips":["192.0.2.1"]}],"subjects":[{"subject":"usr_1","ip_local_count":1,"ip_would_deny_since_last_report":0}],"issues":[{"code":"roster_ahead_of_config","key":"k"}],"policy_status":{"digest":"7ba8cd1b81f42df4393747c9b9313b48338c908d2b866e67b450ced654521d0c","state":"applied"}}`
	const partial = `{"agent_id":"a1","protocol_version":1,"reported_at_ms":1700000000000,"agent_version":"v1.2.3","core_engine":"xray","core_version":"v26.9.9","core_state":"running","capabilities":["policy.destination.v1","host.telemetry.v1"],"partial":true,"have":{"config":{"applied":{"epoch":0,"version":0},"etag":"e3"}},"issues":[{"code":"roster_ahead_of_config","key":"k"}],"policy_status":{"digest":"7ba8cd1b81f42df4393747c9b9313b48338c908d2b866e67b450ced654521d0c","state":"applied"}}`
	got, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != full {
		t.Fatalf("a full report with a nil Audit changed on the wire:\n got=%s\nwant=%s", got, full)
	}
	report.Partial = true
	got, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != partial {
		t.Fatalf("a partial report with a nil Audit changed on the wire:\n got=%s\nwant=%s", got, partial)
	}
}

// A report field added to NodeReport alone vanishes from every partial report,
// because partial reports are written through a second hand-written shape.
func TestAuditSurvivesFullAndPartialReports(t *testing.T) {
	for _, partial := range []bool{false, true} {
		report := auditReport(partial, bothAuditCapabilities)
		wire, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(wire), `"audit":{"batch_id":"`+auditBatchID+`"`) {
			t.Fatalf("partial=%v: audit missing from %s", partial, wire)
		}
		var decoded NodeReport
		if err := json.Unmarshal(wire, &decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded.Audit, report.Audit) {
			t.Fatalf("partial=%v: audit did not round trip:\n got=%+v\nwant=%+v", partial, decoded.Audit, report.Audit)
		}
	}
}

// Privacy rule: no source address leaves the node. The rows are the whole
// surface through which one could, so their field set is pinned: adding a
// field to a row means editing this list, and that edit is the review.
func TestAuditRowsCarryNoSourceAddress(t *testing.T) {
	keys := func(row any) []string {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(mustMarshal(t, row), &fields); err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(fields))
		for name := range fields {
			out = append(out, name)
		}
		sort.Strings(out)
		return out
	}
	if got, want := keys(AuditHit{}), []string{"action", "count", "dest", "first_ms", "hour", "last_ms", "port", "rule_id", "subject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AuditHit fields = %v, want %v", got, want)
	}
	if got, want := keys(AuditUsage{}), []string{"count", "hour", "site", "subject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AuditUsage fields = %v, want %v", got, want)
	}
	if got, want := keys(AuditObservation{}), []string{"batch_id", "dropped_hits", "dropped_trial", "dropped_usage", "unmatched"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AuditObservation fields = %v, want %v", got, want)
	}
}

func TestValidateAuditObservationAccepts(t *testing.T) {
	if err := ValidateAuditObservation(auditObservation()); err != nil {
		t.Fatal(err)
	}
	hitsOnly := auditObservation()
	hitsOnly.Usage = nil
	if err := ValidateAuditObservation(hitsOnly); err != nil {
		t.Fatalf("hits only: %v", err)
	}
	usageOnly := auditObservation()
	usageOnly.Hits = nil
	if err := ValidateAuditObservation(usageOnly); err != nil {
		t.Fatalf("usage only: %v", err)
	}
	// The counters ride on a batch that has rows; they are not themselves rows.
	zero := auditObservation()
	zero.DroppedHits, zero.DroppedTrial, zero.DroppedUsage, zero.Unmatched = 0, 0, 0, 0
	if err := ValidateAuditObservation(zero); err != nil {
		t.Fatalf("zero counters: %v", err)
	}
}

func TestValidateAuditObservationRejects(t *testing.T) {
	// Each case edits a valid observation, so a case that fails for a reason
	// other than the one it names cannot hide behind an unrelated defect.
	hit := func(mutate func(*AuditHit)) func(*AuditObservation) {
		return func(o *AuditObservation) { mutate(&o.Hits[0]) }
	}
	usage := func(mutate func(*AuditUsage)) func(*AuditObservation) {
		return func(o *AuditObservation) { mutate(&o.Usage[0]) }
	}
	trial := func(mutate func(*AuditHit)) func(*AuditObservation) {
		return func(o *AuditObservation) { mutate(&o.Hits[4]) }
	}
	cases := map[string]func(*AuditObservation){
		"no batch id":        func(o *AuditObservation) { o.BatchID = "" },
		"short batch id":     func(o *AuditObservation) { o.BatchID = o.BatchID[:31] },
		"long batch id":      func(o *AuditObservation) { o.BatchID += "0" },
		"uppercase batch id": func(o *AuditObservation) { o.BatchID = strings.ToUpper(o.BatchID) },
		"non-hex batch id":   func(o *AuditObservation) { o.BatchID = strings.Repeat("g", 32) },
		"no rows":            func(o *AuditObservation) { o.Hits, o.Usage = nil, nil },
		"empty row slices":   func(o *AuditObservation) { o.Hits, o.Usage = []AuditHit{}, []AuditUsage{} },

		"hit hour zero":                   hit(func(h *AuditHit) { h.Hour = 0; h.FirstMS, h.LastMS = 1, 1 }),
		"hit hour negative":               hit(func(h *AuditHit) { h.Hour = -AuditHourMS }),
		"hit hour not aligned":            hit(func(h *AuditHit) { h.Hour += 1000 }),
		"hit rule id empty":               hit(func(h *AuditHit) { h.RuleID = "" }),
		"hit rule id unknown":             hit(func(h *AuditHit) { h.RuleID = "x1" }),
		"hit rule id zero pad":            hit(func(h *AuditHit) { h.RuleID = "p01" }),
		"hit rule id bad suffix":          hit(func(h *AuditHit) { h.RuleID = "p1x" }),
		"hit rule id too long":            hit(func(h *AuditHit) { h.RuleID = "p1234567890123" }),
		"hit rule id uppercase":           hit(func(h *AuditHit) { h.RuleID = "P1" }),
		"hit source rule with a suffix":   hit(func(h *AuditHit) { h.RuleID = "s3x1" }),
		"hit group allow rule":            hit(func(h *AuditHit) { h.RuleID = "g5x1" }),
		"hit dest is an ipv4-mapped ipv6": hit(func(h *AuditHit) { h.Dest = "::ffff:203.0.113.9" }),
		"hit action allow":                hit(func(h *AuditHit) { h.Action = "allow" }),
		"hit action empty":                hit(func(h *AuditHit) { h.Action = "" }),
		"hit action uppercase":            hit(func(h *AuditHit) { h.Action = "Block" }),
		"hit no subject":                  hit(func(h *AuditHit) { h.Subject = "" }),
		"hit subject wrong kind":          hit(func(h *AuditHit) { h.Subject = "cli_7" }),
		"hit subject zero":                hit(func(h *AuditHit) { h.Subject = "usr_0" }),
		"hit subject zero pad":            hit(func(h *AuditHit) { h.Subject = "usr_07" }),
		"hit dest empty":                  hit(func(h *AuditHit) { h.Dest = "" }),
		"hit dest uppercase":              hit(func(h *AuditHit) { h.Dest = "Tracker.example" }),
		"hit dest trailing dot":           hit(func(h *AuditHit) { h.Dest = "tracker.example." }),
		"hit dest leading dot":            hit(func(h *AuditHit) { h.Dest = ".tracker.example" }),
		"hit dest empty label":            hit(func(h *AuditHit) { h.Dest = "tracker..example" }),
		"hit dest long label":             hit(func(h *AuditHit) { h.Dest = strings.Repeat("a", 64) + ".example" }),
		"hit dest has a port":             hit(func(h *AuditHit) { h.Dest = "tracker.example:6881" }),
		"hit dest has a space":            hit(func(h *AuditHit) { h.Dest = "tracker example" }),
		"hit dest is unicode":             hit(func(h *AuditHit) { h.Dest = "tracker.exämple" }),
		"hit dest too long":               hit(func(h *AuditHit) { h.Dest = strings.Repeat("a.", 127) + "a" }),
		"hit dest bracketed ip":           hit(func(h *AuditHit) { h.Dest = "[2001:db8::1]" }),
		"hit dest ip with port":           hit(func(h *AuditHit) { h.Dest = "203.0.113.9:25" }),
		"hit dest ip uppercase":           hit(func(h *AuditHit) { h.Dest = "2001:DB8::1" }),
		"hit dest ip expanded":            hit(func(h *AuditHit) { h.Dest = "2001:0db8::1" }),
		"hit dest ip zone":                hit(func(h *AuditHit) { h.Dest = "fe80::1%eth0" }),
		"hit dest is the ip tag":          hit(func(h *AuditHit) { h.Dest = AuditSiteIP }),
		"hit port zero":                   hit(func(h *AuditHit) { h.Port = 0 }),
		"hit count zero":                  hit(func(h *AuditHit) { h.Count = 0 }),
		"hit first after last":            hit(func(h *AuditHit) { h.FirstMS, h.LastMS = h.Hour+2, h.Hour+1 }),
		"hit first before hour":           hit(func(h *AuditHit) { h.FirstMS = h.Hour - 1 }),
		"hit last at next hour":           hit(func(h *AuditHit) { h.LastMS = h.Hour + AuditHourMS }),
		"hit first at next hour":          hit(func(h *AuditHit) { h.FirstMS, h.LastMS = h.Hour+AuditHourMS, h.Hour+AuditHourMS }),

		"trial row with a subject": trial(func(h *AuditHit) { h.Subject = "usr_9" }),
		"trial row with a port":    trial(func(h *AuditHit) { h.Port = 443 }),
		"trial row with an ip":     trial(func(h *AuditHit) { h.Dest = "203.0.113.9" }),
		"trial row with an ipv6":   trial(func(h *AuditHit) { h.Dest = "2001:db8::1" }),
		"trial row with an upper":  trial(func(h *AuditHit) { h.Dest = "Example.net" }),
		"trial row with no dest":   trial(func(h *AuditHit) { h.Dest = "" }),

		"usage hour zero":               usage(func(u *AuditUsage) { u.Hour = 0 }),
		"usage hour not aligned":        usage(func(u *AuditUsage) { u.Hour += 1 }),
		"usage no subject":              usage(func(u *AuditUsage) { u.Subject = "" }),
		"usage subject wrong kind":      usage(func(u *AuditUsage) { u.Subject = "lst_1" }),
		"usage site empty":              usage(func(u *AuditUsage) { u.Site = "" }),
		"usage site uppercase":          usage(func(u *AuditUsage) { u.Site = "Example.com" }),
		"usage site is an ipv4":         usage(func(u *AuditUsage) { u.Site = "203.0.113.9" }),
		"usage site is an ipv6":         usage(func(u *AuditUsage) { u.Site = "2001:db8::1" }),
		"usage site has a port":         usage(func(u *AuditUsage) { u.Site = "example.com:443" }),
		"usage site trailing dot":       usage(func(u *AuditUsage) { u.Site = "example.com." }),
		"usage site last label numeric": usage(func(u *AuditUsage) { u.Site = "3.4" }),
		"usage site padded octets":      usage(func(u *AuditUsage) { u.Site = "192.168.001.001" }),
		"usage site three numbers":      usage(func(u *AuditUsage) { u.Site = "1.2.3" }),
		"usage site hex address":        usage(func(u *AuditUsage) { u.Site = "0x7f000001" }),
		"usage site one number":         usage(func(u *AuditUsage) { u.Site = "2130706433" }),
		"trial dest padded octets":      trial(func(h *AuditHit) { h.Dest = "192.168.001.001" }),
		"trial dest last label numeric": trial(func(h *AuditHit) { h.Dest = "3.4" }),
		"usage count zero":              usage(func(u *AuditUsage) { u.Count = 0 }),
		"usage site too long":           usage(func(u *AuditUsage) { u.Site = strings.Repeat("a", 254) }),
		"usage site mixed ip token":     usage(func(u *AuditUsage) { u.Site = "(IP)" }),

		"dropped hits over int64":  func(o *AuditObservation) { o.DroppedHits = 1 << 63 },
		"dropped trial over int64": func(o *AuditObservation) { o.DroppedTrial = 1 << 63 },
		"dropped usage over int64": func(o *AuditObservation) { o.DroppedUsage = 1 << 63 },
		"unmatched over int64":     func(o *AuditObservation) { o.Unmatched = 1 << 63 },
		"duplicate hit key": func(o *AuditObservation) {
			twin := o.Hits[0]
			twin.Count = 9
			o.Hits = append(o.Hits, twin)
		},
		"duplicate trial key": func(o *AuditObservation) {
			twin := o.Hits[4]
			twin.FirstMS, twin.LastMS = twin.Hour+7, twin.Hour+8
			o.Hits = append(o.Hits, twin)
		},
		"duplicate usage key": func(o *AuditObservation) {
			twin := o.Usage[0]
			twin.Count = 9
			o.Usage = append(o.Usage, twin)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			observation := auditObservation()
			mutate(&observation)
			if err := ValidateAuditObservation(observation); err == nil {
				t.Fatalf("accepted %+v", observation)
			}
		})
	}
}

// The keys differ in one field each; every one of them is a real distinction,
// so none may be folded into "the same row".
func TestAuditAggregationKeysAreWhatTheStorageDistinguishes(t *testing.T) {
	base := AuditHit{Hour: auditHour, RuleID: "p1", Action: AuditActionBlock, Subject: "usr_1", Dest: "a.example", Port: 80, Count: 1, FirstMS: auditHour, LastMS: auditHour}
	variants := map[string]func(*AuditHit){
		"hour":    func(h *AuditHit) { h.Hour += AuditHourMS; h.FirstMS += AuditHourMS; h.LastMS += AuditHourMS },
		"rule":    func(h *AuditHit) { h.RuleID = "p1x2" },
		"action":  func(h *AuditHit) { h.Action = AuditActionObserve },
		"subject": func(h *AuditHit) { h.Subject = "usr_2" },
		"dest":    func(h *AuditHit) { h.Dest = "b.example" },
		"port":    func(h *AuditHit) { h.Port = 81 },
	}
	for name, mutate := range variants {
		other := base
		mutate(&other)
		observation := AuditObservation{BatchID: auditBatchID, Hits: []AuditHit{base, other}}
		if err := ValidateAuditObservation(observation); err != nil {
			t.Errorf("rows that differ only in %s were treated as duplicates: %v", name, err)
		}
	}
	// Count and the time stamps are measurements, not identity.
	other := base
	other.Count, other.LastMS = 5, auditHour+9
	if err := ValidateAuditObservation(AuditObservation{BatchID: auditBatchID, Hits: []AuditHit{base, other}}); err == nil {
		t.Error("rows that differ only in their measurements were accepted")
	}

	usage := AuditUsage{Hour: auditHour, Subject: "usr_1", Site: "a.example", Count: 1}
	for name, other := range map[string]AuditUsage{
		"hour":    {Hour: auditHour + AuditHourMS, Subject: "usr_1", Site: "a.example", Count: 1},
		"subject": {Hour: auditHour, Subject: "usr_2", Site: "a.example", Count: 1},
		"site":    {Hour: auditHour, Subject: "usr_1", Site: "b.example", Count: 1},
	} {
		if err := ValidateAuditObservation(AuditObservation{BatchID: auditBatchID, Usage: []AuditUsage{usage, other}}); err != nil {
			t.Errorf("usage rows that differ only in %s were treated as duplicates: %v", name, err)
		}
	}
}

func TestAuditRuleIDsFollowThePolicyRuleIDForm(t *testing.T) {
	for _, id := range []string{"p1", "p0", "p12x2", "p999999999999", "p1x9999", "s1", "s42", "g5"} {
		hit := AuditHit{Hour: auditHour, RuleID: id, Action: AuditActionBlock, Subject: "usr_1", Dest: "a.example", Port: 80, Count: 1, FirstMS: auditHour, LastMS: auditHour}
		if err := ValidateAuditHit(hit); err != nil {
			t.Errorf("rule id %q: %v", id, err)
		}
	}
	// A source rule's report-only hit is what a block-policy's is: a connection
	// that would have been blocked, with its subject and destination.
	hit := AuditHit{Hour: auditHour, RuleID: "s3", Action: AuditActionObserve, Subject: "usr_1", Dest: "a.example", Port: 80, Count: 1, FirstMS: auditHour, LastMS: auditHour}
	if err := ValidateAuditHit(hit); err != nil {
		t.Errorf("report-only source rule: %v", err)
	}
	// Only a group's observe row is a trial row; its subject is not optional on
	// a source or policy rule.
	hit.Subject = ""
	if err := ValidateAuditHit(hit); err == nil {
		t.Error("a report-only source rule hit without a subject was accepted")
	}
	hit.RuleID, hit.Port, hit.Dest = "p3", 0, AuditSiteIP
	if err := ValidateAuditHit(hit); err == nil {
		t.Error("a report-only policy hit shaped like a trial row was accepted")
	}
}

func TestAuditTrialRowsAreOnlyAGroupsObserve(t *testing.T) {
	trial := AuditHit{Hour: auditHour, RuleID: "g5", Action: AuditActionObserve, Dest: "example.net", Count: 2, FirstMS: auditHour, LastMS: auditHour}
	if err := ValidateAuditHit(trial); err != nil {
		t.Fatalf("trial row: %v", err)
	}
	trial.Dest = AuditSiteIP
	if err := ValidateAuditHit(trial); err != nil {
		t.Fatalf("trial row for an address: %v", err)
	}
	// Once the group is enforced the same rule blocks for real, and a real block
	// names who was blocked and where: it is not folded.
	enforced := trial
	enforced.Action = AuditActionBlock
	if err := ValidateAuditHit(enforced); err == nil {
		t.Error("an enforced group block without a subject was accepted")
	}
	enforced.Subject, enforced.Dest, enforced.Port = "usr_1", "full.example.net", 443
	if err := ValidateAuditHit(enforced); err != nil {
		t.Errorf("enforced group block: %v", err)
	}
}

func TestAuditRowLimits(t *testing.T) {
	hits := func(n int) []AuditHit {
		rows := make([]AuditHit, n)
		for i := range rows {
			rows[i] = AuditHit{Hour: auditHour, RuleID: "p1", Action: AuditActionBlock, Subject: NewSubjectKey(int64(i + 1)),
				Dest: "a.example", Port: 80, Count: 1, FirstMS: auditHour, LastMS: auditHour}
		}
		return rows
	}
	usage := func(n int) []AuditUsage {
		rows := make([]AuditUsage, n)
		for i := range rows {
			rows[i] = AuditUsage{Hour: auditHour, Subject: NewSubjectKey(int64(i + 1)), Site: "a.example", Count: 1}
		}
		return rows
	}
	if MaxAuditHits != 4096 || MaxAuditUsage != 8192 || MaxAuditObservationBytes != 1<<20 {
		t.Fatalf("limits changed: %d %d %d", MaxAuditHits, MaxAuditUsage, MaxAuditObservationBytes)
	}
	// Each at its limit, separately: with ordinary values both at once encode to
	// more than MaxAuditObservationBytes, so the byte limit, not the row limits,
	// is what bounds a full batch and the node trims rows to fit it.
	if err := ValidateAuditObservation(AuditObservation{BatchID: auditBatchID, Hits: hits(MaxAuditHits)}); err != nil {
		t.Fatalf("exactly the hit row limit: %v", err)
	}
	if err := ValidateAuditObservation(AuditObservation{BatchID: auditBatchID, Usage: usage(MaxAuditUsage)}); err != nil {
		t.Fatalf("exactly the usage row limit: %v", err)
	}
	if err := ValidateAuditObservation(AuditObservation{BatchID: auditBatchID, Hits: hits(MaxAuditHits), Usage: usage(MaxAuditUsage)}); err == nil {
		t.Fatal("both row limits at once fit the byte limit; the byte limit no longer binds and this test's premise is gone")
	}
	if err := ValidateAuditObservation(AuditObservation{BatchID: auditBatchID, Hits: hits(MaxAuditHits + 1)}); err == nil {
		t.Error("accepted one hit row over the limit")
	}
	if err := ValidateAuditObservation(AuditObservation{BatchID: auditBatchID, Usage: usage(MaxAuditUsage + 1)}); err == nil {
		t.Error("accepted one usage row over the limit")
	}

	// Within the row limits, long values can still push the encoding past the
	// byte limit; the byte limit is the one the wire and the receiver enforce.
	long := hits(MaxAuditHits)
	for i := range long {
		long[i].Dest = strings.Repeat("a", 61) + "." + strings.Repeat("b", 61) + "." + strings.Repeat("c", 61) + "." + strings.Repeat("d", 61)
	}
	observation := AuditObservation{BatchID: auditBatchID, Hits: long}
	if size := len(mustMarshal(t, observation)); size <= MaxAuditObservationBytes {
		t.Fatalf("the oversize fixture is only %d bytes", size)
	}
	if err := ValidateAuditObservation(observation); err == nil {
		t.Error("accepted an observation over the byte limit")
	}
}

func TestValidateNodeReportBindsAuditToCapabilities(t *testing.T) {
	for name, capabilities := range map[string][]string{
		"both":       bothAuditCapabilities,
		"both, rest": {CapabilityDestinationPolicy, CapabilityAuditHits, CapabilityAuditUsage, CapabilityHostTelemetry},
	} {
		for _, partial := range []bool{false, true} {
			if err := ValidateNodeReport(auditReport(partial, capabilities)); err != nil {
				t.Errorf("%s, partial=%v: %v", name, partial, err)
			}
		}
	}
	if err := ValidateNodeReport(auditReport(false, nil)); err == nil {
		t.Error("an audit observation without any capability was accepted")
	}
	if err := ValidateNodeReport(auditReport(false, []string{CapabilityAuditUsage})); err == nil {
		t.Error("an audit observation without audit.hits.v1 was accepted")
	}
	// Usage rows need their own capability: a node can record hits and not
	// usage (the access log filter is not running), and must not be able to
	// ship usage it did not declare.
	if err := ValidateNodeReport(auditReport(false, []string{CapabilityAuditHits})); err == nil {
		t.Error("usage rows without audit.usage.v1 were accepted")
	}
	hitsOnly := auditReport(false, []string{CapabilityAuditHits})
	hitsOnly.Audit.Usage = nil
	if err := ValidateNodeReport(hitsOnly); err != nil {
		t.Errorf("hits with audit.hits.v1 only: %v", err)
	}
	bad := auditReport(false, bothAuditCapabilities)
	bad.Audit.BatchID = "short"
	if err := ValidateNodeReport(bad); err == nil {
		t.Error("an invalid audit observation was accepted")
	}
	// Declaring the capabilities and carrying no observation is the common round.
	plain := NodeReport{AgentID: "a1", Have: emptyHave(), Capabilities: bothAuditCapabilities}
	if err := ValidateNodeReport(plain); err != nil {
		t.Errorf("capabilities without an observation: %v", err)
	}
}

// The receiver validates the subtree in isolation (ValidateAuditObservation),
// so a bad or capability-less audit must not cost the node its whole report,
// which would also cost it its roster.
func TestValidateNodeReportBaseDoesNotJudgeAudit(t *testing.T) {
	report := auditReport(false, nil)
	if err := ValidateNodeReportBase(report); err != nil {
		t.Fatalf("base check judged an absent-capability audit: %v", err)
	}
	report.Audit.BatchID = ""
	report.Audit.Hits[0].Port = 0
	if err := ValidateNodeReportBase(report); err != nil {
		t.Fatalf("base check judged an invalid audit: %v", err)
	}
}

// FuzzValidateAuditObservation is the third door the receiver opens on what a
// node sends, and the one with the most rows in it. The subtree is decoded and
// validated on its own, so what it accepts is what the panel stores.
//
// AN ACCEPTED OBSERVATION MUST SURVIVE ITS OWN WIRE FORMAT: it is re-encoded,
// decoded and validated again, and the second encoding must equal the first.
// It must also stay inside the byte limit, since that limit is what the
// receiver measures before it decodes anything.
//
// Plain `go test` runs only the seeds; the weekly workflow does the fuzzing.
func FuzzValidateAuditObservation(fuzz *testing.F) {
	hitsOnly := auditObservation()
	hitsOnly.Usage = nil
	usageOnly := auditObservation()
	usageOnly.Hits = nil
	seeds := []AuditObservation{auditObservation(), hitsOnly, usageOnly}
	for index, seed := range seeds {
		if err := ValidateAuditObservation(seed); err != nil {
			fuzz.Fatalf("seed %d is rejected, so it seeds nothing past the check that rejects it: %v", index, err)
		}
		fuzz.Add(mustMarshal(fuzz, seed))
	}
	fuzz.Add([]byte(`{"batch_id":"0123456789abcdef0123456789abcdef","hits":[{"hour":3600000,"rule_id":"s1","action":"observe","subject":"usr_1","dest":"::1","port":1,"count":1,"first_ms":3600000,"last_ms":3600000}]}`))
	fuzz.Add([]byte(`{"batch_id":"0123456789abcdef0123456789abcdef","hits":[{"hour":9223372036854775807,"rule_id":"g1","action":"observe","dest":"(ip)","count":1,"first_ms":9223372036854775807,"last_ms":9223372036854775807}]}`))

	fuzz.Fuzz(func(t *testing.T, body []byte) {
		var observation AuditObservation
		if err := json.Unmarshal(body, &observation); err != nil {
			return
		}
		if err := ValidateAuditObservation(observation); err != nil {
			return
		}
		wire, err := json.Marshal(observation)
		if err != nil {
			t.Fatalf("an accepted observation failed to encode: %v", err)
		}
		if len(wire) > MaxAuditObservationBytes {
			t.Fatalf("an accepted observation encodes to %d bytes, over the %d limit", len(wire), MaxAuditObservationBytes)
		}
		var decoded AuditObservation
		if err := json.Unmarshal(wire, &decoded); err != nil {
			t.Fatalf("an accepted observation failed to decode its own encoding: %v\n%s", err, wire)
		}
		if err := ValidateAuditObservation(decoded); err != nil {
			t.Fatalf("an accepted observation became invalid after a round trip: %v\n%s", err, wire)
		}
		// The privacy half: whatever was accepted, no address got through in a
		// place that is not allowed to hold one.
		looksLikeAddress := func(text string) bool {
			if _, err := netip.ParseAddr(text); err == nil {
				return true
			}
			label := text[strings.LastIndex(text, ".")+1:]
			if label == "" {
				return false
			}
			// A 0x-hex last label is a number too (0x7f000001); checked here
			// independently of isHexNumber so a regression there is caught.
			if hex := strings.ToLower(label); len(hex) > 2 && strings.HasPrefix(hex, "0x") {
				digits := true
				for _, c := range hex[2:] {
					if !strings.ContainsRune("0123456789abcdef", c) {
						digits = false
						break
					}
				}
				if digits {
					return true
				}
			}
			for i := 0; i < len(label); i++ {
				if label[i] < '0' || label[i] > '9' {
					return false
				}
			}
			return true
		}
		for _, usage := range observation.Usage {
			if usage.Site != AuditSiteIP && looksLikeAddress(usage.Site) {
				t.Fatalf("an accepted usage row has an address-shaped site: %q", usage.Site)
			}
		}
		for _, hit := range observation.Hits {
			if hit.Action != AuditActionObserve || hit.RuleID[0] != 'g' {
				continue
			}
			if hit.Subject != "" || hit.Port != 0 {
				t.Fatalf("an accepted trial row carries a subject or a port: %+v", hit)
			}
			if hit.Dest != AuditSiteIP && looksLikeAddress(hit.Dest) {
				t.Fatalf("an accepted trial row has an address-shaped dest: %q", hit.Dest)
			}
		}
		again, _ := json.Marshal(decoded)
		if !bytes.Equal(wire, again) {
			t.Fatalf("an accepted observation does not re-encode to the same bytes:\n first=%s\nsecond=%s", wire, again)
		}
	})
}

func auditPtr(observation AuditObservation) *AuditObservation { return &observation }

// Names that merely contain digits are not addresses: only a last label made
// wholly of digits (or a 0x number) reads as one, and no top-level domain is.
// Single-label hosts and public suffixes have no registrable domain to fold
// to, so the normalised host itself stands for them.
func TestAuditSiteAcceptsNamesThatOnlyLookNumeric(t *testing.T) {
	for _, site := range []string{
		"1.example.com", "123.com", "xn--80ak6aa92e.com", "localhost", "github.io", "a1", "1a", "example.c0m", "0xa.example.com",
	} {
		if err := ValidateAuditUsage(AuditUsage{Hour: auditHour, Subject: "usr_1", Site: site, Count: 1}); err != nil {
			t.Errorf("site %q: %v", site, err)
		}
		trial := AuditHit{Hour: auditHour, RuleID: "g5", Action: AuditActionObserve, Dest: site, Count: 1, FirstMS: auditHour, LastMS: auditHour}
		if err := ValidateAuditHit(trial); err != nil {
			t.Errorf("trial dest %q: %v", site, err)
		}
	}
}

// Errors are logged by whoever calls the validator, so none may repeat what it
// refused: a destination, a site or a subject is exactly what the privacy rule
// keeps out of logs. The cases use values that cannot occur in a message by
// accident.
func TestAuditErrorsDoNotQuoteTheRejectedValue(t *testing.T) {
	const marker = "zz-secret-zz"
	cases := map[string]func(*AuditObservation){
		"hit subject":    func(o *AuditObservation) { o.Hits[0].Subject = SubjectKey("cli_" + marker) },
		"hit subject 2":  func(o *AuditObservation) { o.Hits[0].Subject = SubjectKey("usr_0" + marker) },
		"hit dest":       func(o *AuditObservation) { o.Hits[0].Dest = marker + ".Example" },
		"hit dest ip":    func(o *AuditObservation) { o.Hits[0].Dest = "2001:DB8::" + marker },
		"hit dest ip 2":  func(o *AuditObservation) { o.Hits[0].Dest = "::ffff:203.0.113.9" },
		"hit dest zone":  func(o *AuditObservation) { o.Hits[0].Dest = "fe80::1%" + marker },
		"hit rule":       func(o *AuditObservation) { o.Hits[0].RuleID = marker },
		"hit action":     func(o *AuditObservation) { o.Hits[0].Action = marker },
		"usage subject":  func(o *AuditObservation) { o.Usage[0].Subject = SubjectKey(marker) },
		"usage site":     func(o *AuditObservation) { o.Usage[0].Site = marker + ".Example" },
		"usage site ip":  func(o *AuditObservation) { o.Usage[0].Site = "203.0.113.9" },
		"usage numeric":  func(o *AuditObservation) { o.Usage[0].Site = "203.0.113.77" },
		"trial dest":     func(o *AuditObservation) { o.Hits[4].Dest = "203.0.113.55" },
		"trial dest bad": func(o *AuditObservation) { o.Hits[4].Dest = marker + ".Example" },
		"batch id":       func(o *AuditObservation) { o.BatchID = marker },
	}
	for name, mutate := range cases {
		observation := auditObservation()
		mutate(&observation)
		err := ValidateAuditObservation(observation)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		for _, leaked := range []string{marker, "203.0.113.9", "203.0.113.77", "203.0.113.55", "fe80", "DB8"} {
			if strings.Contains(err.Error(), leaked) {
				t.Errorf("%s: error repeats the value (%q): %v", name, leaked, err)
			}
		}
	}
}
