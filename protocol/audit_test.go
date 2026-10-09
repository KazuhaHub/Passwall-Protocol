package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

// Independent frozen encodings, rather than comparing the new marshaler with
// itself. The beta11 harness also compares both full and partial legacy reports.
func TestNilAuditPreservesLegacyReportBytes(t *testing.T) {
	for _, tc := range []struct {
		partial bool
		want    string
	}{
		{false, `{"agent_id":"audit-agent","partial":false,"have":{},"objects":[],"listener_counters":[],"clients":[]}`},
		{true, `{"agent_id":"audit-agent","partial":true,"have":{}}`},
	} {
		r := NodeReport{AgentID: "audit-agent", Partial: tc.partial, Have: map[string]StreamState{}}
		wire, err := json.Marshal(r)
		if err != nil || string(wire) != tc.want {
			t.Fatalf("partial=%v: %s, %v; want %s", tc.partial, wire, err, tc.want)
		}
	}
}

func TestAuditCapabilitiesRemainOptionalForUpgrade(t *testing.T) {
	for _, capability := range AgentUpgradeCapabilities() {
		if capability == CapabilityAuditHits || capability == CapabilityAuditUsage {
			t.Fatal("optional audit capability changed upgrade requirements")
		}
	}
	if AuditHourMS != 3_600_000 || MaxAuditReplayAgeMS != 48*AuditHourMS || MaxAuditFutureSkewMS != AuditHourMS || AuditBatchRetentionMS <= MaxAuditReplayAgeMS+MaxAuditFutureSkewMS {
		t.Fatal("deduplication must cover the whole accepted replay/future window in milliseconds")
	}
}

const auditTestHour = int64(1_800_000_000_000)

func auditFixture(kind string) AuditObservation {
	o := AuditObservation{BatchID: "0123456789abcdef0123456789abcdef", Kind: kind, Hour: auditTestHour, CollectRevision: 1}
	hit := AuditHit{Hour: o.Hour, RuleID: "p1x2", Action: "block", Subject: NewSubjectKey(7), Dest: "api.example.com", Port: 443, Count: 1, FirstMS: o.Hour, LastMS: o.Hour + AuditHourMS - 1}
	switch kind {
	case "observe":
		hit.Action = "observe"
	case "trial":
		hit.RuleID = "g12"
		hit.Action = "observe"
		hit.Subject = ""
		hit.Port = 0
		hit.Dest = "example.com"
	case "usage":
		o.Usage = []AuditUsage{{Hour: o.Hour, Subject: NewSubjectKey(7), Site: "example.com", Count: 1}}
		return o
	}
	o.Hits = []AuditHit{hit}
	return o
}

func TestAuditKindsAndCounterOnlyBatches(t *testing.T) {
	for _, kind := range []string{"block", "observe", "trial", "usage"} {
		t.Run(kind, func(t *testing.T) {
			o := auditFixture(kind)
			if err := ValidateAuditObservation(o); err != nil {
				t.Fatal(err)
			}
			o.Hits = nil
			o.Usage = nil
			o.Dropped = math.MaxUint64
			if err := ValidateAuditObservation(o); err != nil {
				t.Fatal(err)
			}
			o.Dropped = 0
			o.Unmatched = 1
			if err := ValidateAuditObservation(o); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, dest := range []string{"192.0.2.1", "2001:db8::1", "xn--bcher-kva.example", "_service.example"} {
		o := auditFixture("block")
		o.Hits[0].Dest = dest
		if err := ValidateAuditObservation(o); err != nil {
			t.Fatalf("%s: %v", dest, err)
		}
	}
	for _, kind := range []string{"trial", "usage"} {
		o := auditFixture(kind)
		if kind == "trial" {
			o.Hits[0].Dest = "(ip)"
		} else {
			o.Usage[0].Site = "(ip)"
		}
		if err := ValidateAuditObservation(o); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditRejectsMalformedAndMixedBatches(t *testing.T) {
	cases := []struct {
		name, kind string
		change     func(*AuditObservation)
	}{
		{"short batch id", "block", func(o *AuditObservation) { o.BatchID = "abcd" }},
		{"uppercase batch id", "block", func(o *AuditObservation) { o.BatchID = strings.ToUpper(o.BatchID) }},
		{"nonhex batch id", "block", func(o *AuditObservation) { o.BatchID = strings.Repeat("z", 32) }},
		{"unknown kind", "block", func(o *AuditObservation) { o.Kind = "future" }},
		{"zero revision", "block", func(o *AuditObservation) { o.CollectRevision = 0 }},
		{"zero hour", "block", func(o *AuditObservation) { o.Hour = 0 }},
		{"negative hour", "block", func(o *AuditObservation) { o.Hour = -AuditHourMS }},
		{"unaligned hour", "block", func(o *AuditObservation) { o.Hour++ }},
		{"other row hour", "block", func(o *AuditObservation) { o.Hits[0].Hour += AuditHourMS }},
		{"other usage hour", "usage", func(o *AuditObservation) { o.Usage[0].Hour += AuditHourMS }},
		{"empty batch", "block", func(o *AuditObservation) { o.Hits = nil }},
		{"hits in usage", "usage", func(o *AuditObservation) { o.Hits = auditFixture("block").Hits }},
		{"usage in hits", "block", func(o *AuditObservation) { o.Usage = auditFixture("usage").Usage }},
		{"unknown action", "block", func(o *AuditObservation) { o.Hits[0].Action = "allow" }},
		{"mixed frozen action", "block", func(o *AuditObservation) { o.Hits[0].Action = "observe" }},
		{"group in global observation", "observe", func(o *AuditObservation) { o.Hits[0].RuleID = "g12" }},
		{"policy in trial", "trial", func(o *AuditObservation) { o.Hits[0].RuleID = "p12" }},
		{"group branch in trial", "trial", func(o *AuditObservation) { o.Hits[0].RuleID = "g12x1" }},
		{"invalid rule", "block", func(o *AuditObservation) { o.Hits[0].RuleID = "p0x12345" }},
		{"rule too long", "block", func(o *AuditObservation) { o.Hits[0].RuleID = "p1234567890123" }},
		{"subject in trial", "trial", func(o *AuditObservation) { o.Hits[0].Subject = NewSubjectKey(7) }},
		{"port in trial", "trial", func(o *AuditObservation) { o.Hits[0].Port = 443 }},
		{"ip in trial", "trial", func(o *AuditObservation) { o.Hits[0].Dest = "192.0.2.1" }},
		{"ipv6 in trial", "trial", func(o *AuditObservation) { o.Hits[0].Dest = "2001:db8::1" }},
		{"missing subject", "block", func(o *AuditObservation) { o.Hits[0].Subject = "" }},
		{"invalid subject", "block", func(o *AuditObservation) { o.Hits[0].Subject = "usr_07" }},
		{"missing usage subject", "usage", func(o *AuditObservation) { o.Usage[0].Subject = "" }},
		{"port zero", "block", func(o *AuditObservation) { o.Hits[0].Port = 0 }},
		{"zero hit count", "block", func(o *AuditObservation) { o.Hits[0].Count = 0 }},
		{"zero usage count", "usage", func(o *AuditObservation) { o.Usage[0].Count = 0 }},
		{"empty dest", "block", func(o *AuditObservation) { o.Hits[0].Dest = "" }},
		{"uppercase dest", "block", func(o *AuditObservation) { o.Hits[0].Dest = "Example.com" }},
		{"unicode dest", "block", func(o *AuditObservation) { o.Hits[0].Dest = "书.example" }},
		{"dest with port", "block", func(o *AuditObservation) { o.Hits[0].Dest = "example.com:443" }},
		{"dest with path", "block", func(o *AuditObservation) { o.Hits[0].Dest = "example.com/a" }},
		{"bracketed ip", "block", func(o *AuditObservation) { o.Hits[0].Dest = "[2001:db8::1]" }},
		{"noncanonical ip", "block", func(o *AuditObservation) { o.Hits[0].Dest = "2001:0db8::1" }},
		{"scoped ip", "block", func(o *AuditObservation) { o.Hits[0].Dest = "fe80::1%eth0" }},
		{"long dest", "block", func(o *AuditObservation) { o.Hits[0].Dest = strings.Repeat("a", 254) }},
		{"ip sentinel outside trial", "block", func(o *AuditObservation) { o.Hits[0].Dest = "(ip)" }},
		{"ip in usage", "usage", func(o *AuditObservation) { o.Usage[0].Site = "192.0.2.1" }},
		{"uppercase site", "usage", func(o *AuditObservation) { o.Usage[0].Site = "Example.com" }},
		{"first before hour", "block", func(o *AuditObservation) { o.Hits[0].FirstMS = o.Hour - 1 }},
		{"last at next hour", "block", func(o *AuditObservation) { o.Hits[0].LastMS = o.Hour + AuditHourMS }},
		{"inverted time", "block", func(o *AuditObservation) { o.Hits[0].FirstMS = o.Hour + 2; o.Hits[0].LastMS = o.Hour + 1 }},
		{"duplicate hit key", "block", func(o *AuditObservation) { other := o.Hits[0]; other.Count++; o.Hits = append(o.Hits, other) }},
		{"duplicate usage key", "usage", func(o *AuditObservation) { other := o.Usage[0]; other.Count++; o.Usage = append(o.Usage, other) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := auditFixture(tc.kind)
			tc.change(&o)
			if err := ValidateAuditObservation(o); err == nil {
				t.Fatal("malformed observation accepted")
			}
		})
	}
}

func TestAuditRowAndEncodedSizeLimits(t *testing.T) {
	for _, kind := range []string{"block", "usage"} {
		o := auditFixture(kind)
		if kind == "block" {
			row := o.Hits[0]
			o.Hits = make([]AuditHit, MaxAuditHits)
			for i := range o.Hits {
				row.Port = uint16(i + 1)
				o.Hits[i] = row
			}
		} else {
			row := o.Usage[0]
			o.Usage = make([]AuditUsage, MaxAuditUsage)
			for i := range o.Usage {
				row.Subject = NewSubjectKey(int64(i + 1))
				o.Usage[i] = row
			}
		}
		if err := ValidateAuditObservation(o); err != nil {
			t.Fatalf("at row limit %s: %v", kind, err)
		}
		if kind == "block" {
			o.Hits = append(o.Hits, o.Hits[0])
		} else {
			o.Usage = append(o.Usage, o.Usage[0])
		}
		if err := ValidateAuditObservation(o); err == nil {
			t.Fatalf("%s row overflow accepted", kind)
		}
	}
	o := auditFixture("block")
	row := o.Hits[0]
	row.Dest = strings.Repeat("a", 253)
	o.Hits = make([]AuditHit, MaxAuditHits)
	for i := range o.Hits {
		row.Port = uint16(i + 1)
		o.Hits[i] = row
	}
	encoded, err := json.Marshal(o)
	if err != nil || len(encoded) <= MaxAuditObservationBytes {
		t.Fatalf("bad byte-limit fixture: %d, %v", len(encoded), err)
	}
	if err := ValidateAuditObservation(o); err == nil {
		t.Fatal("oversize subtree accepted")
	}
}

func TestAuditHourArithmeticDoesNotOverflow(t *testing.T) {
	o := auditFixture("block")
	o.Hour = math.MaxInt64 / AuditHourMS * AuditHourMS
	o.Hits[0].Hour = o.Hour
	o.Hits[0].FirstMS = o.Hour
	o.Hits[0].LastMS = math.MaxInt64
	if err := ValidateAuditObservation(o); err != nil {
		t.Fatalf("within the mathematical hour: %v", err)
	}
	o.Hits[0].LastMS = math.MinInt64
	if err := ValidateAuditObservation(o); err == nil {
		t.Fatal("overflowed timestamp accepted")
	}
}

func TestAuditReportIsolationCapabilitiesAndPartialWire(t *testing.T) {
	for _, partial := range []bool{false, true} {
		r := NodeReport{AgentID: "audit-agent", Partial: partial, Have: emptyHave()}
		before, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		o := auditFixture("block")
		r.Audit = &o
		if err := ValidateNodeReportBase(r); err != nil {
			t.Fatal(err)
		}
		if err := ValidateNodeReport(r); err == nil {
			t.Fatal("missing audit hits capability accepted")
		}
		r.Capabilities = []string{CapabilityAuditHits}
		if err := ValidateNodeReport(r); err != nil {
			t.Fatal(err)
		}
		r.PolicyStatus = &PolicyStatus{State: "applied"}
		r.Capabilities = append(r.Capabilities, CapabilityDestinationPolicy)
		wire, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(wire, &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields["audit"]) == 0 {
			t.Fatalf("audit disappeared from partial=%v", partial)
		}
		if len(fields["policy_status"]) == 0 {
			t.Fatalf("policy status disappeared alongside audit, partial=%v", partial)
		}
		var decoded NodeReport
		if err := json.Unmarshal(wire, &decoded); err != nil || decoded.Audit == nil || decoded.Audit.BatchID != o.BatchID {
			t.Fatalf("round trip: %+v, %v", decoded.Audit, err)
		}
		o.BatchID = "bad"
		if err := ValidateNodeReportBase(r); err != nil {
			t.Fatalf("audit rejected control base: %v", err)
		}
		if err := ValidateNodeReport(r); err == nil {
			t.Fatal("sender accepted malformed audit")
		}
		r.Audit = nil
		r.PolicyStatus = nil
		r.Capabilities = nil
		after, err := json.Marshal(r)
		if err != nil || string(before) != string(after) {
			t.Fatalf("nil audit changed wire: %s vs %s (%v)", before, after, err)
		}
	}
	for _, counterOnly := range []bool{false, true} {
		o := auditFixture("usage")
		if counterOnly {
			o.Usage = nil
			o.Dropped = 1
		}
		r := NodeReport{AgentID: "audit-agent", Partial: true, Have: emptyHave(), Capabilities: []string{CapabilityAuditHits}, Audit: &o}
		if err := ValidateNodeReport(r); err == nil {
			t.Fatalf("usage capability not required, counters=%v", counterOnly)
		}
		r.Capabilities = append(r.Capabilities, CapabilityAuditUsage)
		if err := ValidateNodeReport(r); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTrialWireCarriesExplicitAnonymousFields(t *testing.T) {
	o := auditFixture("trial")
	wire, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire, []byte(`"subject":""`)) || !bytes.Contains(wire, []byte(`"port":0`)) || bytes.Contains(wire, []byte("usr_")) {
		t.Fatalf("trial anonymity changed on the wire: %s", wire)
	}
}

// Exercise all four kinds past the initial gates. Accepted observations must
// preserve every frozen field and canonical bytes across encoding and both
// report shapes. Rejected audit must remain independent of base validation.
func FuzzValidateAuditObservation(f *testing.F) {
	for _, kind := range []string{"block", "observe", "trial", "usage"} {
		for _, counters := range []bool{false, true} {
			o := auditFixture(kind)
			if counters {
				o.Hits = nil
				o.Usage = nil
				o.Dropped = math.MaxUint64
				o.Unmatched = 1
			}
			if err := ValidateAuditObservation(o); err != nil {
				f.Fatal(err)
			}
			wire, err := json.Marshal(o)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(wire)
		}
	}
	f.Add([]byte(`null`))
	f.Add([]byte(`{"kind":"trial","hits":[{"subject":"usr_1","port":443}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > MaxAuditObservationBytes+1 {
			return
		}
		var o AuditObservation
		if json.Unmarshal(body, &o) != nil {
			return
		}
		for _, partial := range []bool{false, true} {
			r := NodeReport{AgentID: "audit-agent", Partial: partial, Have: emptyHave(), Audit: &o}
			if err := ValidateNodeReportBase(r); err != nil {
				t.Fatalf("audit affected base: %v", err)
			}
		}
		if ValidateAuditObservation(o) != nil {
			return
		}
		wire, err := json.Marshal(o)
		if err != nil || len(wire) > MaxAuditObservationBytes {
			t.Fatalf("accepted encoding: %v, %d bytes", err, len(wire))
		}
		var decoded AuditObservation
		if err := json.Unmarshal(wire, &decoded); err != nil {
			t.Fatal(err)
		}
		if err := ValidateAuditObservation(decoded); err != nil {
			t.Fatalf("round trip validation: %v", err)
		}
		again, err := json.Marshal(decoded)
		if err != nil || !bytes.Equal(wire, again) {
			t.Fatal("unstable audit encoding")
		}
		for _, partial := range []bool{false, true} {
			r := NodeReport{AgentID: "audit-agent", Partial: partial, Have: emptyHave(), Audit: &decoded, Capabilities: []string{CapabilityAuditHits, CapabilityAuditUsage}}
			if err := ValidateNodeReport(r); err != nil {
				t.Fatalf("accepted audit rejected by sender: %v", err)
			}
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var report NodeReport
			if err := json.Unmarshal(encoded, &report); err != nil {
				t.Fatal(err)
			}
			if report.Audit == nil || !reflect.DeepEqual(*report.Audit, decoded) {
				t.Fatal("frozen audit changed in report round trip")
			}
			if err := ValidateNodeReport(report); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestAuditWireTypesRejectOverflow(t *testing.T) {
	for _, field := range []string{`"port":70000`, `"count":4294967296`, `"count":"1"`, `"count":-1`} {
		var o AuditObservation
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{"hits":[{%s}]}`, field)), &o); err == nil {
			t.Fatalf("wire overflow accepted: %s", field)
		}
	}
}
