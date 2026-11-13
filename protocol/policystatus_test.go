package protocol

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const goodDigest = "7ba8cd1b81f42df4393747c9b9313b48338c908d2b866e67b450ced654521d0c"

func TestValidatePolicyStatusAccepts(t *testing.T) {
	for name, status := range map[string]PolicyStatus{
		"applied":                  {Digest: goodDigest, State: PolicyStateApplied},
		"applied without a digest": {State: PolicyStateApplied},
		"rejected":                 {Digest: goodDigest, State: PolicyStateRejected, IssueCode: IssueDestinationPolicyRejected},
		"rejected without digest":  {State: PolicyStateRejected, IssueCode: IssueDestinationPolicyRejected},
		"sniffing insufficient": {Digest: goodDigest, State: PolicyStateRejected,
			IssueCode: IssueDestinationPolicySniffingInsufficient, Listeners: []ListenerKey{"lst_1", "lst_2"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePolicyStatus(status); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidatePolicyStatusRejects(t *testing.T) {
	many := make([]ListenerKey, MaxPolicyStatusListeners+1)
	for i := range many {
		many[i] = NewListenerKey(int64(i + 1))
	}
	// Canonical row ids are not zero padded, so numeric order is not bytewise.
	sort.Slice(many, func(a, b int) bool { return many[a] < many[b] })
	for name, status := range map[string]PolicyStatus{
		"no state":                                {Digest: goodDigest},
		"unknown state":                           {State: "pending"},
		"short digest":                            {Digest: "abcd", State: PolicyStateApplied},
		"uppercase digest":                        {Digest: strings.ToUpper(goodDigest), State: PolicyStateApplied},
		"non-hex digest":                          {Digest: strings.Repeat("z", 64), State: PolicyStateApplied},
		"applied with issue":                      {State: PolicyStateApplied, IssueCode: IssueDestinationPolicyRejected},
		"applied with listeners":                  {State: PolicyStateApplied, Listeners: []ListenerKey{"lst_1"}},
		"rejected without issue":                  {State: PolicyStateRejected},
		"rejected, unknown issue":                 {State: PolicyStateRejected, IssueCode: "something_else"},
		"rejected, oversize issue":                {State: PolicyStateRejected, IssueCode: strings.Repeat("a", MaxIssueCodeBytes+1)},
		"listeners with wrong code":               {State: PolicyStateRejected, IssueCode: IssueDestinationPolicyRejected, Listeners: []ListenerKey{"lst_1"}},
		"listener bad key":                        {State: PolicyStateRejected, IssueCode: IssueDestinationPolicySniffingInsufficient, Listeners: []ListenerKey{"usr_1"}},
		"sniffing insufficient without listeners": {State: PolicyStateRejected, IssueCode: IssueDestinationPolicySniffingInsufficient},
		"listeners unsorted":                      {State: PolicyStateRejected, IssueCode: IssueDestinationPolicySniffingInsufficient, Listeners: []ListenerKey{"lst_2", "lst_1"}},
		"listeners duplicate":                     {State: PolicyStateRejected, IssueCode: IssueDestinationPolicySniffingInsufficient, Listeners: []ListenerKey{"lst_1", "lst_1"}},
		"too many listeners":                      {State: PolicyStateRejected, IssueCode: IssueDestinationPolicySniffingInsufficient, Listeners: many},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePolicyStatus(status); err == nil {
				t.Fatalf("accepted %+v", status)
			}
		})
	}
	ok := many[:MaxPolicyStatusListeners]
	if err := ValidatePolicyStatus(PolicyStatus{State: PolicyStateRejected, IssueCode: IssueDestinationPolicySniffingInsufficient, Listeners: ok}); err != nil {
		t.Fatalf("rejected exactly the listener limit: %v", err)
	}
}

func policyReport(partial bool, capabilities []string) NodeReport {
	return NodeReport{
		AgentID: "a1", ProtocolVersion: ProtocolVersion1, Partial: partial, Have: emptyHave(),
		Capabilities: capabilities,
		PolicyStatus: &PolicyStatus{Digest: goodDigest, State: PolicyStateApplied},
	}
}

// A report field added to NodeReport alone vanishes from every partial report,
// because partial reports are written through a second hand-written shape.
func TestPolicyStatusSurvivesFullAndPartialReports(t *testing.T) {
	for _, partial := range []bool{false, true} {
		report := policyReport(partial, []string{CapabilityDestinationPolicy})
		wire, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		want := `"policy_status":{"digest":"` + goodDigest + `","state":"applied"}`
		if !strings.Contains(string(wire), want) {
			t.Fatalf("partial=%v: policy_status missing from %s", partial, wire)
		}
		var decoded NodeReport
		if err := json.Unmarshal(wire, &decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded.PolicyStatus, report.PolicyStatus) {
			t.Fatalf("partial=%v: policy status did not round trip: %+v", partial, decoded.PolicyStatus)
		}
	}
}

func TestValidateNodeReportBindsPolicyStatusToCapability(t *testing.T) {
	if err := ValidateNodeReport(policyReport(false, []string{CapabilityDestinationPolicy})); err != nil {
		t.Fatalf("declared capability: %v", err)
	}
	if err := ValidateNodeReport(policyReport(true, []string{CapabilityDestinationPolicy})); err != nil {
		t.Fatalf("partial, declared capability: %v", err)
	}
	if err := ValidateNodeReport(policyReport(false, nil)); err == nil {
		t.Fatal("sender check accepted a policy status without the capability")
	}
	bad := policyReport(false, []string{CapabilityDestinationPolicy})
	bad.PolicyStatus.State = "pending"
	if err := ValidateNodeReport(bad); err == nil {
		t.Fatal("sender check accepted an invalid policy status")
	}
	// Declaring the capability and carrying no status is the common round.
	plain := NodeReport{AgentID: "a1", Have: emptyHave(), Capabilities: []string{CapabilityDestinationPolicy}}
	if err := ValidateNodeReport(plain); err != nil {
		t.Fatalf("capability without status: %v", err)
	}
}

// The receiver validates the subtree in isolation (ValidatePolicyStatus), so a
// bad or capability-less status must not cost the node its whole report: the
// base check, which decides whether anything in the report is trusted, stays
// silent about it.
func TestValidateNodeReportBaseDoesNotJudgePolicyStatus(t *testing.T) {
	report := policyReport(false, nil)
	if err := ValidateNodeReportBase(report); err != nil {
		t.Fatalf("base check judged an absent-capability status: %v", err)
	}
	report.PolicyStatus.State = "pending"
	if err := ValidateNodeReportBase(report); err != nil {
		t.Fatalf("base check judged an invalid status: %v", err)
	}
}

// FuzzValidatePolicyStatus is the status half's counterpart of
// FuzzValidateDestinationPolicy. The status arrives from a node, so it is
// parsed on the panel before anything about it is trusted.
//
// An accepted status must re-encode to the same bytes and stay accepted.
func FuzzValidatePolicyStatus(fuzz *testing.F) {
	seeds := []PolicyStatus{
		{Digest: goodDigest, State: PolicyStateApplied},
		{State: PolicyStateRejected, IssueCode: IssueDestinationPolicyRejected},
		{Digest: goodDigest, State: PolicyStateRejected, IssueCode: IssueDestinationPolicySniffingInsufficient,
			Listeners: []ListenerKey{"lst_1", "lst_2"}},
	}
	for index, seed := range seeds {
		if err := ValidatePolicyStatus(seed); err != nil {
			fuzz.Fatalf("seed %d is rejected, so it seeds nothing past the check that rejects it: %v", index, err)
		}
		fuzz.Add(mustMarshal(fuzz, seed))
	}

	fuzz.Fuzz(func(t *testing.T, body []byte) {
		var status PolicyStatus
		if err := json.Unmarshal(body, &status); err != nil {
			return
		}
		if err := ValidatePolicyStatus(status); err != nil {
			return
		}
		wire, err := json.Marshal(status)
		if err != nil {
			t.Fatalf("an accepted status failed to encode: %v", err)
		}
		var decoded PolicyStatus
		if err := json.Unmarshal(wire, &decoded); err != nil {
			t.Fatalf("an accepted status failed to decode its own encoding: %v\n%s", err, wire)
		}
		if err := ValidatePolicyStatus(decoded); err != nil {
			t.Fatalf("an accepted status became invalid after a round trip: %v\n%s", err, wire)
		}
		again, _ := json.Marshal(decoded)
		if !bytes.Equal(wire, again) {
			t.Fatalf("an accepted status does not re-encode to the same bytes:\n first=%s\nsecond=%s", wire, again)
		}
	})
}
