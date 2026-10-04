package protocol

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func destinationPolicySample() *DestinationPolicy {
	return &DestinationPolicy{Collect: CollectHits, CollectRevision: 1, Rules: []DestinationRule{
		{ID: "p12", Action: RuleBlock, Domains: []string{"domain:example.com"}},
	}}
}

func TestDestinationPolicyValidationAndBounds(t *testing.T) {
	if err := ValidateDestinationPolicy(nil); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*DestinationPolicy)
	}{
		{"empty rule must not widen", func(p *DestinationPolicy) { p.Rules[0].Domains = nil }},
		{"catch all requires subjects", func(p *DestinationPolicy) { p.Rules[0].Domains = nil; p.Rules[0].CatchAll = true }},
		{"catch all forbids match fields", func(p *DestinationPolicy) { p.Rules[0].Subjects = []SubjectKey{"usr_1"}; p.Rules[0].CatchAll = true }},
		{"unknown action", func(p *DestinationPolicy) { p.Rules[0].Action = "drop" }},
		{"invalid ID", func(p *DestinationPolicy) { p.Rules[0].ID = "g1x12345" }},
		{"duplicate IDs", func(p *DestinationPolicy) { p.Rules = append(p.Rules, p.Rules[0]) }},
		{"invalid collection level", func(p *DestinationPolicy) { p.Collect = "off" }},
		{"collection requires revision", func(p *DestinationPolicy) { p.CollectRevision = 0 }},
		{"no collection forbids revision", func(p *DestinationPolicy) { p.Collect = "" }},
		{"unsorted domain set", func(p *DestinationPolicy) { p.Rules[0].Domains = []string{"full:z.test", "domain:a.test"} }},
		{"duplicate domain", func(p *DestinationPolicy) { p.Rules[0].Domains = append(p.Rules[0].Domains, p.Rules[0].Domains[0]) }},
		{"uppercase domain", func(p *DestinationPolicy) { p.Rules[0].Domains = []string{"domain:EXAMPLE.com"} }},
		{"empty keyword", func(p *DestinationPolicy) { p.Rules[0].Domains = []string{"keyword:"} }},
		{"invalid regular expression", func(p *DestinationPolicy) { p.Rules[0].Domains = []string{"regexp:["} }},
		{"too many expressions", func(p *DestinationPolicy) {
			p.Rules[0].Domains = nil
			for i := 0; i < MaxDestinationRegexps+1; i++ {
				p.Rules[0].Domains = append(p.Rules[0].Domains, fmt.Sprintf("regexp:%03d", i))
			}
		}},
		{"unmasked CIDR", func(p *DestinationPolicy) { p.Rules[0].CIDRs = []string{"10.0.0.1/8"} }},
		{"invalid subject", func(p *DestinationPolicy) { p.Exempt = []SubjectKey{"usr_01"} }},
		{"duplicate exemption", func(p *DestinationPolicy) { p.Exempt = []SubjectKey{"usr_1", "usr_1"} }},
		{"out of range port", func(p *DestinationPolicy) { p.Rules[0].Ports = "65536" }},
		{"reversed port range", func(p *DestinationPolicy) { p.Rules[0].Ports = "90-80" }},
		{"invalid port grammar", func(p *DestinationPolicy) { p.Rules[0].Ports = "80, 443" }},
		{"unknown network", func(p *DestinationPolicy) { p.Rules[0].Network = "icmp" }},
		{"unknown protocol", func(p *DestinationPolicy) { p.Rules[0].Domains = nil; p.Rules[0].Protocols = []string{"tls"} }},
		{"protocol with domains", func(p *DestinationPolicy) { p.Rules[0].Protocols = []string{"bittorrent"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := destinationPolicySample()
			test.change(p)
			if err := ValidateDestinationPolicy(p); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	for _, rule := range []DestinationRule{
		{ID: "g1", Action: RuleBlock, Subjects: []SubjectKey{"usr_1"}, CatchAll: true},
		{ID: "p1", Action: RuleAllow, Ports: "25,465,587,6881-6889"},
		{ID: "p1", Action: RuleObserve, Network: "udp"},
		{ID: "p1", Action: RuleBlock, CIDRs: []string{"10.0.0.0/8"}, Private: true},
		{ID: "p1", Action: RuleBlock, Protocols: []string{"bittorrent"}},
	} {
		if err := ValidateDestinationPolicy(&DestinationPolicy{Rules: []DestinationRule{rule}}); err != nil {
			t.Fatalf("valid rule rejected: %v", err)
		}
	}
}

func TestDestinationPolicyExactLimitsAndOverflow(t *testing.T) {
	for _, test := range []struct {
		name  string
		limit int
		build func(int) *DestinationPolicy
	}{
		{"rules", MaxDestinationRules, func(n int) *DestinationPolicy {
			p := &DestinationPolicy{}
			for i := 0; i < n; i++ {
				p.Rules = append(p.Rules, DestinationRule{ID: fmt.Sprintf("p%d", i+1), Action: RuleBlock, Ports: "25"})
			}
			return p
		}},
		{"domains", MaxDestinationDomains, func(n int) *DestinationPolicy {
			p := destinationPolicySample()
			p.Rules[0].Domains = nil
			for i := 0; i < n; i++ {
				p.Rules[0].Domains = append(p.Rules[0].Domains, fmt.Sprintf("full:%05d.example", i))
			}
			return p
		}},
		{"expressions", MaxDestinationRegexps, func(n int) *DestinationPolicy {
			p := destinationPolicySample()
			p.Rules[0].Domains = nil
			for i := 0; i < n; i++ {
				p.Rules[0].Domains = append(p.Rules[0].Domains, fmt.Sprintf("regexp:%03d", i))
			}
			return p
		}},
		{"CIDRs", MaxDestinationCIDRs, func(n int) *DestinationPolicy {
			p := destinationPolicySample()
			for i := 0; i < n; i++ {
				p.Rules[0].CIDRs = append(p.Rules[0].CIDRs, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
			}
			sort.Strings(p.Rules[0].CIDRs)
			return p
		}},
		{"subjects plus exemptions", MaxDestinationSubjects, func(n int) *DestinationPolicy {
			p := destinationPolicySample()
			for i := 0; i < n; i++ {
				s := NewSubjectKey(int64(100000 + i))
				if i%2 == 0 {
					p.Exempt = append(p.Exempt, s)
				} else {
					p.Rules[0].Subjects = append(p.Rules[0].Subjects, s)
				}
			}
			return p
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateDestinationPolicy(test.build(test.limit)); err != nil {
				t.Fatalf("exact limit rejected: %v", err)
			}
			if err := ValidateDestinationPolicy(test.build(test.limit + 1)); err == nil {
				t.Fatal("limit overflow accepted")
			}
		})
	}
	p := destinationPolicySample()
	p.Rules[0].Domains = []string{"keyword:" + strings.Repeat("x", MaxDestinationPolicyBytes)}
	if err := ValidateDestinationPolicy(p); err == nil {
		t.Fatal("encoded byte limit overflow accepted")
	}
	for _, capability := range AgentUpgradeCapabilities() {
		if capability == CapabilityDestinationPolicy {
			t.Fatal("optional destination policy changed upgrade requirements")
		}
	}
}

func TestNilDestinationPolicyPreservesV020ConfigBytes(t *testing.T) {
	type oldConfig struct {
		Listeners []Listener    `json:"listeners"`
		Coverage  SegmentCounts `json:"coverage"`
		Core      CoreSelection `json:"core"`
	}
	for _, config := range []ConfigBody{{}, {Listeners: []Listener{}, Core: CoreSelection{Engine: "xray", Version: "26.6.27"}}, {Listeners: []Listener{{Key: "lst_1", Config: RawConfig(`{"port":443}`)}}}} {
		before, err := json.Marshal(oldConfig{config.Listeners, config.Coverage, config.Core})
		if err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatalf("nil policy changed config bytes: %s != %s", before, after)
		}
	}
}

func TestPolicyDigestPreservesExecutionOrder(t *testing.T) {
	if PolicyDigest(nil) != "" {
		t.Fatal("nil digest must remain empty")
	}
	p := destinationPolicySample()
	p.Rules = []DestinationRule{{ID: "p9", Action: RuleAllow, Domains: []string{"domain:example.com"}}, {ID: "p1", Action: RuleBlock, Domains: []string{"domain:example.com"}}}
	if err := ValidateDestinationPolicy(p); err != nil {
		t.Fatal(err)
	}
	before := PolicyDigest(p)
	p.Rules[0], p.Rules[1] = p.Rules[1], p.Rules[0]
	if before == PolicyDigest(p) {
		t.Fatal("changing execution order must change digest")
	}
}

func TestPolicyStatusIsIsolatedAndPreservedInPartialReports(t *testing.T) {
	status := &PolicyStatus{Digest: PolicyDigest(destinationPolicySample()), State: "applied"}
	for _, partial := range []bool{false, true} {
		r := NodeReport{AgentID: "agent-1", Have: emptyHave(), Partial: partial, PolicyStatus: status, Capabilities: []string{CapabilityDestinationPolicy}}
		body, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var decoded NodeReport
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded.PolicyStatus, status) {
			t.Fatal("policy status lost from report")
		}
		if err := ValidateNodeReport(r); err != nil {
			t.Fatal(err)
		}
		r.Capabilities = nil
		if err := ValidateNodeReport(r); err == nil {
			t.Fatal("status without capability accepted")
		}
		r.PolicyStatus = &PolicyStatus{State: "broken"}
		if err := ValidateNodeReportBase(r); err != nil {
			t.Fatalf("invalid observation blocked base control report: %v", err)
		}
	}
}

func TestPolicyStatusValidation(t *testing.T) {
	for _, good := range []PolicyStatus{{State: "applied"}, {State: "applied", Digest: strings.Repeat("a", 64)}, {State: "rejected", Digest: strings.Repeat("a", 64), IssueCode: IssueDestinationPolicyRejected}, {State: "rejected", Digest: strings.Repeat("a", 64), IssueCode: IssueDestinationPolicySniffingInsufficient, Listeners: []ListenerKey{"lst_1", "lst_2"}}} {
		if err := ValidatePolicyStatus(good); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []PolicyStatus{{State: "unknown"}, {State: "rejected", IssueCode: IssueDestinationPolicyRejected}, {State: "applied", Digest: strings.Repeat("A", 64)}, {State: "applied", IssueCode: IssueDestinationPolicyRejected}, {State: "rejected", Digest: strings.Repeat("a", 64), IssueCode: "core_convergence_failed"}, {State: "rejected", Digest: strings.Repeat("a", 64), IssueCode: IssueDestinationPolicyRejected, Listeners: []ListenerKey{"lst_1"}}, {State: "rejected", Digest: strings.Repeat("a", 64), IssueCode: IssueDestinationPolicySniffingInsufficient, Listeners: []ListenerKey{"lst_2", "lst_1"}}} {
		if err := ValidatePolicyStatus(bad); err == nil {
			t.Fatalf("invalid status accepted: %#v", bad)
		}
	}
}

func FuzzValidateDestinationPolicy(f *testing.F) {
	seed, _ := json.Marshal(destinationPolicySample())
	f.Add(seed)
	f.Add([]byte(`null`))
	f.Add([]byte(`{"rules":[{"id":"g1","action":"block","catch_all":true}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > MaxDestinationPolicyBytes+1 {
			return
		}
		var p *DestinationPolicy
		if json.Unmarshal(body, &p) != nil {
			return
		}
		if ValidateDestinationPolicy(p) == nil {
			first := PolicyDigest(p)
			if first != PolicyDigest(p) {
				t.Fatal("unstable digest")
			}
			_ = MatchDestination(p, "usr_1", "example.com", 443, "tcp")
		}
	})
}

func FuzzValidatePolicyStatus(f *testing.F) {
	f.Add([]byte(`{"state":"applied","digest":""}`))
	f.Add([]byte(`{"state":"rejected","digest":"bad"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<20 {
			return
		}
		var s PolicyStatus
		if json.Unmarshal(body, &s) == nil {
			_ = ValidatePolicyStatus(s)
		}
	})
}
