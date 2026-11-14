package protocol

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
)

// The table is pinned entry by entry: "private" means exactly what xray-core's
// GetPrivateIPMatcher means, and a block rule that drifted from it would let a
// destination through that the core's own `geoip:private` would have stopped.
func TestPrivateDestinationCIDRsMatchXray(t *testing.T) {
	want := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3", "::/127", "fc00::/7", "fe80::/10", "ff00::/8",
	}
	if !reflect.DeepEqual(PrivateDestinationCIDRs(), want) {
		t.Fatalf("PrivateDestinationCIDRs() = %v", PrivateDestinationCIDRs())
	}
	for _, c := range PrivateDestinationCIDRs() {
		p, err := netip.ParsePrefix(c)
		if err != nil || p.Masked().String() != c {
			t.Fatalf("%q is not a canonical prefix", c)
		}
	}
}

// MatchDestination is a diagnostic tool fed whatever policy PSP holds, so it
// must degrade, not panic, on a policy that would not validate.
func TestMatchDestinationToleratesInvalidPolicies(t *testing.T) {
	policy := &DestinationPolicy{Rules: []DestinationRule{
		{ID: "??", Action: "bogus", Domains: []string{"regexp:(", "nonsense", "domain:"}, CIDRs: []string{"x"}, Ports: "9-1,abc"},
		{ID: "p1", Action: RuleBlock},
	}}
	for _, in := range []MatchInput{
		{}, {Target: "a.example", Port: 80}, {Target: "10.0.0.1", Source: "garbage", Port: 1},
	} {
		got := MatchDestination(policy, in)
		if got.Verdict == "" {
			t.Fatalf("empty verdict for %+v", in)
		}
	}
}

func TestMatchDestinationIsPure(t *testing.T) {
	policy := validPolicy()
	before := PolicyDigest(policy)
	MatchDestination(policy, MatchInput{Target: "10.1.1.1", Subject: "usr_1", Port: 25, Network: "tcp"})
	if PolicyDigest(policy) != before {
		t.Fatal("MatchDestination modified the policy")
	}
}

// The table is what `private` means, so a caller scribbling on what it got must
// not be able to change what a rule matches.
func TestPrivateDestinationCIDRsReturnsACopy(t *testing.T) {
	first := PrivateDestinationCIDRs()
	first[0] = "8.8.8.8/32"
	if again := PrivateDestinationCIDRs(); again[0] != "0.0.0.0/8" {
		t.Fatalf("the table changed under a caller: %v", again[0])
	}
	policy := &DestinationPolicy{Rules: []DestinationRule{{ID: "p1", Action: RuleBlock, Private: true}}}
	if got := MatchDestination(policy, MatchInput{Target: "8.8.8.8"}); got.Verdict != MatchDefault {
		t.Fatalf("a caller's edit reached the matcher: %+v", got)
	}
}

func TestMatchDestinationTypedOutcomes(t *testing.T) {
	if BuiltinTrailingDot != "trailing_dot" || NoteHostnameSkipsIPRules != "hostname_skips_ip_rules" {
		t.Fatal("a builtin or note changed its wire spelling")
	}
	var verdict MatchVerdict = MatchBlock
	var result MatchStepResult = StepHit
	if verdict != "block" || result != "hit" {
		t.Fatal("the typed constants changed their wire spelling")
	}
	for got, want := range map[string]string{
		string(MatchAllow): "allow", string(MatchBlock): "block", string(MatchObserve): "observe", string(MatchDefault): "default",
		string(StepHit): "hit", string(StepMiss): "miss", string(StepUntestable): "untestable",
		string(StepShadowed): "shadowed", string(StepSkipped): "skipped",
	} {
		if got != want {
			t.Fatalf("constant spelled %q, want %q", got, want)
		}
	}
}

// FuzzMatchDestination is pointed at whatever policy PSP holds, valid or not,
// and at whatever a person types into the test tool. It must never panic and
// its trace must be well-formed: one step per rule (plus the exempt step when
// there is an exempt list), and at most one hit.
func FuzzMatchDestination(fuzz *testing.F) {
	fuzz.Add([]byte(`{"policy":{"rules":[{"id":"p1","action":"block","domains":["domain:example.com"]}]},"input":{"target":"www.example.com"}}`))
	fuzz.Add([]byte(`{"policy":{"rules":[{"id":"s1","action":"block","source_cidrs":["203.0.113.0/24"]},{"id":"p1","action":"allow","private":true,"ports":"1-5"}],"exempt":["usr_1"]},"input":{"subject":"usr_1","source":"203.0.113.1","target":"[::1]","port":3,"network":"TCP"}}`))
	fuzz.Add([]byte(`{"policy":{"rules":[{"id":"zz","action":"x","domains":["regexp:(","keyword:"],"cidrs":["x"],"ports":"9-1"}]},"input":{"target":" 010.1.1.1. "}}`))
	fuzz.Fuzz(func(t *testing.T, body []byte) {
		var doc struct {
			Policy *DestinationPolicy `json:"policy"`
			Input  MatchInput         `json:"input"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return
		}
		got := MatchDestination(doc.Policy, doc.Input)
		switch got.Verdict {
		case MatchAllow, MatchBlock, MatchObserve, MatchDefault:
		default:
			t.Fatalf("verdict %q is not one of the four", got.Verdict)
		}
		hits := 0
		for _, step := range got.Steps {
			switch step.Result {
			case StepHit:
				hits++
			case StepMiss, StepUntestable, StepShadowed, StepSkipped:
			default:
				t.Fatalf("step result %q is not one of the five", step.Result)
			}
		}
		if hits > 1 {
			t.Fatalf("%d hits in one trace: %+v", hits, got.Steps)
		}
		want := 0
		if doc.Policy != nil {
			want = len(doc.Policy.Rules)
			if len(doc.Policy.Exempt) > 0 {
				want++
			}
			// The trailing-dot builtin has a step exactly when a block rule has
			// domains.
			for _, rule := range doc.Policy.Rules {
				if rule.Action == RuleBlock && len(rule.Domains) > 0 {
					want++
					break
				}
			}
		}
		if len(got.Steps) != want {
			t.Fatalf("%d steps for %d expected: %+v", len(got.Steps), want, got.Steps)
		}
		if (got.Verdict == MatchDefault) != (hits == 0) {
			t.Fatalf("verdict %q with %d hits", got.Verdict, hits)
		}
	})
}

func onDemand(rules ...DestinationRule) *DestinationPolicy {
	return &DestinationPolicy{Rules: rules, Resolve: ResolveOnDemand}
}

// Under on_demand the CIDR and Private alternatives of a rule are tried on a
// hostname's resolved addresses, which is what a router that resolves first
// would do; the result is the reference answer with those addresses as input.
func TestMatch_OnDemandEqualsReferenceWithIPs(t *testing.T) {
	rules := []DestinationRule{
		{ID: "s1", Action: RuleBlock, SourceCIDRs: []string{"203.0.113.0/24"}},
		{ID: "p1", Action: RuleAllow, Domains: []string{"full:ok.example"}, CIDRs: []string{"192.0.2.0/24"}},
		{ID: "p2", Action: RuleBlock, CIDRs: []string{"10.0.0.0/8"}},
		{ID: "p3", Action: RuleBlock, Private: true},
		{ID: "g1x1", Action: RuleAllow, Subjects: []SubjectKey{"usr_1"}, Domains: []string{"full:member.example"}},
		{ID: "g1", Action: RuleBlock, Subjects: []SubjectKey{"usr_1"}, CatchAll: true},
		{ID: "p4", Action: RuleObserve, CIDRs: []string{"100.0.0.0/10"}},
	}
	for _, tc := range []struct {
		name       string
		in         MatchInput
		verdict    MatchVerdict
		terminated string
		entry      string
	}{
		{"source deny first", MatchInput{Target: "a.example", Resolved: []string{"8.8.8.8"}, Source: "203.0.113.5"}, MatchBlock, "s1", "203.0.113.0/24"},
		{"phase 1 allow by resolved cidr", MatchInput{Target: "a.example", Resolved: []string{"192.0.2.7"}}, MatchAllow, "p1", "192.0.2.0/24"},
		{"phase 1 allow by domain", MatchInput{Target: "ok.example", Resolved: []string{"10.1.1.1"}}, MatchAllow, "p1", "full:ok.example"},
		{"phase 3 block by cidr", MatchInput{Target: "a.example", Resolved: []string{"10.1.1.1"}}, MatchBlock, "p2", "10.0.0.0/8"},
		{"phase 3 block by private", MatchInput{Target: "a.example", Resolved: []string{"127.0.0.1"}}, MatchBlock, "p3", "127.0.0.0/8"},
		{"any resolved address is enough", MatchInput{Target: "a.example", Resolved: []string{"8.8.8.8", "10.9.9.9"}}, MatchBlock, "p2", "10.0.0.0/8"},
		{"an allowed address elsewhere in the set permits the allow", MatchInput{Target: "a.example", Resolved: []string{"10.9.9.9", "192.0.2.1"}}, MatchAllow, "p1", "192.0.2.0/24"},
		{"ipv6 private", MatchInput{Target: "a.example", Resolved: []string{"::1"}}, MatchBlock, "p3", "::/127"},
		{"ipv4-mapped is unmapped", MatchInput{Target: "a.example", Resolved: []string{"::ffff:10.1.1.1"}}, MatchBlock, "p2", "10.0.0.0/8"},
		{"public resolution reaches the group", MatchInput{Target: "a.example", Subject: "usr_1", Resolved: []string{"8.8.8.8"}}, MatchBlock, "g1", ""},
		{"group member allow", MatchInput{Target: "member.example", Subject: "usr_1", Resolved: []string{"8.8.8.8"}}, MatchAllow, "g1x1", "full:member.example"},
		{"a blocked cidr beats the group allow", MatchInput{Target: "member.example", Subject: "usr_1", Resolved: []string{"10.0.0.1"}}, MatchBlock, "p2", "10.0.0.0/8"},
		{"private beats the group allow", MatchInput{Target: "member.example", Subject: "usr_1", Resolved: []string{"172.16.0.1"}}, MatchBlock, "p3", "172.16.0.0/12"},
		{"observe last", MatchInput{Target: "a.example", Resolved: []string{"100.1.1.1"}}, MatchObserve, "p4", "100.0.0.0/10"},
		{"nothing hits", MatchInput{Target: "a.example", Resolved: []string{"8.8.8.8"}}, MatchDefault, "", ""},
		{"an address target is matched directly and Resolved is ignored", MatchInput{Target: "10.2.2.2", Resolved: []string{"8.8.8.8"}}, MatchBlock, "p2", "10.0.0.0/8"},
		{"an unparsable resolved entry is ignored", MatchInput{Target: "a.example", Resolved: []string{"nonsense", "10.1.1.1"}}, MatchBlock, "p2", "10.0.0.0/8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.in.Source == "" {
				tc.in.Source = "8.8.4.4" // a known source that matches no source rule
			}
			got := MatchDestination(onDemandPolicy(rules), tc.in)
			if got.Verdict != tc.verdict || got.Terminated != tc.terminated {
				t.Fatalf("got %s/%q, want %s/%q: %+v", got.Verdict, got.Terminated, tc.verdict, tc.terminated, got.Steps)
			}
			if got.Conditional {
				t.Fatalf("conditional: %+v", got.Steps)
			}
			if tc.entry != "" {
				last := got.Steps[len(got.Steps)-1]
				for _, s := range got.Steps {
					if s.Result == StepHit {
						last = s
					}
				}
				if last.Entry != tc.entry {
					t.Fatalf("entry = %q, want %q", last.Entry, tc.entry)
				}
			}
			if len(got.Notes) != 0 {
				t.Fatalf("unexpected notes %v", got.Notes)
			}
		})
	}
}

func onDemandPolicy(rules []DestinationRule) *DestinationPolicy {
	return &DestinationPolicy{Rules: rules, Resolve: ResolveOnDemand}
}

func TestMatch_OnDemandWithoutResolvedIsConditional(t *testing.T) {
	p := onDemand(
		DestinationRule{ID: "p1", Action: RuleBlock, CIDRs: []string{"10.0.0.0/8"}},
		DestinationRule{ID: "p2", Action: RuleBlock, Domains: []string{"full:b.example"}},
	)
	got := MatchDestination(p, MatchInput{Target: "a.example"})
	if got.Verdict != MatchDefault || !got.Conditional {
		t.Fatalf("got %s conditional=%v, want default/conditional: %+v", got.Verdict, got.Conditional, got.Steps)
	}
	if got.Steps[len(got.Steps)-2].Result != StepUntestable {
		t.Fatalf("steps = %+v", got.Steps)
	}
	if !reflect.DeepEqual(got.Notes, []MatchNote{NoteHostnameNeedsResolution}) {
		t.Fatalf("notes = %v", got.Notes)
	}
	// A later rule that does hit ends the evaluation, still conditional.
	got = MatchDestination(p, MatchInput{Target: "b.example"})
	if got.Verdict != MatchBlock || got.Terminated != "p2" || !got.Conditional {
		t.Fatalf("got %s %q conditional=%v", got.Verdict, got.Terminated, got.Conditional)
	}
	// A domain hit on the same rule is not untestable.
	q := onDemand(DestinationRule{ID: "p1", Action: RuleBlock, Domains: []string{"full:a.example"}, CIDRs: []string{"10.0.0.0/8"}})
	got = MatchDestination(q, MatchInput{Target: "a.example"})
	if got.Verdict != MatchBlock || got.Conditional || len(got.Notes) != 0 {
		t.Fatalf("domain hit: %+v", got)
	}
	// A definite miss on another field beats the untestable alternative.
	r := onDemand(DestinationRule{ID: "p1", Action: RuleBlock, CIDRs: []string{"10.0.0.0/8"}, Ports: "25"})
	got = MatchDestination(r, MatchInput{Target: "a.example", Port: 80})
	if got.Conditional || got.Steps[0].Result != StepMiss {
		t.Fatalf("port miss: %+v", got)
	}
}

func TestMatch_OnDemandResolutionFailed(t *testing.T) {
	p := onDemand(DestinationRule{ID: "p1", Action: RuleBlock, CIDRs: []string{"10.0.0.0/8"}})
	got := MatchDestination(p, MatchInput{Target: "nx.example", Resolved: []string{}})
	if got.Verdict != MatchDefault || got.Conditional {
		t.Fatalf("got %s conditional=%v", got.Verdict, got.Conditional)
	}
	if got.Steps[0].Result != StepMiss {
		t.Fatalf("steps = %+v", got.Steps)
	}
	if !reflect.DeepEqual(got.Notes, []MatchNote{NoteResolutionFailedEngineDependent}) {
		t.Fatalf("notes = %v", got.Notes)
	}
	// A non-empty resolution that misses is a clean miss.
	got = MatchDestination(p, MatchInput{Target: "a.example", Resolved: []string{"8.8.8.8"}})
	if len(got.Notes) != 0 {
		t.Fatalf("notes = %v", got.Notes)
	}
	// An address target is not a resolution failure.
	got = MatchDestination(p, MatchInput{Target: "8.8.8.8", Resolved: []string{}})
	if len(got.Notes) != 0 {
		t.Fatalf("notes = %v", got.Notes)
	}
}

// AsIs ignores Resolved altogether and keeps its note.
func TestMatch_AsIsIgnoresResolved(t *testing.T) {
	p := &DestinationPolicy{Rules: []DestinationRule{{ID: "p1", Action: RuleBlock, CIDRs: []string{"10.0.0.0/8"}}}}
	for _, resolved := range [][]string{nil, {}, {"10.1.1.1"}} {
		got := MatchDestination(p, MatchInput{Target: "a.example", Resolved: resolved})
		if got.Verdict != MatchDefault || got.Conditional || !reflect.DeepEqual(got.Notes, []MatchNote{NoteHostnameSkipsIPRules}) {
			t.Fatalf("resolved=%v: %+v", resolved, got)
		}
	}
	// An unknown mode on a policy that would not validate behaves as AsIs.
	p.Resolve = "if_non_match"
	got := MatchDestination(p, MatchInput{Target: "a.example", Resolved: []string{"10.1.1.1"}})
	if got.Verdict != MatchDefault {
		t.Fatalf("unknown mode: %+v", got)
	}
}

// Report-only must never change a verdict, with or without resolved addresses:
// turning every block rule into an observe rule (moved to the last phase) leaves
// every non-block outcome as it was and turns a block into observe or default.
func TestReport_NeverChangesAVerdictAcrossResolvedInputs(t *testing.T) {
	enforce := []DestinationRule{
		{ID: "p1", Action: RuleAllow, Domains: []string{"full:ok.example"}, CIDRs: []string{"192.0.2.0/24"}},
		{ID: "p2", Action: RuleBlock, CIDRs: []string{"10.0.0.0/8"}},
		{ID: "p3", Action: RuleBlock, Private: true},
		{ID: "p4", Action: RuleBlock, Domains: []string{"domain:bad.example"}},
		{ID: "g1x1", Action: RuleAllow, Subjects: []SubjectKey{"usr_1"}, Domains: []string{"full:member.example"}, CIDRs: []string{"8.8.8.0/24"}},
		{ID: "g1", Action: RuleBlock, Subjects: []SubjectKey{"usr_1"}, CatchAll: true},
	}
	// The report form keeps allows where they are and turns every block into an
	// observe rule in the last phase, after the group allows. A group catch-all
	// becomes a catch-all observe (a trial), and a phase-5 domain observe comes
	// after the IP blocks it follows in enforce mode.
	report := []DestinationRule{enforce[0], enforce[4]}
	catchAll := enforce[5]
	catchAll.Action = RuleObserve
	report = append(report, catchAll)
	for _, rule := range enforce[1:4] {
		rule.Action = RuleObserve
		report = append(report, rule)
	}
	report = append(report, DestinationRule{ID: "p5", Action: RuleObserve, Domains: []string{"full:obs.example"}})
	for _, mode := range []ResolveMode{ResolveAsIs, ResolveOnDemand} {
		e := &DestinationPolicy{Rules: enforce, Resolve: mode}
		r := &DestinationPolicy{Rules: report, Resolve: mode}
		if err := ValidateDestinationPolicy(r); err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{"a.example", "ok.example", "x.bad.example", "member.example", "obs.example", "10.1.1.1", "8.8.8.8", "192.0.2.4"} {
			for _, resolved := range [][]string{nil, {}, {"8.8.8.8"}, {"10.1.1.1"}, {"192.0.2.9"}, {"8.8.8.8", "127.0.0.1"}, {"fd00::1"}} {
				for _, subject := range []SubjectKey{"", "usr_1"} {
					in := MatchInput{Target: target, Resolved: resolved, Subject: subject}
					ev, rv := MatchDestination(e, in), MatchDestination(r, in)
					// Observe is an allow that is recorded, so it is the same verdict
					// as default or allow for what the connection may do.
					norm := func(v MatchVerdict) MatchVerdict {
						if v == MatchObserve {
							return MatchDefault
						}
						return v
					}
					if ev.Verdict == MatchBlock {
						if rv.Verdict == MatchBlock {
							t.Fatalf("%s %q %v %q: enforce blocks, report blocks", mode, target, resolved, subject)
						}
					} else if norm(rv.Verdict) != norm(ev.Verdict) {
						t.Fatalf("%s %q %v %q: enforce %s, report %s", mode, target, resolved, subject, ev.Verdict, rv.Verdict)
					}
					if rv.Verdict == MatchBlock {
						t.Fatalf("report-only blocked %q %v", target, resolved)
					}
				}
			}
		}
	}
}
