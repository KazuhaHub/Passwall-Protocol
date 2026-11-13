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
