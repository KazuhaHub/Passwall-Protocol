package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func routedTransit() *Transit {
	return &Transit{
		LinksOut: []LinkOut{ssLinkOut(3), realityLinkOut(4)},
		Egress:   []EgressBinding{{Listener: NewListenerKey(1), Link: NewLinkKey(3)}},
		Routes: []ListenerRoutes{{Listener: NewListenerKey(1), Rules: []RouteRule{
			{ID: "r1", Domains: []string{"domain:netflix.com", "keyword:nflx"}, Exit: NewLinkKey(4)},
			{ID: "r2", CIDRs: []string{"10.0.0.0/8"}, Ports: "443", Network: "tcp", Exit: LocalExit},
		}}},
	}
}

func TestRouteCapabilityIsNotAnUpgradeCapability(t *testing.T) {
	for _, upgrade := range AgentUpgradeCapabilities() {
		if upgrade == CapabilityTransitRoute {
			t.Fatalf("%s is an upgrade capability", upgrade)
		}
	}
}

// The golden strings were written from the v0.8.x encoding before Routes and
// Exits existed: a server that routes by nothing must keep producing exactly
// these bytes, or every agent in the fleet re-applies its config and every
// policy digest moves.
func TestTransitWithoutRoutesIsByteIdenticalToV08(t *testing.T) {
	transit := Transit{
		Forwards: []Forward{validForward()},
		LinksOut: []LinkOut{ssLinkOut(3)},
		Egress:   []EgressBinding{{Listener: NewListenerKey(1), Link: NewLinkKey(3)}},
	}
	const want = `{"forwards":[{"key":"fwd_7","port":20443,"target":"landing.example.com","target_port":443,"network":"tcp"}],"links_out":[{"key":"lnk_3","address":"exit.example.com","port":30001,"protocol":"ss2022","ss":{"method":"2022-blake3-aes-128-gcm","password":"glwKkLUrNxQ4VbjbZG4svg=="}}],"egress":[{"listener":"lst_1","link":"lnk_3"}]}`
	got, err := json.Marshal(transit)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("transit without Routes changed on the wire:\n got=%s\nwant=%s", got, want)
	}
}

func TestPolicyWithoutExitsKeepsItsDigest(t *testing.T) {
	policy := &DestinationPolicy{Rules: []DestinationRule{
		{ID: "p1", Action: RuleBlock, Domains: []string{"domain:example.com"}, Ports: "25"},
		{ID: "p2", Action: RuleBlock, Inbounds: []ListenerKey{NewListenerKey(1)}, Private: true},
	}}
	const want = `{"rules":[{"id":"p1","action":"block","domains":["domain:example.com"],"ports":"25"},{"id":"p2","action":"block","inbounds":["lst_1"],"private":true}]}`
	got, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("a policy without Exits changed on the wire:\n got=%s\nwant=%s", got, want)
	}
	// The digest is the hash of exactly those bytes.
	sum := sha256.Sum256([]byte(want))
	if hex.EncodeToString(sum[:]) != PolicyDigest(policy) {
		t.Fatalf("digest %s is not the hash of the canonical bytes", PolicyDigest(policy))
	}
	policy.Rules[0].Exits = []LinkKey{LocalExit}
	if PolicyDigest(policy) == hex.EncodeToString(sum[:]) {
		t.Fatal("Exits does not take part in the digest")
	}
}

func TestRoutesRoundTrip(t *testing.T) {
	transit := routedTransit()
	wire, err := json.Marshal(transit)
	if err != nil {
		t.Fatal(err)
	}
	var back Transit
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(back)
	if string(again) != string(wire) {
		t.Fatalf("round trip changed the bytes:\n%s\n%s", wire, again)
	}
	if err := ValidateTransit(&back); err != nil {
		t.Fatal(err)
	}
}

func TestLocalExitIsNotALinkKey(t *testing.T) {
	if _, err := LocalExit.RowID(); err == nil {
		t.Fatal("local parsed as a link key")
	}
	// Everywhere a link key is validated keeps refusing it.
	if err := ValidateTransit(&Transit{LinksOut: []LinkOut{func() LinkOut { l := ssLinkOut(1); l.Key = LocalExit; return l }()}}); err == nil {
		t.Fatal("a link out keyed local was accepted")
	}
	if err := ValidateTransit(&Transit{LinksIn: []LinkIn{func() LinkIn { l := ssLinkIn(1, 30001); l.Key = LocalExit; return l }()}}); err == nil {
		t.Fatal("a link in keyed local was accepted")
	}
	if err := ValidateTransit(&Transit{LinksOut: []LinkOut{ssLinkOut(3)}, Egress: []EgressBinding{{Listener: NewListenerKey(1), Link: LocalExit}}}); err == nil {
		t.Fatal("an egress binding to local was accepted")
	}
	observation := auditObservation()
	observation.Hits[0].Egress = LocalExit
	if err := ValidateAuditObservation(observation); err == nil {
		t.Fatal("an audit hit egress of local was accepted")
	}
}

func TestValidateRoutes(t *testing.T) {
	if err := ValidateTransit(routedTransit()); err != nil {
		t.Fatalf("valid routes rejected: %v", err)
	}
	rules := func(t *Transit) *[]RouteRule { return &t.Routes[0].Rules }
	cases := []struct {
		name   string
		mutate func(*Transit)
		want   string // "" = valid
	}{
		{"a route to local with no links at all", func(t *Transit) {
			*t = Transit{Routes: []ListenerRoutes{{Listener: NewListenerKey(1), Rules: []RouteRule{{ID: "r1", Ports: "25", Exit: LocalExit}}}}}
		}, ""},
		{"rule id r10", func(t *Transit) { (*rules(t))[0].ID = "r10" }, ""},
		{"full and keyword and domain together", func(t *Transit) {
			(*rules(t))[0].Domains = []string{"domain:a.com", "full:b.com", "keyword:c"}
		}, ""},
		{"ports and network alone", func(t *Transit) {
			(*rules(t))[0] = RouteRule{ID: "r1", Ports: "1-1024", Network: "udp", Exit: NewLinkKey(4)}
		}, ""},
		{"private is not a route field, a cidr list is enough", func(t *Transit) { (*rules(t))[1].CIDRs = []string{"::/0"} }, ""},
		{"rule id without r", func(t *Transit) { (*rules(t))[0].ID = "p1" }, "id must match"},
		{"rule id r0", func(t *Transit) { (*rules(t))[0].ID = "r0" }, "id must match"},
		{"rule id with a leading zero", func(t *Transit) { (*rules(t))[0].ID = "r01" }, "id must match"},
		{"rule id with a suffix", func(t *Transit) { (*rules(t))[0].ID = "r1x1" }, "id must match"},
		{"rule id empty", func(t *Transit) { (*rules(t))[0].ID = "" }, "id must match"},
		{"duplicate rule id", func(t *Transit) { (*rules(t))[1].ID = "r1" }, "duplicate rule id"},
		{"a regexp domain", func(t *Transit) { (*rules(t))[0].Domains = []string{`regexp:^a\.com$`} }, "domain:, full: and keyword: only"},
		{"a domain without a prefix", func(t *Transit) { (*rules(t))[0].Domains = []string{"example.com"} }, "prefix"},
		{"unsorted domains", func(t *Transit) { (*rules(t))[0].Domains = []string{"domain:b.com", "domain:a.com"} }, "sorted"},
		{"duplicate domains", func(t *Transit) { (*rules(t))[0].Domains = []string{"domain:a.com", "domain:a.com"} }, "sorted"},
		{"an uppercase domain", func(t *Transit) { (*rules(t))[0].Domains = []string{"domain:A.com"} }, "lowercase"},
		{"a non-canonical cidr", func(t *Transit) { (*rules(t))[1].CIDRs = []string{"10.1.0.0/8"} }, "not canonical"},
		{"an ipv4-mapped cidr", func(t *Transit) { (*rules(t))[1].CIDRs = []string{"::ffff:10.0.0.0/104"} }, "IPv4-mapped"},
		{"unsorted cidrs", func(t *Transit) { (*rules(t))[1].CIDRs = []string{"192.168.0.0/16", "10.0.0.0/8"} }, "sorted"},
		{"ports that run backwards", func(t *Transit) { (*rules(t))[1].Ports = "9-1" }, "backwards"},
		{"ports that are not canonical", func(t *Transit) { (*rules(t))[1].Ports = "080" }, "port"},
		{"network icmp", func(t *Transit) { (*rules(t))[1].Network = "icmp" }, "network"},
		{"network tcp,udp is a forward network, not a route one", func(t *Transit) { (*rules(t))[1].Network = "tcp,udp" }, "network"},
		{"a rule that matches nothing", func(t *Transit) { (*rules(t))[1] = RouteRule{ID: "r2", Exit: LocalExit} }, "match on something"},
		{"no exit", func(t *Transit) { (*rules(t))[0].Exit = "" }, "exit"},
		{"exit is a link in", func(t *Transit) {
			t.LinksIn = []LinkIn{ssLinkIn(9, 30009)}
			(*rules(t))[0].Exit = NewLinkKey(9)
		}, "outgoing links"},
		{"exit is an unknown link", func(t *Transit) { (*rules(t))[0].Exit = NewLinkKey(99) }, "outgoing links"},
		{"exit is a listener key", func(t *Transit) { (*rules(t))[0].Exit = "lst_1" }, "outgoing links"},
		{"exit is LOCAL", func(t *Transit) { (*rules(t))[0].Exit = "LOCAL" }, "outgoing links"},
		{"listener is a link key", func(t *Transit) { t.Routes[0].Listener = "lnk_1" }, "listener"},
		{"listener appears twice", func(t *Transit) { t.Routes = append(t.Routes, t.Routes[0]) }, "two route lists"},
		{"a listener with no rules", func(t *Transit) { t.Routes = append(t.Routes, ListenerRoutes{Listener: NewListenerKey(2)}) }, "no rules"},
		{"a listener with an empty rule list", func(t *Transit) {
			t.Routes = append(t.Routes, ListenerRoutes{Listener: NewListenerKey(2), Rules: []RouteRule{}})
		}, "no rules"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transit := routedTransit()
			tc.mutate(transit)
			err := ValidateTransit(transit)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case tc.want != "" && err == nil:
				t.Fatal("accepted")
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestValidateRouteLimits(t *testing.T) {
	ruleList := func(n int) []RouteRule {
		list := make([]RouteRule, n)
		for i := range list {
			list[i] = RouteRule{ID: "r" + strconv.Itoa(i+1), Ports: "25", Exit: LocalExit}
		}
		return list
	}
	if err := ValidateTransit(&Transit{Routes: []ListenerRoutes{{Listener: NewListenerKey(1), Rules: ruleList(MaxRouteRulesPerListener)}}}); err != nil {
		t.Fatalf("a full listener rejected: %v", err)
	}
	if err := ValidateTransit(&Transit{Routes: []ListenerRoutes{{Listener: NewListenerKey(1), Rules: ruleList(MaxRouteRulesPerListener + 1)}}}); err == nil {
		t.Fatal("65 rules on one listener accepted")
	}
	var all []ListenerRoutes
	for i := 0; i < MaxRouteRules/MaxRouteRulesPerListener; i++ {
		all = append(all, ListenerRoutes{Listener: NewListenerKey(int64(i + 1)), Rules: ruleList(MaxRouteRulesPerListener)})
	}
	if err := ValidateTransit(&Transit{Routes: all}); err != nil {
		t.Fatalf("1024 rules in total rejected: %v", err)
	}
	all = append(all, ListenerRoutes{Listener: NewListenerKey(1000), Rules: ruleList(1)})
	if err := ValidateTransit(&Transit{Routes: all}); err == nil {
		t.Fatal("1025 rules in total accepted")
	}
}

func TestValidateExits(t *testing.T) {
	rule := func(mutate func(*DestinationRule)) *DestinationPolicy {
		r := DestinationRule{ID: "p1", Action: RuleBlock, Ports: "25"}
		mutate(&r)
		return &DestinationPolicy{Rules: []DestinationRule{r}}
	}
	cases := []struct {
		name   string
		mutate func(*DestinationRule)
		valid  bool
	}{
		{"no exits", func(r *DestinationRule) {}, true},
		{"local alone", func(r *DestinationRule) { r.Exits = []LinkKey{LocalExit} }, true},
		{"links then local, sorted", func(r *DestinationRule) { r.Exits = []LinkKey{"lnk_3", "lnk_4", LocalExit} }, true},
		{"exits on an allow rule", func(r *DestinationRule) { r.Action = RuleAllow; r.Exits = []LinkKey{"lnk_3"} }, true},
		{"exits with nothing else on a catch-all group rule", func(r *DestinationRule) {
			*r = DestinationRule{ID: "g1", Action: RuleBlock, CatchAll: true, Subjects: []SubjectKey{"usr_1"}, Exits: []LinkKey{LocalExit}}
		}, true},
		{"unsorted", func(r *DestinationRule) { r.Exits = []LinkKey{LocalExit, "lnk_3"} }, false},
		{"duplicate", func(r *DestinationRule) { r.Exits = []LinkKey{"lnk_3", "lnk_3"} }, false},
		{"a listener key", func(r *DestinationRule) { r.Exits = []LinkKey{"lst_1"} }, false},
		{"a non-canonical link key", func(r *DestinationRule) { r.Exits = []LinkKey{"lnk_03"} }, false},
		{"upper case local", func(r *DestinationRule) { r.Exits = []LinkKey{"Local"} }, false},
		{"empty element", func(r *DestinationRule) { r.Exits = []LinkKey{""} }, false},
		{"exits alone do not make a match", func(r *DestinationRule) {
			*r = DestinationRule{ID: "p1", Action: RuleBlock, Exits: []LinkKey{LocalExit}}
		}, false},
		{"exits on a source rule", func(r *DestinationRule) {
			*r = DestinationRule{ID: "s1", Action: RuleBlock, SourceCIDRs: []string{"203.0.113.0/24"}, Exits: []LinkKey{LocalExit}}
		}, false},
		{"too many exits", func(r *DestinationRule) {
			for i := 1; i <= MaxLinks+1; i++ {
				r.Exits = append(r.Exits, NewLinkKey(int64(i)))
			}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDestinationPolicy(rule(tc.mutate))
			if tc.valid && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestMatchRoute(t *testing.T) {
	transit := *routedTransit()
	lst1, lst2 := NewListenerKey(1), NewListenerKey(2)
	cases := []struct {
		name     string
		listener ListenerKey
		in       MatchInput
		want     LinkKey
	}{
		{"first rule by domain suffix", lst1, MatchInput{Target: "www.netflix.com"}, "lnk_4"},
		{"first rule by keyword", lst1, MatchInput{Target: "cdn.nflxvideo.net"}, "lnk_4"},
		{"a domain is not a mid-label suffix", lst1, MatchInput{Target: "notnetflix.com", Port: 80, Network: "tcp"}, "lnk_3"},
		{"second rule: cidr, port and network", lst1, MatchInput{Target: "10.1.2.3", Port: 443, Network: "tcp"}, LocalExit},
		{"second rule misses on the port", lst1, MatchInput{Target: "10.1.2.3", Port: 80, Network: "tcp"}, "lnk_3"},
		{"second rule misses on the network", lst1, MatchInput{Target: "10.1.2.3", Port: 443, Network: "udp"}, "lnk_3"},
		{"an ipv4-mapped address is its ipv4 address", lst1, MatchInput{Target: "::ffff:10.1.2.3", Port: 443, Network: "TCP"}, LocalExit},
		{"as_is: a hostname never matches cidrs, whatever it resolves to", lst1, MatchInput{Target: "intranet.example", Port: 443, Network: "tcp", Resolved: []string{"10.1.2.3"}}, "lnk_3"},
		{"an uppercase host is lowercased", lst1, MatchInput{Target: "WWW.NETFLIX.COM"}, "lnk_4"},
		{"a trailing dot is not normalised", lst1, MatchInput{Target: "www.netflix.com."}, "lnk_3"},
		{"no rule: the egress binding", lst1, MatchInput{Target: "example.org", Port: 80, Network: "tcp"}, "lnk_3"},
		{"a listener with no routes and no binding leaves locally", lst2, MatchInput{Target: "www.netflix.com"}, LocalExit},
		{"an unknown listener leaves locally", "", MatchInput{Target: "www.netflix.com"}, LocalExit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, known := MatchRoute(transit, tc.listener, tc.in, ResolveAsIs)
			if got != tc.want || !known {
				t.Fatalf("exit = %q known=%v, want %q known", got, known, tc.want)
			}
		})
	}
	// Rule order decides: both rules hit, the earlier one wins.
	ordered := Transit{LinksOut: []LinkOut{ssLinkOut(3)}, Routes: []ListenerRoutes{{Listener: lst1, Rules: []RouteRule{
		{ID: "r2", Domains: []string{"domain:example.com"}, Exit: "lnk_3"},
		{ID: "r1", Domains: []string{"keyword:example"}, Exit: LocalExit},
	}}}}
	if got, _ := MatchRoute(ordered, lst1, MatchInput{Target: "a.example.com"}, ResolveAsIs); got != "lnk_3" {
		t.Fatalf("rule order ignored: %q", got)
	}
	if got, _ := MatchRoute(ordered, lst1, MatchInput{Target: "example.net"}, ResolveAsIs); got != LocalExit {
		t.Fatalf("second rule not reached: %q", got)
	}
}

func TestPolicyRuleExitsInMatchDestination(t *testing.T) {
	policy := &DestinationPolicy{Rules: []DestinationRule{
		{ID: "p1", Action: RuleBlock, Domains: []string{"domain:example.com"}, Exits: []LinkKey{"lnk_4", LocalExit}},
		{ID: "p2", Action: RuleObserve, Domains: []string{"domain:example.com"}},
	}}
	if err := ValidateDestinationPolicy(policy); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		exit       LinkKey
		verdict    MatchVerdict
		terminated string
		cond       bool
	}{
		{"exit in the set", "lnk_4", MatchBlock, "p1", false},
		{"local in the set", LocalExit, MatchBlock, "p1", false},
		{"exit outside the set falls to the next rule", "lnk_3", MatchObserve, "p2", false},
		{"unknown exit is untestable", "", MatchObserve, "p2", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchDestination(policy, MatchInput{Target: "example.com", Exit: tc.exit})
			if got.Verdict != tc.verdict || got.Terminated != tc.terminated || got.Conditional != tc.cond {
				t.Fatalf("got %s %q conditional=%v: %+v", got.Verdict, got.Terminated, got.Conditional, got.Steps)
			}
		})
	}
}

func TestMatchRouted(t *testing.T) {
	transit := *routedTransit()
	policy := &DestinationPolicy{Rules: []DestinationRule{
		{ID: "p1", Action: RuleBlock, Domains: []string{"domain:netflix.com"}, Exits: []LinkKey{"lnk_3"}},
	}}
	lst1 := NewListenerKey(1)
	// Netflix is routed out lnk_4, so a rule scoped to the default exit lnk_3
	// must not see it.
	result, exit := MatchRouted(policy, transit, MatchInput{Inbound: lst1, Target: "www.netflix.com"})
	if exit != "lnk_4" || result.Verdict != MatchDefault {
		t.Fatalf("exit=%q verdict=%s", exit, result.Verdict)
	}
	result, exit = MatchRouted(policy, transit, MatchInput{Inbound: lst1, Target: "www.netflix.com", Exit: "lnk_3"})
	if exit != "lnk_3" || result.Verdict != MatchBlock {
		t.Fatalf("an explicit exit was overridden: exit=%q verdict=%s", exit, result.Verdict)
	}
	result, exit = MatchRouted(policy, transit, MatchInput{Target: "www.netflix.com"})
	if exit != "" || result.Verdict != MatchDefault || !result.Conditional {
		t.Fatalf("with no inbound the exit must stay unknown: exit=%q %+v", exit, result)
	}
}

// A route rule that depends on something the input leaves unknown makes the
// choice conditional: the connection might have taken that rule.
func TestMatchRouteIsConditionalOnUnknownInput(t *testing.T) {
	lst1 := NewListenerKey(1)
	transit := Transit{LinksOut: []LinkOut{ssLinkOut(4)}, Routes: []ListenerRoutes{{Listener: lst1, Rules: []RouteRule{
		{ID: "r1", Ports: "443", Exit: "lnk_4"},
		{ID: "r2", Domains: []string{"domain:example.com"}, Exit: LocalExit},
	}}}}
	// Unknown port, earlier rule: the later hit is only a guess.
	exit, known := MatchRoute(transit, lst1, MatchInput{Target: "a.example.com"}, ResolveAsIs)
	if exit != LocalExit || known {
		t.Fatalf("exit=%q known=%v, want local and unknown", exit, known)
	}
	// A definite miss on a known port is skipped with certainty.
	if exit, known = MatchRoute(transit, lst1, MatchInput{Target: "a.example.com", Port: 80}, ResolveAsIs); exit != LocalExit || !known {
		t.Fatalf("exit=%q known=%v", exit, known)
	}
	// The default is conditional too when a rule could still have hit.
	if exit, known = MatchRoute(transit, lst1, MatchInput{Target: "other.org"}, ResolveAsIs); exit != LocalExit || known {
		t.Fatalf("default: exit=%q known=%v", exit, known)
	}
}

func TestMatchRoutedDoesNotGuessTheExit(t *testing.T) {
	lst1 := NewListenerKey(1)
	transit := Transit{LinksOut: []LinkOut{ssLinkOut(4)}, Routes: []ListenerRoutes{{Listener: lst1, Rules: []RouteRule{
		{ID: "r1", Ports: "443", Exit: "lnk_4"},
	}}}}
	policy := &DestinationPolicy{Rules: []DestinationRule{
		{ID: "p1", Action: RuleBlock, CIDRs: []string{"10.0.0.0/8"}, Exits: []LinkKey{LocalExit}},
	}}
	result, exit := MatchRouted(policy, transit, MatchInput{Inbound: lst1, Target: "10.1.1.1"})
	if exit != "" || result.Verdict == MatchBlock || !result.Conditional {
		t.Fatalf("a guessed exit gave a confident verdict: exit=%q %+v", exit, result)
	}
	// With the port known the route is certain and the block applies.
	result, exit = MatchRouted(policy, transit, MatchInput{Inbound: lst1, Target: "10.1.1.1", Port: 80})
	if exit != LocalExit || result.Verdict != MatchBlock || result.Conditional {
		t.Fatalf("exit=%q %+v", exit, result)
	}
}

// Under on_demand the router resolves a hostname for a route rule's CIDRs, as
// it does for a policy rule's.
func TestMatchRouteOnDemand(t *testing.T) {
	lst1 := NewListenerKey(1)
	transit := Transit{LinksOut: []LinkOut{ssLinkOut(4)}, Routes: []ListenerRoutes{{Listener: lst1, Rules: []RouteRule{
		{ID: "r1", CIDRs: []string{"10.0.0.0/8"}, Exit: "lnk_4"},
	}}}}
	host := MatchInput{Target: "intranet.corp"}
	if exit, known := MatchRoute(transit, lst1, host, ResolveAsIs); exit != LocalExit || !known {
		t.Fatalf("as_is: exit=%q known=%v", exit, known)
	}
	if _, known := MatchRoute(transit, lst1, host, ResolveOnDemand); known {
		t.Fatal("on_demand without resolved addresses must be conditional")
	}
	host.Resolved = []string{"10.1.2.3"}
	if exit, known := MatchRoute(transit, lst1, host, ResolveOnDemand); exit != "lnk_4" || !known {
		t.Fatalf("on_demand resolved into the cidr: exit=%q known=%v", exit, known)
	}
	host.Resolved = []string{"8.8.8.8"}
	if exit, known := MatchRoute(transit, lst1, host, ResolveOnDemand); exit != LocalExit || !known {
		t.Fatalf("on_demand resolved elsewhere: exit=%q known=%v", exit, known)
	}
	host.Resolved = []string{"10.1.2.3"}
	if exit, _ := MatchRoute(transit, lst1, host, ResolveAsIs); exit != LocalExit {
		t.Fatalf("as_is must ignore Resolved: %q", exit)
	}
}
