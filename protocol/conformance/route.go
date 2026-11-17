package conformance

import "github.com/KazuhaHub/passwall-protocol/protocol"

// RouteVector is one serialised value of the routing surface and whether it is
// acceptable. Two tables use it:
//
//   - RouteTransitVectors: a protocol.Transit, held to ValidateTransit.
//   - RouteExitsVectors: a protocol.DestinationPolicy, held to
//     ValidateDestinationPolicy, for DestinationRule.Exits.
//
// The subject is the raw JSON for the reason ProbeVector gives: a type error
// must cost a peer what a validation error does. The expected values are
// written from the rules, not copied from the code; append, never edit a
// verdict to make an implementation pass.
type RouteVector = ProbeVector

const (
	routeLinks = `"links_out":[` +
		`{"key":"lnk_3","address":"exit.example.com","port":30001,"protocol":"ss2022","ss":{"method":"2022-blake3-aes-128-gcm","password":"glwKkLUrNxQ4VbjbZG4svg=="}}` +
		`]`
	routeEgress = `"egress":[{"listener":"lst_1","link":"lnk_3"}]`
)

func routes(rules string) string {
	return `{` + routeLinks + `,` + routeEgress + `,"routes":[{"listener":"lst_1","rules":[` + rules + `]}]}`
}

// RouteTransitVectors is the shared table for Transit.Routes.
var RouteTransitVectors = []RouteVector{
	{Name: "domain rule to a link", Valid: true, JSON: routes(`{"id":"r1","domains":["domain:netflix.com","full:a.example","keyword:nflx"],"exit":"lnk_3"}`)},
	{Name: "rule to local", Valid: true, JSON: routes(`{"id":"r1","cidrs":["10.0.0.0/8"],"exit":"local"}`)},
	{Name: "ports and network alone", Valid: true, JSON: routes(`{"id":"r1","ports":"25,465,587","network":"tcp","exit":"local"}`)},
	{Name: "rule ids need not ascend", Valid: true,
		JSON: routes(`{"id":"r2","ports":"25","exit":"local"},{"id":"r1","ports":"26","exit":"lnk_3"}`)},
	{Name: "routes to local with no links at all", Valid: true,
		JSON: `{"routes":[{"listener":"lst_1","rules":[{"id":"r1","ports":"25","exit":"local"}]}]}`},
	{Name: "two listeners", Valid: true,
		JSON: `{"routes":[{"listener":"lst_1","rules":[{"id":"r1","ports":"25","exit":"local"}]},{"listener":"lst_2","rules":[{"id":"r1","ports":"25","exit":"local"}]}]}`},
	{Name: "regexp domain", Valid: false, JSON: routes(`{"id":"r1","domains":["regexp:^a$"],"exit":"lnk_3"}`)},
	{Name: "domain without a prefix", Valid: false, JSON: routes(`{"id":"r1","domains":["netflix.com"],"exit":"lnk_3"}`)},
	{Name: "domains out of order", Valid: false, JSON: routes(`{"id":"r1","domains":["domain:b.com","domain:a.com"],"exit":"lnk_3"}`)},
	{Name: "non-canonical cidr", Valid: false, JSON: routes(`{"id":"r1","cidrs":["10.1.0.0/8"],"exit":"lnk_3"}`)},
	{Name: "ports that run backwards", Valid: false, JSON: routes(`{"id":"r1","ports":"9-1","exit":"lnk_3"}`)},
	{Name: "network tcp,udp", Valid: false, JSON: routes(`{"id":"r1","ports":"25","network":"tcp,udp","exit":"lnk_3"}`)},
	{Name: "rule that matches nothing", Valid: false, JSON: routes(`{"id":"r1","exit":"lnk_3"}`)},
	{Name: "rule id r0", Valid: false, JSON: routes(`{"id":"r0","ports":"25","exit":"lnk_3"}`)},
	{Name: "rule id with a leading zero", Valid: false, JSON: routes(`{"id":"r01","ports":"25","exit":"lnk_3"}`)},
	{Name: "rule id of a policy rule", Valid: false, JSON: routes(`{"id":"p1","ports":"25","exit":"lnk_3"}`)},
	{Name: "duplicate rule id", Valid: false, JSON: routes(`{"id":"r1","ports":"25","exit":"local"},{"id":"r1","ports":"26","exit":"local"}`)},
	{Name: "exit is not one of the outgoing links", Valid: false, JSON: routes(`{"id":"r1","ports":"25","exit":"lnk_4"}`)},
	{Name: "exit is a listener", Valid: false, JSON: routes(`{"id":"r1","ports":"25","exit":"lst_1"}`)},
	{Name: "exit omitted", Valid: false, JSON: routes(`{"id":"r1","ports":"25"}`)},
	{Name: "exit written in capitals", Valid: false, JSON: routes(`{"id":"r1","ports":"25","exit":"LOCAL"}`)},
	{Name: "listener appears twice", Valid: false,
		JSON: `{"routes":[{"listener":"lst_1","rules":[{"id":"r1","ports":"25","exit":"local"}]},{"listener":"lst_1","rules":[{"id":"r2","ports":"26","exit":"local"}]}]}`},
	{Name: "listener is a link key", Valid: false,
		JSON: `{"routes":[{"listener":"lnk_1","rules":[{"id":"r1","ports":"25","exit":"local"}]}]}`},
	{Name: "listener with no rules", Valid: false, JSON: `{"routes":[{"listener":"lst_1","rules":[]}]}`},
	{Name: "egress binding to local", Valid: false,
		JSON: `{` + routeLinks + `,"egress":[{"listener":"lst_1","link":"local"}]}`},
	{Name: "link keyed local", Valid: false,
		JSON: `{"links_out":[{"key":"local","address":"exit.example.com","port":30001,"protocol":"ss2022","ss":{"method":"2022-blake3-aes-128-gcm","password":"glwKkLUrNxQ4VbjbZG4svg=="}}]}`},
}

func exitsPolicy(exits string) string {
	return `{"rules":[{"id":"p1","action":"block","ports":"25","exits":` + exits + `}]}`
}

// RouteExitsVectors is the shared table for DestinationRule.Exits.
var RouteExitsVectors = []RouteVector{
	{Name: "local", Valid: true, JSON: exitsPolicy(`["local"]`)},
	{Name: "links then local, sorted as text", Valid: true, JSON: exitsPolicy(`["lnk_10","lnk_3","local"]`)},
	{Name: "no exits", Valid: true, JSON: `{"rules":[{"id":"p1","action":"block","ports":"25"}]}`},
	{Name: "empty exits list", Valid: true, JSON: exitsPolicy(`[]`)},
	{Name: "local before a link", Valid: false, JSON: exitsPolicy(`["local","lnk_3"]`)},
	{Name: "duplicate exit", Valid: false, JSON: exitsPolicy(`["lnk_3","lnk_3"]`)},
	{Name: "a listener key", Valid: false, JSON: exitsPolicy(`["lst_1"]`)},
	{Name: "non-canonical link key", Valid: false, JSON: exitsPolicy(`["lnk_03"]`)},
	{Name: "local in capitals", Valid: false, JSON: exitsPolicy(`["Local"]`)},
	{Name: "an empty exit", Valid: false, JSON: exitsPolicy(`[""]`)},
	{Name: "exits on a source rule", Valid: false,
		JSON: `{"rules":[{"id":"s1","action":"block","source_cidrs":["203.0.113.0/24"],"exits":["local"]}]}`},
	{Name: "exits are not a match", Valid: false, JSON: `{"rules":[{"id":"p1","action":"block","exits":["local"]}]}`},
}

// RouteMatchVector is one MatchRoute case.
type RouteMatchVector struct {
	Name     string
	Transit  protocol.Transit
	Listener protocol.ListenerKey
	Input    protocol.MatchInput
	// Resolve is the destination policy's Resolve mode.
	Resolve protocol.ResolveMode
	Exit    protocol.LinkKey
	// Conditional is MatchRoute's known == false: a rule that could have hit
	// depends on input the vector leaves unknown. Exit is then the best guess.
	Conditional bool
}

func linkOut(id int64) protocol.LinkOut {
	return protocol.LinkOut{Key: protocol.NewLinkKey(id), Address: "exit.example.com", Port: 30001, Protocol: protocol.LinkProtocolSS2022,
		SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: "glwKkLUrNxQ4VbjbZG4svg=="}}
}

var routeTransit = protocol.Transit{
	LinksOut: []protocol.LinkOut{linkOut(3), linkOut(4)},
	Egress:   []protocol.EgressBinding{{Listener: lst1, Link: "lnk_3"}},
	Routes: []protocol.ListenerRoutes{
		{Listener: lst1, Rules: []protocol.RouteRule{
			{ID: "r1", Domains: []string{"domain:netflix.com", "keyword:nflx"}, Exit: "lnk_4"},
			{ID: "r2", CIDRs: []string{"10.0.0.0/8"}, Ports: "443", Network: "tcp", Exit: protocol.LocalExit},
			{ID: "r3", Domains: []string{"domain:example.com"}, Exit: "lnk_3"},
			{ID: "r4", Domains: []string{"keyword:example"}, Exit: protocol.LocalExit},
		}},
	},
}

// RouteMatchVectors cover MatchRoute: first match wins, the default is the
// egress binding or local, and unknown input never satisfies a rule.
var RouteMatchVectors = []RouteMatchVector{
	{Name: "domain suffix", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "www.netflix.com"}, Exit: "lnk_4"},
	{Name: "keyword", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "cdn.nflxvideo.net"}, Exit: "lnk_4"},
	{Name: "first rule wins over a later one", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "a.example.com"}, Exit: "lnk_3"},
	{Name: "later rule when the first misses", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "example.net"}, Exit: protocol.LocalExit},
	{Name: "cidr, port and network together", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "10.1.2.3", Port: 443, Network: "tcp"}, Exit: protocol.LocalExit},
	{Name: "port mismatch falls to the default", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "10.1.2.3", Port: 80, Network: "tcp"}, Exit: "lnk_3"},
	{Name: "unknown port makes a ports rule untestable, so the choice is conditional", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "10.1.2.3", Network: "tcp"}, Exit: "lnk_3", Conditional: true},
	{Name: "unknown network makes a network rule untestable, so the choice is conditional", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "10.1.2.3", Port: 443}, Exit: "lnk_3", Conditional: true},
	{Name: "ipv4-mapped address is its ipv4 address", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "::ffff:10.1.2.3", Port: 443, Network: "tcp"}, Exit: protocol.LocalExit},
	{Name: "as_is: a hostname never matches cidrs", Transit: routeTransit, Listener: lst1,
		Input: protocol.MatchInput{Target: "intranet.corp", Port: 443, Network: "tcp", Resolved: []string{"10.1.2.3"}}, Exit: "lnk_3"},
	{Name: "on_demand: a hostname that resolves into the cidr takes the rule", Transit: routeTransit, Listener: lst1, Resolve: protocol.ResolveOnDemand,
		Input: protocol.MatchInput{Target: "intranet.corp", Port: 443, Network: "tcp", Resolved: []string{"10.1.2.3"}}, Exit: protocol.LocalExit},
	{Name: "on_demand: a hostname without resolved addresses makes the choice conditional", Transit: routeTransit, Listener: lst1, Resolve: protocol.ResolveOnDemand,
		Input: protocol.MatchInput{Target: "intranet.corp", Port: 443, Network: "tcp"}, Exit: "lnk_3", Conditional: true},
	{Name: "on_demand: a hostname resolved elsewhere misses the cidr rule", Transit: routeTransit, Listener: lst1, Resolve: protocol.ResolveOnDemand,
		Input: protocol.MatchInput{Target: "intranet.corp", Port: 443, Network: "tcp", Resolved: []string{"8.8.8.8"}}, Exit: "lnk_3"},
	{Name: "uppercase host is lowercased", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "WWW.NETFLIX.COM"}, Exit: "lnk_4"},
	{Name: "trailing dot is not normalised", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "www.netflix.com."}, Exit: "lnk_3"},
	{Name: "default is the egress binding", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "other.org"}, Exit: "lnk_3"},
	{Name: "listener without routes or binding leaves locally", Transit: routeTransit, Listener: lst2, Input: protocol.MatchInput{Target: "www.netflix.com"}, Exit: protocol.LocalExit},
	{Name: "a route to local overrides the binding", Transit: routeTransit, Listener: lst1, Input: protocol.MatchInput{Target: "foo.example"}, Exit: protocol.LocalExit},
}

// IntersectVector is one IntersectDestinations case. When Exact is false, Want
// is the over-approximation the function must return.
type IntersectVector struct {
	Name  string
	A, B  protocol.DestinationMatcher
	Want  protocol.DestinationMatcher
	Exact bool
}

var never = protocol.DestinationMatcher{Never: true}

// IntersectVectors pin the conjunction the Xray compiler builds.
var IntersectVectors = []IntersectVector{
	{Name: "domain nests in domain",
		A: protocol.DestinationMatcher{Domains: []string{"domain:a.com"}}, B: protocol.DestinationMatcher{Domains: []string{"domain:www.a.com"}},
		Want: protocol.DestinationMatcher{Domains: []string{"domain:www.a.com"}}, Exact: true},
	{Name: "domain is not a mid-label suffix",
		A: protocol.DestinationMatcher{Domains: []string{"domain:a.com"}}, B: protocol.DestinationMatcher{Domains: []string{"domain:ba.com"}}, Want: never, Exact: true},
	{Name: "full against domain",
		A: protocol.DestinationMatcher{Domains: []string{"domain:a.com"}}, B: protocol.DestinationMatcher{Domains: []string{"full:x.a.com", "full:b.com"}},
		Want: protocol.DestinationMatcher{Domains: []string{"full:x.a.com"}}, Exact: true},
	{Name: "keyword against a full",
		A: protocol.DestinationMatcher{Domains: []string{"keyword:nflx"}}, B: protocol.DestinationMatcher{Domains: []string{"full:a.nflx.com", "full:a.com"}},
		Want: protocol.DestinationMatcher{Domains: []string{"full:a.nflx.com"}}, Exact: true},
	{Name: "keyword against a domain that holds it",
		A: protocol.DestinationMatcher{Domains: []string{"keyword:nflx"}}, B: protocol.DestinationMatcher{Domains: []string{"domain:nflx.com"}},
		Want: protocol.DestinationMatcher{Domains: []string{"domain:nflx.com"}}, Exact: true},
	{Name: "keyword against two keywords, one inside the other",
		A: protocol.DestinationMatcher{Domains: []string{"keyword:nflx"}}, B: protocol.DestinationMatcher{Domains: []string{"keyword:nflxv"}},
		Want: protocol.DestinationMatcher{Domains: []string{"keyword:nflxv"}}, Exact: true},
	{Name: "unrelated keywords are inexact and keep the longer",
		A: protocol.DestinationMatcher{Domains: []string{"keyword:ab"}}, B: protocol.DestinationMatcher{Domains: []string{"keyword:cde"}},
		Want: protocol.DestinationMatcher{Domains: []string{"keyword:cde"}}, Exact: false},
	{Name: "a regexp against a domain is inexact and keeps the domain",
		A: protocol.DestinationMatcher{Domains: []string{`regexp:^a`}}, B: protocol.DestinationMatcher{Domains: []string{"domain:a.com"}},
		Want: protocol.DestinationMatcher{Domains: []string{"domain:a.com"}}, Exact: false},
	{Name: "a regexp against a full is evaluated on the host",
		A: protocol.DestinationMatcher{Domains: []string{`regexp:^a`}}, B: protocol.DestinationMatcher{Domains: []string{"full:a.com", "full:b.com"}},
		Want: protocol.DestinationMatcher{Domains: []string{"full:a.com"}}, Exact: true},
	{Name: "cidr nests in cidr",
		A: protocol.DestinationMatcher{CIDRs: []string{"10.0.0.0/8"}}, B: protocol.DestinationMatcher{CIDRs: []string{"10.1.0.0/16"}},
		Want: protocol.DestinationMatcher{CIDRs: []string{"10.1.0.0/16"}}, Exact: true},
	{Name: "private against private",
		A: protocol.DestinationMatcher{Private: true}, B: protocol.DestinationMatcher{Private: true}, Want: protocol.DestinationMatcher{Private: true}, Exact: true},
	{Name: "private against a cidr inside the table",
		A: protocol.DestinationMatcher{Private: true}, B: protocol.DestinationMatcher{CIDRs: []string{"10.1.0.0/16"}},
		Want: protocol.DestinationMatcher{CIDRs: []string{"10.1.0.0/16"}}, Exact: true},
	{Name: "a hostname matcher against an address matcher is empty",
		A: protocol.DestinationMatcher{Domains: []string{"domain:a.com"}}, B: protocol.DestinationMatcher{CIDRs: []string{"10.0.0.0/8"}}, Want: never, Exact: true},
	{Name: "ports and network",
		A: protocol.DestinationMatcher{Ports: "80,443,8000-9000", Network: "tcp"}, B: protocol.DestinationMatcher{Ports: "1-100,8500-10000"},
		Want: protocol.DestinationMatcher{Ports: "80,8500-9000", Network: "tcp"}, Exact: true},
	{Name: "tcp against udp", A: protocol.DestinationMatcher{Network: "tcp"}, B: protocol.DestinationMatcher{Network: "udp"}, Want: never, Exact: true},
	{Name: "no destination constraint is the identity",
		A: protocol.DestinationMatcher{Ports: "25"}, B: protocol.DestinationMatcher{Domains: []string{"domain:a.com"}},
		Want: protocol.DestinationMatcher{Domains: []string{"domain:a.com"}, Ports: "25"}, Exact: true},
	{Name: "on_demand cidr against a domain keeps the domain",
		A: protocol.DestinationMatcher{CIDRs: []string{"10.0.0.0/8"}, OnDemand: true}, B: protocol.DestinationMatcher{Domains: []string{"domain:a.com"}},
		Want: protocol.DestinationMatcher{Domains: []string{"domain:a.com"}}, Exact: false},
}
