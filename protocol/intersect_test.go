package protocol

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
)

func TestIntersectDestinationsVectors(t *testing.T) {
	m := func(domains []string, cidrs []string, ports, network string) DestinationMatcher {
		return DestinationMatcher{Domains: domains, CIDRs: cidrs, Ports: ports, Network: network}
	}
	d := func(entries ...string) []string { return entries }
	cases := []struct {
		name  string
		a, b  DestinationMatcher
		want  DestinationMatcher
		exact bool
	}{
		{"nothing against nothing", DestinationMatcher{}, DestinationMatcher{}, DestinationMatcher{}, true},
		{"unconstrained is the identity", DestinationMatcher{}, m(d("domain:a.com"), nil, "80", "tcp"), m(d("domain:a.com"), nil, "80", "tcp"), true},
		{"domain nests in domain", m(d("domain:a.com"), nil, "", ""), m(d("domain:www.a.com"), nil, "", ""), m(d("domain:www.a.com"), nil, "", ""), true},
		{"domain against a sibling domain", m(d("domain:a.com"), nil, "", ""), m(d("domain:b.com"), nil, "", ""), DestinationMatcher{Never: true}, true},
		{"domain is not a mid-label suffix", m(d("domain:a.com"), nil, "", ""), m(d("domain:ba.com"), nil, "", ""), DestinationMatcher{Never: true}, true},
		{"domain against a full inside it", m(d("domain:a.com"), nil, "", ""), m(d("full:x.a.com"), nil, "", ""), m(d("full:x.a.com"), nil, "", ""), true},
		{"domain against a full outside it", m(d("domain:a.com"), nil, "", ""), m(d("full:b.com"), nil, "", ""), DestinationMatcher{Never: true}, true},
		{"full against full", m(d("full:a.com"), nil, "", ""), m(d("full:a.com"), nil, "", ""), m(d("full:a.com"), nil, "", ""), true},
		{"keyword against a full that contains it", m(d("keyword:nflx"), nil, "", ""), m(d("full:a.nflx.com"), nil, "", ""), m(d("full:a.nflx.com"), nil, "", ""), true},
		{"keyword against a full that lacks it", m(d("keyword:nflx"), nil, "", ""), m(d("full:a.com"), nil, "", ""), DestinationMatcher{Never: true}, true},
		{"keyword against a domain that contains it", m(d("keyword:nflx"), nil, "", ""), m(d("domain:nflx.com"), nil, "", ""), m(d("domain:nflx.com"), nil, "", ""), true},
		{"keyword against a domain that lacks it becomes a regexp", m(d("keyword:nflx"), nil, "", ""), m(d("domain:a.com"), nil, "", ""),
			m(d(`regexp:(?s)^(?:.*nflx.*)\.a\.com$`), nil, "", ""), true},
		{"keyword contained in keyword", m(d("keyword:nflx"), nil, "", ""), m(d("keyword:nflxv"), nil, "", ""), m(d("keyword:nflxv"), nil, "", ""), true},
		{"unrelated keywords are inexact, the longer wins", m(d("keyword:ab"), nil, "", ""), m(d("keyword:cde"), nil, "", ""), m(d("keyword:cde"), nil, "", ""), false},
		{"regexp against a domain is inexact", m(d(`regexp:^a`), nil, "", ""), m(d("domain:a.com"), nil, "", ""), m(d("domain:a.com"), nil, "", ""), false},
		{"regexp against a full is evaluated on the host", m(d(`regexp:^a`), nil, "", ""), m(d("full:a.com", "full:b.com"), nil, "", ""), m(d("full:a.com"), nil, "", ""), true},
		{"a regexp that does not compile never matches", m(d(`regexp:(`), nil, "", ""), m(d("domain:a.com"), nil, "", ""), DestinationMatcher{Never: true}, true},
		{"alternatives are a cross product", m(d("domain:a.com", "domain:b.com"), nil, "", ""), m(d("domain:x.a.com", "domain:y.b.com", "domain:c.com"), nil, "", ""),
			m(d("domain:x.a.com", "domain:y.b.com"), nil, "", ""), true},
		{"cidr nests in cidr", m(nil, []string{"10.0.0.0/8"}, "", ""), m(nil, []string{"10.1.0.0/16"}, "", ""), m(nil, []string{"10.1.0.0/16"}, "", ""), true},
		{"disjoint cidrs", m(nil, []string{"10.0.0.0/8"}, "", ""), m(nil, []string{"11.0.0.0/8"}, "", ""), DestinationMatcher{Never: true}, true},
		{"v4 against v6", m(nil, []string{"0.0.0.0/0"}, "", ""), m(nil, []string{"::/0"}, "", ""), DestinationMatcher{Never: true}, true},
		{"a hostname rule against an address rule", m(d("domain:a.com"), nil, "", ""), m(nil, []string{"10.0.0.0/8"}, "", ""), DestinationMatcher{Never: true}, true},
		{"private against private is private", DestinationMatcher{Private: true}, DestinationMatcher{Private: true}, DestinationMatcher{Private: true}, true},
		{"private against a cidr inside the table", DestinationMatcher{Private: true}, m(nil, []string{"10.1.0.0/16"}, "", ""), m(nil, []string{"10.1.0.0/16"}, "", ""), true},
		{"private against a cidr holding table entries", DestinationMatcher{Private: true}, m(nil, []string{"192.0.0.0/8"}, "", ""),
			m(nil, []string{"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "192.88.99.0/24"}, "", ""), true},
		{"private against a public cidr", DestinationMatcher{Private: true}, m(nil, []string{"8.8.8.0/24"}, "", ""), DestinationMatcher{Never: true}, true},
		{"ports intersect", m(nil, nil, "80,443,8000-9000", ""), m(nil, nil, "1-100,8500-10000", ""), m(nil, nil, "80,8500-9000", ""), true},
		{"ports with nothing in common", m(nil, nil, "80", ""), m(nil, nil, "443", ""), DestinationMatcher{Never: true}, true},
		{"adjacent port ranges are one range", m(nil, nil, "1-10,11-20", ""), m(nil, nil, "5-15", ""), m(nil, nil, "5-15", ""), true},
		{"ports against any", m(nil, nil, "", ""), m(nil, nil, "25", ""), m(nil, nil, "25", ""), true},
		{"network against any", m(nil, nil, "", "tcp"), m(nil, nil, "", ""), m(nil, nil, "", "tcp"), true},
		{"tcp against udp", m(nil, nil, "", "tcp"), m(nil, nil, "", "udp"), DestinationMatcher{Never: true}, true},
		{"never absorbs", DestinationMatcher{Never: true}, m(d("domain:a.com"), nil, "", ""), DestinationMatcher{Never: true}, true},
		{"destination and ports and network together", m(d("domain:a.com"), nil, "443", "tcp"), m(d("keyword:a.c"), nil, "400-500", ""), m(d("domain:a.com"), nil, "443", "tcp"), true},
		{"on_demand cidr against a domain keeps the domain", DestinationMatcher{CIDRs: []string{"10.0.0.0/8"}, OnDemand: true}, m(d("domain:a.com"), nil, "", ""),
			m(d("domain:a.com"), nil, "", ""), false},
		{"on_demand cidr against an as-is cidr is exact and as-is", DestinationMatcher{CIDRs: []string{"10.0.0.0/8"}, OnDemand: true}, m(nil, []string{"10.1.0.0/16"}, "", ""),
			m(nil, []string{"10.1.0.0/16"}, "", ""), true},
		{"on_demand unconstrained side keeps on_demand", DestinationMatcher{CIDRs: []string{"10.0.0.0/8"}, OnDemand: true}, m(nil, nil, "80", ""),
			DestinationMatcher{CIDRs: []string{"10.0.0.0/8"}, Ports: "80", OnDemand: true}, true},
		{"two on_demand cidr sets are inexact", DestinationMatcher{CIDRs: []string{"10.0.0.0/8"}, OnDemand: true}, DestinationMatcher{CIDRs: []string{"10.1.0.0/16"}, OnDemand: true},
			DestinationMatcher{CIDRs: []string{"10.0.0.0/8"}, OnDemand: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, exact := IntersectDestinations(tc.a, tc.b)
			if !reflect.DeepEqual(got, tc.want) || exact != tc.exact {
				t.Fatalf("got %+v exact=%v\nwant %+v exact=%v", got, exact, tc.want, tc.exact)
			}
			// The conjunction is symmetric as a set, whatever the spelling.
			back, backExact := IntersectDestinations(tc.b, tc.a)
			if backExact != exact {
				t.Fatalf("exactness depends on the order: %v then %v", exact, backExact)
			}
			if !exact {
				return
			}
			if !reflect.DeepEqual(back, got) {
				t.Fatalf("result depends on the order:\n%+v\n%+v", got, back)
			}
		})
	}
}

func TestIntersectDestinationsDoesNotAliasItsOperands(t *testing.T) {
	a := DestinationMatcher{Domains: []string{"domain:a.com"}}
	got, _ := IntersectDestinations(a, DestinationMatcher{Ports: "80"})
	got.Domains[0] = "domain:changed"
	if a.Domains[0] != "domain:a.com" {
		t.Fatal("editing the result reached the operand")
	}
}

// byteReader turns fuzz bytes into small matchers over a vocabulary chosen so
// that entries overlap: the interesting cases are a host that is in one set and
// not the other, so hosts and entries are built from the same few pieces.
type byteReader struct {
	data []byte
	next int
}

func (r *byteReader) byte() byte {
	if r.next >= len(r.data) {
		return 0
	}
	b := r.data[r.next]
	r.next++
	return b
}

func (r *byteReader) pick(options []string) string { return options[int(r.byte())%len(options)] }

var (
	fuzzLabels = []string{"a", "b", "ab", "a.b", "b.a", "com", "a.com", "x.a.com", "nflx", "-", "ab.c", "c.", ".c", "", "A"}
	fuzzRegexp = []string{`^a`, `b$`, `a\.b`, `^(a|b)\.`, `^x\.`, `(`, `.`, `^a\.com$`}
	fuzzCIDRs  = []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "0.0.0.0/0", "192.168.0.0/16", "192.0.0.0/8", "::/0", "fc00::/7", "fe80::/10",
		"::1/128", "127.0.0.1/32", "2001:db8::/32", "::/80", "::ffff:0:0/96", "8.8.8.0/24", "nonsense", "10.1.2.3/8"}
	fuzzPorts   = []string{"", "", "80", "80,443", "1-1024", "443", "8000-9000", "1-65535", "80-90,100", "8500-10000", "bad", "9-1"}
	fuzzNetwork = []string{"", "", "tcp", "udp", "icmp"}
	fuzzHosts   = []string{"a.com", "x.a.com", "b.a", "ab", "nflx.com", "a.nflx.com", "a.b", "c.", "a.com.", "", "-", "ab.c", "xa.com", ".a.com", "10.1.2.3",
		"10.0.0.1", "192.168.1.1", "8.8.8.8", "::1", "fc00::1", "::ffff:10.1.2.3", "127.0.0.1", "2001:db8::1", "[::1]", "0.0.0.0", "fe80::1", "192.0.2.5"}
)

func (r *byteReader) matcher() DestinationMatcher {
	var m DestinationMatcher
	for n := int(r.byte() % 3); n > 0; n-- {
		kinds := []string{"domain:", "full:", "keyword:", "domain:", "full:", "keyword:", "regexp:"}
		kind := r.pick(kinds)
		value := r.pick(fuzzLabels)
		if kind == "regexp:" {
			value = r.pick(fuzzRegexp)
		}
		m.Domains = append(m.Domains, kind+value)
	}
	for n := int(r.byte() % 3); n > 0; n-- {
		m.CIDRs = append(m.CIDRs, r.pick(fuzzCIDRs))
	}
	m.Private = r.byte()%4 == 0
	m.Ports = r.pick(fuzzPorts)
	m.Network = r.pick(fuzzNetwork)
	m.OnDemand = r.byte()%4 == 0
	// The result is held to be right for matchers a validator would accept, as
	// well as for the odd ones above, but sorted and unique like a rule's.
	m.Domains = sortedUnique(m.Domains)
	m.CIDRs = sortedUnique(m.CIDRs)
	return m
}

// checkIntersect is the property the compiler relies on: the result matches a
// connection exactly when both operands do, and when it is inexact it never
// matches less.
func checkIntersect(t *testing.T, data []byte) bool {
	t.Helper()
	r := &byteReader{data: data}
	a, b := r.matcher(), r.matcher()
	result, exact := IntersectDestinations(a, b)
	again, againExact := IntersectDestinations(a, b)
	if !reflect.DeepEqual(result, again) || exact != againExact {
		t.Fatalf("not deterministic for %+v and %+v", a, b)
	}
	if !slices.IsSorted(result.Domains) || !slices.IsSorted(result.CIDRs) || len(slices.Compact(slices.Clone(result.Domains))) != len(result.Domains) {
		t.Fatalf("result lists are not sorted and unique: %+v", result)
	}
	hosts := slices.Clone(fuzzHosts)
	for _, entry := range append(slices.Clone(a.Domains), b.Domains...) {
		_, value, _ := cutEntry(entry)
		hosts = append(hosts, value, "x."+value, value+"x", "x"+value, "a."+value+".b")
	}
	for i := 0; i < 6; i++ {
		hosts = append(hosts, r.pick(fuzzLabels)+"."+r.pick(fuzzLabels), r.pick(fuzzLabels)+r.pick(fuzzLabels))
	}
	ports := []uint16{0, 25, 80, 100, 443, 1024, 8080, 8500, 9000, 9001, 65535}
	networks := []string{"", "tcp", "udp", "icmp"}
	resolveds := [][]string{nil, {}, {"10.1.2.3"}, {"8.8.8.8", "192.168.1.1"}, {"fc00::1", "1.1.1.1"}, {"10.0.0.1", "127.0.0.1"}}
	for _, host := range hosts {
		for _, port := range ports {
			for _, network := range networks {
				for _, resolved := range resolveds {
					in := MatchInput{Target: host, Port: port, Network: network, Resolved: resolved}
					both := a.Matches(in) && b.Matches(in)
					got := result.Matches(in)
					if exact && got != both {
						t.Fatalf("exact result disagrees on %+v: result=%v a&&b=%v\na=%+v\nb=%+v\nresult=%+v", in, got, both, a, b, result)
					}
					if !exact && both && !got {
						t.Fatalf("inexact result is not an over-approximation on %+v\na=%+v\nb=%+v\nresult=%+v", in, a, b, result)
					}
				}
			}
		}
	}
	return exact && !result.Never
}

func cutEntry(entry string) (kind, value string, ok bool) {
	for i := 0; i < len(entry); i++ {
		if entry[i] == ':' {
			return entry[:i], entry[i+1:], true
		}
	}
	return "", entry, false
}

// FuzzIntersect checks the conjunction against the reference matcher: for any
// two matchers and any connection, an exact result matches iff both operands do.
func FuzzIntersect(fuzz *testing.F) {
	fuzz.Add([]byte{})
	fuzz.Add([]byte{1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	fuzz.Add([]byte{2, 2, 1, 1, 0, 9, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8})
	fuzz.Add([]byte{1, 2, 7, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	fuzz.Add([]byte{0, 2, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	fuzz.Add([]byte{2, 2, 4, 2, 5, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0})
	fuzz.Fuzz(func(t *testing.T, data []byte) { checkIntersect(t, data) })
}

// The seeds above are few; this walks a fixed pseudo-random stream through the
// same property, so the ordinary test run covers it too.
func TestIntersectAgainstTheReferenceMatcher(t *testing.T) {
	const pairs, batchSize = 400, 50
	rng := rand.New(rand.NewPCG(1, 2))
	// Draw the same stream in order before running the independent checks.
	var inputs [pairs][40]byte
	for i := range inputs {
		for j := range inputs[i] {
			inputs[i][j] = byte(rng.Uint32())
		}
	}
	var nonTrivial [pairs / batchSize]int
	t.Run("batches", func(t *testing.T) {
		for batch := range nonTrivial {
			first := batch * batchSize
			t.Run(fmt.Sprintf("%03d-%03d", first, first+batchSize-1), func(t *testing.T) {
				t.Parallel()
				for i := first; i < first+batchSize; i++ {
					if checkIntersect(t, inputs[i][:]) {
						nonTrivial[batch]++
					}
				}
			})
		}
	})
	// A property that only ever saw empty intersections would prove little.
	total := 0
	for _, count := range nonTrivial {
		total += count
	}
	if total < 40 {
		t.Fatalf("only %d of the generated pairs had a non-empty exact intersection", total)
	}
	t.Logf("%d non-empty exact intersections checked", total)
}
