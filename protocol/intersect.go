package protocol

import (
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// DestinationMatcher is the destination half of a rule, on its own: what a
// DestinationRule and a RouteRule both say about where a connection goes.
//
// Domains, CIDRs and Private are alternatives, and a matcher with none of the
// three accepts every destination. They are ANDed with Ports and Network.
type DestinationMatcher struct {
	Domains []string
	CIDRs   []string
	Private bool
	Ports   string
	Network string
	// OnDemand is ResolveOnDemand: a hostname also satisfies CIDRs and Private
	// through the addresses it resolves to. A route rule has it exactly when the
	// policy it is routed under does (RouteRule.Matcher).
	OnDemand bool
	// Never is a matcher that accepts nothing, the intersection of two matchers
	// with nothing in common. It cannot be told by an empty field, which means
	// "any".
	Never bool
}

// DestinationMatcherOf is the destination matcher of a policy rule under the
// policy's Resolve mode.
func DestinationMatcherOf(rule DestinationRule, resolve ResolveMode) DestinationMatcher {
	return DestinationMatcher{
		Domains: rule.Domains, CIDRs: rule.CIDRs, Private: rule.Private,
		Ports: rule.Ports, Network: rule.Network, OnDemand: resolve == ResolveOnDemand,
	}
}

// Matches is whether the matcher definitely accepts the connection. Input the
// matcher depends on and does not know is not a match. It is the same reading
// MatchDestination gives a rule, so one matcher means one thing.
func (m DestinationMatcher) Matches(in MatchInput) bool { return m.Outcome(in) == StepHit }

// Outcome is Matches with the third answer MatchDestination gives a rule: hit,
// miss, or untestable when the input leaves unknown something the matcher
// depends on (a port, a network, a target, or under OnDemand the resolved
// addresses of a hostname).
func (m DestinationMatcher) Outcome(in MatchInput) MatchStepResult {
	if m.Never {
		return StepMiss
	}
	rule := DestinationRule{ID: "p1", Domains: m.Domains, CIDRs: m.CIDRs, Private: m.Private, Ports: m.Ports, Network: m.Network}
	mode := ResolveAsIs
	if m.OnDemand {
		mode = ResolveOnDemand
	}
	outcome, _, _ := matchRule(rule, MatchInput{Target: in.Target, Port: in.Port, Network: in.Network, Resolved: in.Resolved},
		newMatchTarget(in.Target), newResolution(&DestinationPolicy{Resolve: mode}, in))
	return outcome
}

// constrained is whether the matcher says anything about the destination.
func (m DestinationMatcher) constrained() bool {
	return len(m.Domains) > 0 || len(m.CIDRs) > 0 || m.Private
}

func (m DestinationMatcher) hasAddresses() bool { return len(m.CIDRs) > 0 || m.Private }

// IntersectDestinations is the conjunction of two matchers: a connection
// matches the result exactly when it matches both. The Xray compiler uses it to
// make a policy rule apply only to the traffic a route rule sends out one exit.
// It is pure and deterministic, and its lists come back sorted and
// duplicate-free.
//
// WHEN exact IS TRUE the result matches precisely what a and b both match.
//
// exact APPLIES TO THIS ONE PAIR. Whether a policy rule applies to the traffic
// of one route rule's exit also depends on the earlier route rules, which the
// compiler handles by emitting segments in route order (see RouteRule); this
// function does not exclude them.
//
// WHEN exact IS FALSE the result is an OVER-APPROXIMATION: it matches
// everything a and b both match, and possibly more. It is never a subset, so a
// caller that applies the result to a block loses nothing and over-blocks at
// worst, and a caller for whom matching too much is unsafe (an allow or an observe, which
// would then record or exempt traffic that is not in scope) must refuse an
// inexact result and never use it. The bound is deliberate and
// uniform, so no caller has to know which pair was approximated.
//
// What is exact:
//   - domain: against domain:, full:, and keyword: when the domain contains the
//     keyword or the result can be written as a regexp (the host is any
//     prefix plus the domain, and the keyword lies in the prefix or reaches into
//     the domain from it); the result is then a regexp: entry, so a caller that
//     bounds regexps must count it. Exactness here needs an ASCII domain and
//     keyword and a result under 1024 bytes.
//   - full: against everything, including a regexp, which is evaluated on the
//     one host.
//   - keyword: against keyword: when one contains the other.
//   - CIDRs and Private against each other (prefixes nest or are disjoint),
//     ports (range intersection) and network.
//   - a matcher with no destination constraint is the identity.
//
// What is not, with the over-approximation returned:
//   - regexp: against domain:, keyword: or another regexp: the other entry
//     (for two regexps the smaller one by text);
//   - keyword: against an unrelated keyword: the longer one (then the smaller
//     by text), since "contains both" is not one keyword;
//   - a domain, and an address matcher with OnDemand on the other side: a
//     hostname that merely resolves into the CIDRs is a match, so the domain
//     entries are kept;
//   - address matchers that both have OnDemand: the first one's addresses (a
//     hostname must resolve into both, which is not resolving into their
//     intersection).
//
// A regexp that does not compile never matches, so a pair holding one is empty
// and exact.
//
// A result that matches nothing says so with Never, and is exact.
func IntersectDestinations(a, b DestinationMatcher) (result DestinationMatcher, exact bool) {
	if a.Never || b.Never {
		return DestinationMatcher{Never: true}, true
	}
	ports, never := intersectPorts(a.Ports, b.Ports)
	if never {
		return DestinationMatcher{Never: true}, true
	}
	network, never := intersectNetwork(a.Network, b.Network)
	if never {
		return DestinationMatcher{Never: true}, true
	}
	result = DestinationMatcher{Ports: ports, Network: network}
	exact = true
	switch {
	case !a.constrained() && !b.constrained():
	case !b.constrained():
		result.Domains, result.CIDRs, result.Private = a.Domains, a.CIDRs, a.Private
		result.OnDemand = a.OnDemand && a.hasAddresses()
	case !a.constrained():
		result.Domains, result.CIDRs, result.Private = b.Domains, b.CIDRs, b.Private
		result.OnDemand = b.OnDemand && b.hasAddresses()
	default:
		var domainsExact, addressesExact bool
		result.Domains, domainsExact = intersectDomains(a, b)
		result.CIDRs, result.Private, result.OnDemand, addressesExact = intersectAddresses(a, b)
		exact = domainsExact && addressesExact
		if len(result.Domains) == 0 && len(result.CIDRs) == 0 && !result.Private {
			return DestinationMatcher{Never: true}, exact
		}
	}
	// Own the slices, so a caller that edits the result cannot reach an operand.
	result.Domains, result.CIDRs = slices.Clone(result.Domains), slices.Clone(result.CIDRs)
	if len(result.Domains) == 0 {
		result.Domains = nil
	}
	if len(result.CIDRs) == 0 {
		result.CIDRs = nil
	}
	return result, exact
}

func sortedUnique(items []string) []string {
	sort.Strings(items)
	return slices.Compact(items)
}

func intersectDomains(a, b DestinationMatcher) (domains []string, exact bool) {
	exact = true
	for _, x := range a.Domains {
		for _, y := range b.Domains {
			entries, ok := intersectDomainEntries(x, y)
			domains = append(domains, entries...)
			exact = exact && ok
		}
	}
	// A hostname that resolves into the other side's addresses matches that
	// side. The conjunction is then "this entry and resolves there", which a
	// matcher cannot say: keep the entry, which is the over-approximation.
	if b.OnDemand && b.hasAddresses() {
		domains = append(domains, a.Domains...)
		exact = exact && len(a.Domains) == 0
	}
	if a.OnDemand && a.hasAddresses() {
		domains = append(domains, b.Domains...)
		exact = exact && len(b.Domains) == 0
	}
	return sortedUnique(domains), exact
}

func intersectAddresses(a, b DestinationMatcher) (cidrs []string, private, onDemand, exact bool) {
	exact = true
	if !a.hasAddresses() || !b.hasAddresses() {
		return nil, false, false, true
	}
	if a.OnDemand && b.OnDemand {
		// A hostname must resolve into a and into b, not into both at once.
		return slices.Clone(a.CIDRs), a.Private, true, false
	}
	aOwn, bOwn := parsePrefixes(a.CIDRs), parsePrefixes(b.CIDRs)
	table := privatePrefixes()
	meet := func(ps, qs []netip.Prefix) {
		for _, p := range ps {
			for _, q := range qs {
				if prefix, ok := intersectPrefix(p, q); ok {
					cidrs = append(cidrs, prefix.String())
				}
			}
		}
	}
	meet(aOwn, bOwn)
	if b.Private {
		meet(aOwn, table)
	}
	if a.Private {
		meet(table, bOwn)
	}
	// The table against the table is the table itself. Doing it prefix by
	// prefix would spell Private out and lose the flag.
	private = a.Private && b.Private
	return sortedUnique(cidrs), private, false, true
}

// parsePrefixes are the CIDRs that parse, masked. One that does not never
// matches in the reference matcher, so dropping it is exact.
func parsePrefixes(cidrs []string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, cidr := range cidrs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return prefixes
}

// intersectPrefix: two prefixes either nest or share nothing, so the
// intersection is the longer one or empty.
func intersectPrefix(p, q netip.Prefix) (netip.Prefix, bool) {
	if !p.Overlaps(q) {
		return netip.Prefix{}, false
	}
	if q.Bits() > p.Bits() {
		return q, true
	}
	return p, true
}

func intersectNetwork(a, b string) (string, bool) {
	known := func(network string) bool { return network == "" || network == "tcp" || network == "udp" }
	switch {
	case !known(a) || !known(b):
		// A network the model has no word for never matches.
		return "", true
	case a == "":
		return b, false
	case b == "" || a == b:
		return a, false
	}
	return "", true
}

// intersectPorts returns the canonical spelling of the ports both specs allow.
// never is set when there are none, or when a spec does not parse (it matches
// nothing in the reference matcher).
func intersectPorts(a, b string) (spec string, never bool) {
	if a == "" && b == "" {
		return "", false
	}
	var left, right [][2]uint16
	var err error
	if a != "" {
		if left, err = parsePorts(a); err != nil {
			return "", true
		}
	}
	if b != "" {
		if right, err = parsePorts(b); err != nil {
			return "", true
		}
	}
	switch {
	case a == "":
		return b, false
	case b == "":
		return a, false
	}
	var out [][2]uint16
	for i, j := 0, 0; i < len(left) && j < len(right); {
		low, high := max(left[i][0], right[j][0]), min(left[i][1], right[j][1])
		if low <= high {
			if n := len(out); n > 0 && int(out[n-1][1])+1 == int(low) {
				out[n-1][1] = high // adjacent: one spelling for one set
			} else {
				out = append(out, [2]uint16{low, high})
			}
		}
		if left[i][1] < right[j][1] {
			i++
		} else {
			j++
		}
	}
	if len(out) == 0 {
		return "", true
	}
	parts := make([]string, len(out))
	for i, r := range out {
		parts[i] = strconv.Itoa(int(r[0]))
		if r[1] != r[0] {
			parts[i] += "-" + strconv.Itoa(int(r[1]))
		}
	}
	return strings.Join(parts, ","), false
}

type domainEntry struct{ kind, value, text string }

func splitDomainEntry(text string) domainEntry {
	kind, value, _ := strings.Cut(text, ":")
	return domainEntry{kind, value, text}
}

var domainEntryRank = map[string]int{"domain": 0, "full": 1, "keyword": 2, "regexp": 3}

// intersectDomainEntries is the conjunction of two domain entries as a list of
// entries (an OR); see IntersectDestinations for what is exact and what the
// over-approximation is.
func intersectDomainEntries(x, y string) (entries []string, exact bool) {
	if x == y {
		return []string{x}, true
	}
	e, f := splitDomainEntry(x), splitDomainEntry(y)
	// An entry of a kind the matcher does not know never matches.
	rankE, okE := domainEntryRank[e.kind]
	rankF, okF := domainEntryRank[f.kind]
	if !okE || !okF {
		return nil, true
	}
	// A regexp that does not compile never matches.
	if (e.kind == "regexp" && !regexpCompiles(e.value)) || (f.kind == "regexp" && !regexpCompiles(f.value)) {
		return nil, true
	}
	if rankE > rankF || (rankE == rankF && e.text > f.text) {
		e, f = f, e
	}
	// A full: is one host: the other entry either matches it or not.
	if e.kind == "full" || f.kind == "full" {
		full, other := e, f
		if f.kind == "full" {
			full, other = f, e
		}
		if domainEntryMatches(other.text, full.value) {
			return []string{full.text}, true
		}
		return nil, true
	}
	switch e.kind + "+" + f.kind {
	case "domain+domain":
		switch {
		case domainEntryMatches(e.text, f.value):
			return []string{f.text}, true
		case domainEntryMatches(f.text, e.value):
			return []string{e.text}, true
		}
		return nil, true
	case "domain+keyword":
		if strings.Contains(e.value, f.value) {
			return []string{e.text}, true
		}
		if re, ok := keywordInDomainRegexp(e.value, f.value); ok {
			return []string{"regexp:" + re}, true
		}
		return []string{e.text}, false
	case "keyword+keyword":
		switch {
		case strings.Contains(e.value, f.value):
			return []string{e.text}, true
		case strings.Contains(f.value, e.value):
			return []string{f.text}, true
		case len(f.value) > len(e.value):
			return []string{f.text}, false
		}
		return []string{e.text}, false
	case "domain+regexp", "keyword+regexp":
		return []string{e.text}, false
	}
	// regexp+regexp
	return []string{e.text}, false
}

func regexpCompiles(expr string) bool {
	_, err := regexp.Compile(expr)
	return err == nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// keywordInDomainRegexp writes "the host is domain or a subdomain of it, and
// contains keyword" as one regexp, for a domain that does not itself contain the
// keyword (when it does, domain: alone is the answer). A host that is the domain
// itself cannot contain the keyword, so the host is X + "." + domain for some X,
// and the keyword either lies inside X, or starts in X and runs into ".domain":
// keyword[:i] ends X and keyword[i:] is a prefix of ".domain".
//
// ASCII only: the regexp reads UTF-8, and a host that is not would match a
// literal U+FFFD the string comparison does not see.
func keywordInDomainRegexp(domain, keyword string) (string, bool) {
	if !isASCII(domain) || !isASCII(keyword) {
		return "", false
	}
	alternatives := []string{".*" + regexp.QuoteMeta(keyword) + ".*"}
	dotted := "." + domain
	for i := 0; i < len(keyword); i++ {
		if strings.HasPrefix(dotted, keyword[i:]) {
			alternatives = append(alternatives, ".*"+regexp.QuoteMeta(keyword[:i]))
		}
	}
	expr := "(?s)^(?:" + strings.Join(alternatives, "|") + `)\.` + regexp.QuoteMeta(domain) + "$"
	if len(expr) > 1024 || !regexpCompiles(expr) {
		return "", false
	}
	return expr, true
}
