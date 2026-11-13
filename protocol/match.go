package protocol

import (
	"net/netip"
	"regexp"
	"strings"
	"sync"
)

// privateDestinationCIDRs is what DestinationRule.Private means: the table
// behind xray-core's private-address matcher (GetPrivateIPMatcher in
// common/geodata/consts.go, which backs `geoip:private`).
//
// Read from xray-core v1.260327.1-0.20260711155151-50231eaff98c, the oldest
// copy in the module cache; the three newer copies (...20260728..., ...20260908...,
// ...20261021...) carry the identical list. A rule that used a narrower table
// would let a private destination through that the core's own rule stops, and
// a wider one would block addresses an operator never named.
var privateDestinationCIDRs = [...]string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/3",
	"::/127",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

// PrivateDestinationCIDRs returns the table DestinationRule.Private stands for.
// It is a fresh copy on every call: the table is what a rule MEANS, so nothing a
// caller does to the slice may reach the matcher.
func PrivateDestinationCIDRs() []string {
	return append([]string(nil), privateDestinationCIDRs[:]...)
}

var privatePrefixes = sync.OnceValue(func() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(privateDestinationCIDRs))
	for _, cidr := range privateDestinationCIDRs {
		prefixes = append(prefixes, netip.MustParsePrefix(cidr))
	}
	return prefixes
})

// MatchInput is one connection to test a policy against. A zero field means
// "unknown", and a rule that depends on an unknown field is untestable rather
// than a miss.
type MatchInput struct {
	Subject SubjectKey  // "" = not exempt, in no group
	Inbound ListenerKey // "" = unknown inbound: rules with Inbounds are untestable
	Source  string      // client IP; "" = unknown: SourceCIDRs rules are untestable
	Target  string      // hostname or IP literal
	Port    uint16      // 0 = unknown: rules with Ports are untestable
	Network string      // "tcp" | "udp" | "" (unknown)
}

// MatchStepResult is how one step of the trace came out.
type MatchStepResult string

const (
	StepHit        MatchStepResult = "hit"
	StepMiss       MatchStepResult = "miss"
	StepUntestable MatchStepResult = "untestable" // depends on something the input left unknown
	// StepShadowed would have hit, but an earlier step ended the evaluation.
	StepShadowed MatchStepResult = "shadowed"
	// StepSkipped came after the step that ended the evaluation and would not
	// have hit either.
	StepSkipped MatchStepResult = "skipped"
)

// MatchVerdict is what a policy does with a connection.
type MatchVerdict string

const (
	MatchAllow   MatchVerdict = "allow"
	MatchBlock   MatchVerdict = "block"
	MatchObserve MatchVerdict = "observe" // allowed, and recorded
	MatchDefault MatchVerdict = "default" // no rule hit: the core's own routing decides
)

// MatchBuiltin names a rule the node adds to the policy itself, which has a
// step in the trace but no entry in DestinationPolicy.Rules.
type MatchBuiltin string

// BuiltinTrailingDot is the node-internal rule that blocks every hostname target
// ending in "." (Xray: regexp:\.$ to the blocked outbound, ruleTag
// psp-trailing-dot). A compiler emits it whenever the policy has a block rule
// with Domains, between the exempt list and the phase-3 block rules.
//
// WHY THESE HOSTS ARE BLOCKED AND NOT NORMALISED. xray-core's router hands the
// target to its matchers as written (it lowercases it, and does nothing else),
// so "example.com." reaches `domain:example.com`, `full:example.com` and an
// anchored regexp as a different string and passes all three. There is no hook
// to strip the dot before matching, so the dot cannot be removed on the
// engine's behalf. A rule that blocks every such host closes every matcher
// kind (domain, full, keyword, regexp) at once, where a per-entry companion
// ("domain:example.com." next to "domain:example.com") would have to be
// generated for each entry of each kind and would miss a regexp that was not
// written for it. A target with a trailing dot is not a host a client has a
// reason to ask for by name, so what is lost is nothing an operator wanted.
//
// Case needs no such rule. See newMatchTarget for the trace.
const BuiltinTrailingDot MatchBuiltin = "trailing_dot"

// MatchNote is something a caller should tell the person reading the trace, that
// is not itself a verdict.
type MatchNote string

// NoteHostnameSkipsIPRules: the target is a hostname and the policy has rules
// over CIDRs or Private that were evaluated and did not hit. Those rules match
// addresses only, and nothing here resolves the hostname (the core routes with
// AsIs), so a hostname that resolves into a blocked range is not matched. On
// Xray, freedom has a default block of private destinations that can stop such a
// name after resolution, but only in the cases listed below; sing-box has none.
// The note lets the panel say so instead of reporting a clean miss.
//
// WHEN XRAY'S FALLBACK APPLIES (proxy/freedom/freedom.go: getDefaultFinalRule
// and matchFinalRule). It differs between the core versions the catalog ships,
// so treat it as a partial backstop only:
//   - only the freedom outbound has it, so a connection routed to any other
//     outbound is not covered;
//   - only for an inbound named exactly vless, vmess, trojan, hysteria or
//     wireguard, or one whose name begins with shadowsocks. Any other kind
//     (socks, http, dokodemo-door, ...) has no default; vless-reverse blocks
//     everything instead;
//   - it is the LAST rule tried: the operator's own finalRules match first;
//   - at v1.260327.1-0.20260711155151-50231eaff98c, with AsIs, freedom resolves
//     the hostname before checking. At 52a412d9e2f5 and 1b1647cd9ddf it dials
//     first and checks the remote address afterwards, so a TCP connection to the
//     private host is opened before it is dropped (a client can probe whether an
//     internal port is open), and a handler with sockopt.dialerProxy skips the
//     default block entirely (usesDialerProxy).
//
// A node must therefore not rely on the fallback.
//
// sing-box has no fallback at all, so there a hostname that resolves into a
// blocked range is simply let through.
const NoteHostnameSkipsIPRules MatchNote = "hostname_skips_ip_rules"

// MatchStep is one line of the trace.
type MatchStep struct {
	RuleID string // "" with Exempt == true for the exempt step, or with Builtin set
	Exempt bool
	// Builtin is set on the step of a node-internal rule, whose RuleID is "".
	Builtin MatchBuiltin
	Result  MatchStepResult
	Entry   string // the matching Domains/CIDRs/SourceCIDRs entry, when hit
}

// MatchResult is the outcome.
type MatchResult struct {
	Verdict     MatchVerdict
	Terminated  string // RuleID that terminated, "" for exempt, builtin and default
	ExemptHit   bool
	Steps       []MatchStep
	Conditional bool // an "untestable" step precedes the terminating step
	Notes       []MatchNote
}

// MatchDestination evaluates a policy against one connection without a core. It
// is for the panel's "test this destination" tool, so it explains rather than
// decides: every rule gets a step, and what it could not know is said so.
//
// It is pure and does no resolution: a hostname is never matched against CIDRs
// (the core routes with AsIs, no DNS), and an address is never matched against
// domains.
//
// EVERY MATCHER SEES THE HOST AS WRITTEN, lowercased, as xray-core's does. A
// hostname with a trailing dot is therefore NOT the same host to `domain:`,
// `full:` or an anchored regexp. What stops it is the builtin rule
// BuiltinTrailingDot, which this models as a step of its own (RuleID "", Builtin
// set) between the exempt list and the block rules: it hits for any hostname
// ending in "." when the policy has a block rule with Domains, and the verdict
// is then block with Terminated "". See BuiltinTrailingDot for why the host is
// blocked and not normalised.
//
// THERE IS NO NAME RESOLUTION. A hostname is never matched against CIDRs or
// Private, so a hostname that resolves into a blocked range is not matched, and
// the result says so with NoteHostnameSkipsIPRules. This is a documented
// limitation, not a gap to fill here. Xray's freedom has a default private-IP
// block that applies only in the cases NoteHostnameSkipsIPRules lists; sing-box
// has none.
//
// DOMAIN RULES JUDGE THE NAME AS SENT. A dotless hostname can be expanded by the
// node's DNS search list (common under Docker and Kubernetes), so the connection
// can go to a name the rules never saw. This trace models the name as sent.
//
// Surrounding spaces and the brackets of an IPv6 literal are accepted, and an
// address is read as xray-core's net.ParseAddress reads it: an IPv4-mapped IPv6
// address is its IPv4 address, and a leading-zero IPv4 or a zoned IPv6 is just a
// hostname. The semantics follow Xray and sing-box: the first hit terminates, in
// phase order, with the exempt list consulted between phases 1 and 3.
//
// It tolerates a policy that would not validate (an unknown rule is a miss, a
// regexp that does not compile never matches) because it is also pointed at
// whatever PSP is currently holding.
func MatchDestination(policy *DestinationPolicy, in MatchInput) MatchResult {
	result := MatchResult{Verdict: MatchDefault}
	if policy == nil {
		return result
	}
	target := newMatchTarget(in.Target)
	exemptDone := len(policy.Exempt) == 0
	builtinDone := !hasBlockDomains(policy)
	finished := false
	sawUntestable := false
	noted := false

	// finish records the step that ends the evaluation.
	finish := func(step MatchStep, verdict MatchVerdict, terminated string, exemptHit bool) {
		result.Steps = append(result.Steps, step)
		result.Verdict, result.Terminated, result.ExemptHit = verdict, terminated, exemptHit
		result.Conditional = sawUntestable
		finished = true
	}
	// special is a step that is not a rule of the policy: the exempt list, or
	// the trailing-dot builtin. Both can end the evaluation, and both are
	// reported as shadowed or skipped once something else has.
	special := func(step MatchStep, hit bool, verdict MatchVerdict, exemptHit bool) {
		switch {
		case finished && hit:
			step.Result = StepShadowed
		case finished:
			step.Result = StepSkipped
		case hit:
			step.Result = StepHit
			finish(step, verdict, "", exemptHit)
			return
		default:
			step.Result = StepMiss
		}
		result.Steps = append(result.Steps, step)
	}
	exemptStep := func() {
		exemptDone = true
		special(MatchStep{Exempt: true}, in.Subject != "" && containsKey(policy.Exempt, in.Subject), MatchAllow, true)
	}
	builtinStep := func() {
		builtinDone = true
		special(MatchStep{Builtin: BuiltinTrailingDot}, target.isHostname() && strings.HasSuffix(target.host, "."), MatchBlock, false)
	}
	// atBlockPhase runs what sits between the allows (phase 1) and the blocks
	// (phase 3): the exempt list at 2, the builtin at 2.5.
	atBlockPhase := func() {
		if !exemptDone {
			exemptStep()
		}
		if !builtinDone {
			builtinStep()
		}
	}

	for _, rule := range policy.Rules {
		phase, known := rulePhase(rule)
		if !known {
			phase = phaseGroup
		}
		if phase > phaseAllow {
			atBlockPhase()
		}
		// A rule with an id or action this package does not know has no verdict to
		// give, so it never hits (rather than terminating with an invented one).
		outcome, entry, ipSkipped := StepMiss, "", false
		if known {
			outcome, entry, ipSkipped = matchRule(rule, in, target)
		}
		if ipSkipped && outcome != StepHit && !finished && !noted {
			result.Notes = append(result.Notes, NoteHostnameSkipsIPRules)
			noted = true
		}
		step := MatchStep{RuleID: rule.ID}
		switch {
		case finished && outcome == StepHit:
			step.Result = StepShadowed
		case finished:
			step.Result = StepSkipped
		case outcome == StepHit:
			step.Result, step.Entry = StepHit, entry
			finish(step, MatchVerdict(rule.Action), rule.ID, false)
			continue
		default:
			step.Result = outcome
			if outcome == StepUntestable {
				sawUntestable = true
			}
		}
		result.Steps = append(result.Steps, step)
	}
	atBlockPhase()
	if !finished {
		result.Conditional = sawUntestable
	}
	return result
}

// hasBlockDomains is whether the trailing-dot builtin applies. Only a BLOCK rule
// has anything for a dotted host to slip past; an allow or observe rule that
// misses it fails safe, and an observe-only policy must not gain a blocking
// rule, since report-only never changes a verdict.
func hasBlockDomains(policy *DestinationPolicy) bool {
	for _, rule := range policy.Rules {
		if rule.Action == RuleBlock && len(rule.Domains) > 0 {
			return true
		}
	}
	return false
}

func containsKey(keys []SubjectKey, want SubjectKey) bool {
	for _, key := range keys {
		if key == want {
			return true
		}
	}
	return false
}

// matchTarget is the target after the reading xray-core gives it: the brackets
// of an IPv6 literal and surrounding spaces removed, lowercase, an address
// recognised as one (IPv4-mapped IPv6 unmapped, so 10/8 matches
// ::ffff:10.1.2.3 as the core's matcher would).
//
// THE HOST IS NOT OTHERWISE CHANGED, and in particular a trailing dot stays.
//
// CASE: xray-core lowercases the target before any domain matcher sees it
// (app/router/condition.go, DomainMatcher.Apply and ApplyDomain call
// strings.ToLower on the target domain before MatchAny), and that target is
// also what a sniffed domain becomes once the dispatcher substitutes it
// (app/dispatcher/default.go). The patterns are lowercased when built
// (common/geodata/domain_matcher.go parseDomain, for domain, full and keyword).
// A regexp is not lowercased, but it only ever sees the lowercased host. So an
// uppercase host cannot slip past `domain:`, `full:` or `keyword:`, and needs no
// builtin rule; the lowercasing here is the same step. (Read at
// v1.260327.1-0.20260711155151-50231eaff98c. An engine that does not lowercase
// has this hole and needs a rule of its own.)
type matchTarget struct {
	host    string
	addr    netip.Addr
	isAddr  bool
	unknown bool
}

func (t matchTarget) isHostname() bool { return !t.unknown && !t.isAddr }

// parseAddress reads an address the way xray-core's net.ParseAddress does as
// far as it matters here: surrounding spaces and a bracketed IPv6 literal are
// accepted, and what net.ParseIP rejects (a leading-zero IPv4, a zone) is not an
// address. The second result is the cleaned text.
func parseAddress(raw string) (netip.Addr, string, bool) {
	// In xray-core's order: the brackets come off first, and only then are the
	// spaces trimmed, and only when an edge is not alphanumeric. So " [::1] " is
	// a hostname (the brackets were not at the edge) and "[ ::1 ]" is an address.
	text := raw
	if len(text) > 0 && text[0] == '[' && text[len(text)-1] == ']' {
		text = text[1 : len(text)-1]
	}
	if len(text) > 0 && (!isAlphaNum(text[0]) || !isAlphaNum(text[len(text)-1])) {
		text = strings.TrimSpace(text)
	}
	text = strings.ToLower(text)
	addr, err := netip.ParseAddr(text)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, text, false
	}
	return addr.Unmap(), text, true
}

func isAlphaNum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func newMatchTarget(raw string) matchTarget {
	addr, text, ok := parseAddress(raw)
	if ok {
		return matchTarget{host: text, addr: addr, isAddr: true}
	}
	if text == "" {
		return matchTarget{unknown: true}
	}
	return matchTarget{host: text}
}

// matchRule evaluates one rule. Fields are ANDed, and a definite miss on any of
// them beats an untestable one, because the rule cannot hit either way.
func matchRule(rule DestinationRule, in MatchInput, target matchTarget) (outcome MatchStepResult, entry string, ipSkipped bool) {
	untestable := false
	if len(rule.Subjects) > 0 && (in.Subject == "" || !containsKey(rule.Subjects, in.Subject)) {
		return StepMiss, "", ipSkipped
	}
	if len(rule.Inbounds) > 0 {
		if in.Inbound == "" {
			untestable = true
		} else if !containsListener(rule.Inbounds, in.Inbound) {
			return StepMiss, "", ipSkipped
		}
	}
	if len(rule.SourceCIDRs) > 0 {
		source, _, ok := parseAddress(in.Source)
		if !ok {
			untestable = true
		} else if matched := firstPrefix(rule.SourceCIDRs, source); matched == "" {
			return StepMiss, "", ipSkipped
		} else {
			entry = matched
		}
	}
	if len(rule.Domains) > 0 || len(rule.CIDRs) > 0 || rule.Private {
		// The IP alternatives cannot be tried on a hostname: nothing resolves it.
		ipSkipped = target.isHostname() && (len(rule.CIDRs) > 0 || rule.Private)
		switch matched := matchDestinationGroup(rule, target); {
		case target.unknown:
			untestable = true
		case matched == "":
			return StepMiss, "", ipSkipped
		default:
			entry = matched
		}
	}
	if rule.Ports != "" {
		if in.Port == 0 {
			untestable = true
		} else if !portIn(rule.Ports, in.Port) {
			return StepMiss, "", ipSkipped
		}
	}
	if rule.Network != "" {
		// A network the policy has no word for cannot be compared, so it is
		// unknown rather than a mismatch.
		switch network := strings.ToLower(strings.TrimSpace(in.Network)); network {
		case "tcp", "udp":
			if network != rule.Network {
				return StepMiss, "", ipSkipped
			}
		default:
			untestable = true
		}
	}
	// A sniffed protocol cannot be known from a destination, so a protocol rule
	// can never be shown to hit or to miss here.
	if len(rule.Protocols) > 0 {
		untestable = true
	}
	if untestable {
		return StepUntestable, "", ipSkipped
	}
	return StepHit, entry, ipSkipped
}

func containsListener(keys []ListenerKey, want ListenerKey) bool {
	for _, key := range keys {
		if key == want {
			return true
		}
	}
	return false
}

func firstPrefix(cidrs []string, addr netip.Addr) string {
	for _, cidr := range cidrs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil && prefix.Contains(addr) {
			return cidr
		}
	}
	return ""
}

// matchDestinationGroup is the OR of Domains, CIDRs and Private. It returns the
// entry that matched, or "" for none.
func matchDestinationGroup(rule DestinationRule, target matchTarget) string {
	if target.unknown {
		return ""
	}
	if !target.isAddr {
		for _, entry := range rule.Domains {
			if domainEntryMatches(entry, target.host) {
				return entry
			}
		}
		return ""
	}
	if matched := firstPrefix(rule.CIDRs, target.addr); matched != "" {
		return matched
	}
	if rule.Private {
		for _, prefix := range privatePrefixes() {
			if prefix.Contains(target.addr) {
				return prefix.String()
			}
		}
	}
	return ""
}

func domainEntryMatches(entry, host string) bool {
	kind, value, ok := strings.Cut(entry, ":")
	if !ok {
		return false
	}
	switch kind {
	case "domain":
		return host == value || strings.HasSuffix(host, "."+value)
	case "full":
		return host == value
	case "keyword":
		return strings.Contains(host, value)
	case "regexp":
		// Unanchored, as the core's matcher is: the policy carries its own ^ and $.
		re, err := regexp.Compile(value)
		return err == nil && re.MatchString(host)
	}
	return false
}

func portIn(spec string, port uint16) bool {
	ranges, err := parsePorts(spec)
	if err != nil {
		return false
	}
	for _, r := range ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}
