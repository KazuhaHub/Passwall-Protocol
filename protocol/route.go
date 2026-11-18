package protocol

import (
	"fmt"
	"strings"
)

// CapabilityTransitRoute says the agent compiles Transit.Routes on every engine
// it runs, so a listener's traffic leaves through the exit its route rules pick
// for the destination, and honours DestinationRule.Exits when it compiles the
// destination policy.
//
// IT GATES SENDING, AND THE GATE IS MANDATORY. An agent that does not know the
// field ignores it and sends everything through the listener's default exit, so
// a user who asked for "streaming through Tokyo, the rest from here" would be
// served from the wrong country with no error anywhere. PSP must send
// Transit.Routes, and a DestinationRule.Exits, only to an agent that declared
// it. ValidateTransit cannot see capabilities.
//
// It is meaningful only alongside CapabilityTransitLink, and like it it is not
// an upgrade capability.
const CapabilityTransitRoute = "transit.route.v1"

// LocalExit is the exit that leaves from the agent itself, not through a link.
//
// It is a LinkKey so a route rule and a policy rule name every exit in one
// type, but it is NOT a link: LinkKey.RowID rejects it, so a LinkIn, a LinkOut,
// an EgressBinding, an audit hit or a probe result can never carry it. It is
// valid only in RouteRule.Exit and DestinationRule.Exits.
const LocalExit LinkKey = "local"

// Limits on routes. A listener is routed by a handful of rules; a list longer
// than this is a PSP defect, and the first-match scan is paid per connection.
const (
	MaxRouteRulesPerListener = 64
	MaxRouteRules            = 1024
)

// ListenerRoutes are the route rules of one listener, evaluated in order.
type ListenerRoutes struct {
	Listener ListenerKey `json:"listener"`
	Rules    []RouteRule `json:"rules"`
}

// RouteRule sends the connections it matches out through Exit. The first
// matching rule of a listener decides; a connection no rule matches leaves
// through the listener's default exit (see DefaultExit).
//
// The matchers are those of a DestinationRule and mean the same: Domains and
// CIDRs are alternatives, ANDed with Ports and Network. The router resolves
// a hostname for CIDRs exactly when the policy's Resolve is on_demand: under
// as-is a hostname never matches CIDRs, under on_demand it matches through its
// resolved addresses (see MatchRoute).
//
// DOMAINS ARE domain:, full: AND keyword: ONLY. A regexp cannot be intersected
// with a policy rule's matcher (see IntersectDestinations), and the intersection
// is how the Xray compiler makes a policy rule apply to the traffic of one exit.
// Refusing it here keeps every route rule exactly representable.
//
// COMPILE CONTRACT. The exit is chosen by the first matching route rule, else
// the default exit. A consumer that applies a destination policy per exit
// (DestinationRule.Exits) must emit, for each routed listener, in route order:
// for each route rule k, segment k = every policy rule whose Exits allows
// exit_k (empty Exits allows all), each ANDed with route_k, followed by a
// catch-all on route_k to exit_k; then the default segment (the policy rules
// whose Exits allows the default exit, unrestricted, then the default).
// Earlier segments consume the traffic of earlier route rules, which is what
// makes "first match wins" hold for a connection that also matches a later rule.
// IntersectDestinations is exact for ONE (policy rule, route rule) pair; the
// result is correct only because of that ordering, not because each
// intersection excludes the earlier route rules by itself.
//
// A rule must match on something. "Everything else" is the default exit, and
// leaving every field out to say it would make one early rule swallow the rest.
type RouteRule struct {
	// ID is r<n>, n >= 1 with no leading zero, unique within the listener.
	ID      string   `json:"id"`
	Domains []string `json:"domains,omitempty"`
	CIDRs   []string `json:"cidrs,omitempty"`
	Ports   string   `json:"ports,omitempty"`
	Network string   `json:"network,omitempty"`
	// Exit is LocalExit or one of Transit.LinksOut.
	Exit LinkKey `json:"exit"`
}

func validateRoutes(transit *Transit) error {
	if len(transit.Routes) == 0 {
		return nil
	}
	out := make(map[LinkKey]bool, len(transit.LinksOut))
	for _, link := range transit.LinksOut {
		out[link.Key] = true
	}
	seen := make(map[ListenerKey]bool, len(transit.Routes))
	total, domains, cidrs := 0, 0, 0
	for _, routes := range transit.Routes {
		if _, err := routes.Listener.RowID(); err != nil {
			return fmt.Errorf("routes: %w", err)
		}
		if seen[routes.Listener] {
			return fmt.Errorf("listener %s has two route lists", routes.Listener)
		}
		seen[routes.Listener] = true
		// An empty list says nothing a missing one does not, and would be a
		// second spelling of "no routes" with different bytes.
		if len(routes.Rules) == 0 {
			return fmt.Errorf("routes of %s have no rules", routes.Listener)
		}
		if len(routes.Rules) > MaxRouteRulesPerListener {
			return fmt.Errorf("listener %s has %d route rules, maximum is %d", routes.Listener, len(routes.Rules), MaxRouteRulesPerListener)
		}
		total += len(routes.Rules)
		if total > MaxRouteRules {
			return fmt.Errorf("transit has more than %d route rules", MaxRouteRules)
		}
		ids := make(map[string]bool, len(routes.Rules))
		for _, rule := range routes.Rules {
			if err := validateRouteRule(rule, out); err != nil {
				return fmt.Errorf("routes of %s, rule %q: %w", routes.Listener, rule.ID, err)
			}
			if ids[rule.ID] {
				return fmt.Errorf("routes of %s: duplicate rule id %q", routes.Listener, rule.ID)
			}
			ids[rule.ID] = true
			domains += len(rule.Domains)
			cidrs += len(rule.CIDRs)
		}
	}
	// The same ceilings a destination policy has: a route list is written by
	// the same hands and compiled by the same code.
	if domains > MaxPolicyDomains {
		return fmt.Errorf("routes have %d domains, maximum is %d", domains, MaxPolicyDomains)
	}
	if cidrs > MaxPolicyCIDRs {
		return fmt.Errorf("routes have %d destination cidrs, maximum is %d", cidrs, MaxPolicyCIDRs)
	}
	return nil
}

func validateRouteRule(rule RouteRule, links map[LinkKey]bool) error {
	number, ok := strings.CutPrefix(rule.ID, "r")
	if !ok || !canonicalDigits(number, 12) || number == "0" {
		return fmt.Errorf("id must match ^r[1-9][0-9]{0,11}$")
	}
	if len(rule.Domains) == 0 && len(rule.CIDRs) == 0 && rule.Ports == "" && rule.Network == "" {
		return fmt.Errorf("a route rule must match on something; the default exit covers the rest")
	}
	if err := validateSortedUnique("domains", rule.Domains); err != nil {
		return err
	}
	for _, entry := range rule.Domains {
		if strings.HasPrefix(entry, "regexp:") {
			return fmt.Errorf("domain %q: a route rule takes domain:, full: and keyword: only", entry)
		}
		if err := validateDomainEntry(entry); err != nil {
			return fmt.Errorf("domain %q: %w", entry, err)
		}
	}
	if err := validateCIDRList("cidrs", rule.CIDRs); err != nil {
		return err
	}
	if rule.Ports != "" {
		if _, err := parsePorts(rule.Ports); err != nil {
			return err
		}
	}
	switch rule.Network {
	case "", "tcp", "udp":
	default:
		return fmt.Errorf("network %q is not tcp, udp or empty", rule.Network)
	}
	if rule.Exit != LocalExit && !links[rule.Exit] {
		return fmt.Errorf("exit %q is neither %q nor one of this agent's outgoing links", rule.Exit, LocalExit)
	}
	return nil
}

// DefaultExit is where a listener's traffic leaves when no route rule matches:
// the link of its EgressBinding, else LocalExit.
func DefaultExit(transit Transit, listener ListenerKey) LinkKey {
	for _, binding := range transit.Egress {
		if binding.Listener == listener {
			return binding.Link
		}
	}
	return LocalExit
}

// MatchRoute is the exit a connection arriving on listener leaves through: the
// Exit of the first route rule that matches, else DefaultExit. It is the
// reference model the Xray compiler and the panel's test tool are held to.
// resolve is the destination policy's Resolve mode.
//
// known is false when the choice is conditional: a rule BEFORE the deciding one
// (or before the default) depends on something the input leaves unknown, so the
// connection might have taken that rule instead. exit is then the best guess,
// the exit the rules give when every unknown is read as a miss, and a caller
// must not act on it as if it were certain (MatchRouted does not).
//
// Unknown input is untestable, not a miss, exactly as MatchDestination reads a
// policy rule: a port, network or target the input leaves unknown makes a rule
// that depends on it untestable. A rule that is definitely missed, on a known
// field, is skipped with certainty. The target is read as MatchDestination
// reads it (lowercased, an IPv4-mapped address unmapped, a trailing dot kept),
// so "example.com." does not match domain:example.com here either.
//
// RESOLUTION FOLLOWS THE POLICY. Under ResolveAsIs nothing is resolved: a
// hostname never matches a rule's CIDRs and MatchInput.Resolved is ignored.
// Under ResolveOnDemand the Xray router resolves a hostname for IP rules, so a
// hostname meets a route rule's CIDRs through MatchInput.Resolved, and with
// Resolved nil the rule is untestable (the exit is conditional), as an on_demand
// policy rule is.
//
// An unknown listener ("") has no routes and no binding, so it leaves locally.
func MatchRoute(transit Transit, listener ListenerKey, in MatchInput, resolve ResolveMode) (exit LinkKey, known bool) {
	known = true
	for _, routes := range transit.Routes {
		if routes.Listener != listener {
			continue
		}
		for _, rule := range routes.Rules {
			switch rule.Matcher(resolve).Outcome(in) {
			case StepHit:
				return rule.Exit, known
			case StepUntestable:
				known = false
			}
		}
		break
	}
	return DefaultExit(transit, listener), known
}

// MatchRouted is MatchDestination with the exit filled in: it asks MatchRoute
// which exit the connection takes, using the policy's Resolve mode, so a rule
// with DestinationRule.Exits is judged on it. An input that already names an
// Exit keeps it. When the route choice is conditional, or there is no Inbound,
// the exit stays unknown, so rules with Exits come back untestable and the
// result conditional rather than a confident verdict on a guess. It returns the
// exit it used, "" when unknown.
func MatchRouted(policy *DestinationPolicy, transit Transit, in MatchInput) (MatchResult, LinkKey) {
	if in.Exit == "" && in.Inbound != "" {
		resolve := ResolveAsIs
		if policy != nil {
			resolve = policy.Resolve
		}
		if exit, known := MatchRoute(transit, in.Inbound, in, resolve); known {
			in.Exit = exit
		}
	}
	return MatchDestination(policy, in), in.Exit
}

// Matcher is the rule's destination matcher under the policy's Resolve mode:
// the router resolves a hostname for a rule's CIDRs exactly when the policy
// does, because Xray's domainStrategy is router-wide.
func (rule RouteRule) Matcher(resolve ResolveMode) DestinationMatcher {
	return DestinationMatcher{Domains: rule.Domains, CIDRs: rule.CIDRs, Ports: rule.Ports, Network: rule.Network,
		OnDemand: resolve == ResolveOnDemand}
}
