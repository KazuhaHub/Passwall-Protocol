package conformance

import "github.com/KazuhaHub/passwall-protocol/protocol"

// SniffingVector is one (inbound sniffing object, need) -> verdict case for
// protocol.CheckXraySniffing.
//
// THE EXPECTED VALUES ARE WRITTEN FROM THE RULES, NOT COPIED FROM THE CODE.
// Each case states a consequence of how xray-core's dispatcher decides whether
// content.Protocol is set (it is, whenever sniffing is enabled and a sniffer
// matched, independent of destOverride; with metadataOnly only the fakedns
// sniffer runs), so a Node or a PSP that re-implements the check is held to
// the rule, not to this package's reading of it.
type SniffingVector struct {
	Name string
	// Raw is the inbound's "sniffing" object exactly as it would appear in the
	// core config. Empty means the key is absent.
	Raw  string
	Need protocol.SniffNeed
	// Malformed means CheckXraySniffing must return an error; Verdict and
	// Reason are then unused.
	Malformed bool
	Verdict   protocol.SniffVerdict
	Reason    string
}

const (
	needDomains   = protocol.SniffForDomains
	needProtocols = protocol.SniffForProtocols
	needResolved  = protocol.SniffForResolvedIPs
)

// SniffingVectors is the shared table. Append to it; never edit a verdict to
// make an implementation pass.
var SniffingVectors = []SniffingVector{
	{Name: "nothing needed, nothing sniffed", Raw: "", Need: 0, Verdict: protocol.SniffOK},
	{Name: "nothing needed, sniffing disabled", Raw: `{"enabled":false}`, Need: 0, Verdict: protocol.SniffOK},

	{Name: "absent, domains needed", Raw: "", Need: needDomains, Verdict: protocol.SniffInject, Reason: "sniffing_disabled"},
	{Name: "whitespace only is absent", Raw: "  \n", Need: needDomains, Verdict: protocol.SniffInject, Reason: "sniffing_disabled"},
	{Name: "null is absent", Raw: "null", Need: needDomains, Verdict: protocol.SniffInject, Reason: "sniffing_disabled"},
	{Name: "empty object is disabled", Raw: "{}", Need: needDomains, Verdict: protocol.SniffInject, Reason: "sniffing_disabled"},
	{Name: "explicitly disabled", Raw: `{"enabled":false,"destOverride":["http","tls","quic"]}`, Need: needDomains,
		Verdict: protocol.SniffInject, Reason: "sniffing_disabled"},
	{Name: "absent, protocols needed", Raw: "", Need: needProtocols, Verdict: protocol.SniffInject, Reason: "sniffing_disabled"},
	{Name: "disabled, protocols needed", Raw: `{"enabled":false}`, Need: needProtocols, Verdict: protocol.SniffInject, Reason: "sniffing_disabled"},

	{Name: "full override, domains", Raw: `{"enabled":true,"destOverride":["http","tls","quic"]}`, Need: needDomains, Verdict: protocol.SniffOK},
	{Name: "full override with routeOnly false", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":false}`,
		Need: needDomains, Verdict: protocol.SniffOK},
	{Name: "routeOnly blocks domain matching", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}`,
		Need: needDomains, Verdict: protocol.SniffInsufficient, Reason: "route_only"},
	{Name: "routeOnly is irrelevant to protocols", Raw: `{"enabled":true,"routeOnly":true}`, Need: needProtocols, Verdict: protocol.SniffOK},
	{Name: "routeOnly with domains and protocols", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}`,
		Need: needDomains | needProtocols, Verdict: protocol.SniffInsufficient, Reason: "route_only"},
	{Name: "ipsExcluded blocks domain matching", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"ipsExcluded":["10.0.0.0/8"]}`,
		Need: needDomains, Verdict: protocol.SniffInsufficient, Reason: "ips_excluded"},
	{Name: "ipsExcluded as a string", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"ipsExcluded":"10.0.0.0/8"}`,
		Need: needDomains, Verdict: protocol.SniffInsufficient, Reason: "ips_excluded"},
	{Name: "empty ipsExcluded is fine", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"ipsExcluded":[]}`, Need: needDomains, Verdict: protocol.SniffOK},
	{Name: "ipsExcluded is irrelevant to protocols", Raw: `{"enabled":true,"ipsExcluded":["10.0.0.0/8"]}`, Need: needProtocols, Verdict: protocol.SniffOK},
	{Name: "exclusions are reported before routeOnly", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"domainsExcluded":["full:a"],"ipsExcluded":["10.0.0.0/8"],"routeOnly":true}`,
		Need: needDomains, Verdict: protocol.SniffInsufficient, Reason: "domains_excluded"},
	{Name: "ipsExcluded is reported before routeOnly", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"ipsExcluded":["10.0.0.0/8"],"routeOnly":true}`,
		Need: needDomains, Verdict: protocol.SniffInsufficient, Reason: "ips_excluded"},
	{Name: "fakedns entries are known", Raw: `{"enabled":true,"destOverride":["http","tls","quic","fakedns+others"]}`, Need: needDomains, Verdict: protocol.SniffOK},
	{Name: "override is case-insensitive", Raw: `{"enabled":true,"destOverride":["HTTP","Tls","QUIC"]}`, Need: needDomains, Verdict: protocol.SniffOK},
	{Name: "override as a comma-separated string", Raw: `{"enabled":true,"destOverride":"http,tls,quic"}`, Need: needDomains, Verdict: protocol.SniffOK},
	{Name: "override as a short string", Raw: `{"enabled":true,"destOverride":"http"}`, Need: needDomains,
		Verdict: protocol.SniffInsufficient, Reason: "dest_override_missing:tls"},
	{Name: "https and ssl are aliases of tls", Raw: `{"enabled":true,"destOverride":["http","https","quic"]}`, Need: needDomains, Verdict: protocol.SniffOK},
	{Name: "ssl is an alias of tls", Raw: `{"enabled":true,"destOverride":["http","ssl","quic"]}`, Need: needDomains, Verdict: protocol.SniffOK},
	{Name: "domainsExcluded as a string", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"domainsExcluded":"full:a.example"}`,
		Need: needDomains, Verdict: protocol.SniffInsufficient, Reason: "domains_excluded"},
	{Name: "extra override entries are fine", Raw: `{"enabled":true,"destOverride":["fakedns","http","tls","quic"]}`,
		Need: needDomains, Verdict: protocol.SniffOK},
	{Name: "empty domainsExcluded is fine", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"domainsExcluded":[]}`,
		Need: needDomains, Verdict: protocol.SniffOK},
	{Name: "unknown keys are ignored", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"x":1,"tag":"in"}`,
		Need: needDomains, Verdict: protocol.SniffOK},

	{Name: "override missing quic", Raw: `{"enabled":true,"destOverride":["http","tls"]}`, Need: needDomains,
		Verdict: protocol.SniffInsufficient, Reason: "dest_override_missing:quic"},
	{Name: "override missing http", Raw: `{"enabled":true,"destOverride":["tls","quic"]}`, Need: needDomains,
		Verdict: protocol.SniffInsufficient, Reason: "dest_override_missing:http"},
	{Name: "override missing tls", Raw: `{"enabled":true,"destOverride":["http","quic"]}`, Need: needDomains,
		Verdict: protocol.SniffInsufficient, Reason: "dest_override_missing:tls"},
	{Name: "first missing entry is named", Raw: `{"enabled":true,"destOverride":["http"]}`, Need: needDomains,
		Verdict: protocol.SniffInsufficient, Reason: "dest_override_missing:tls"},
	{Name: "empty override", Raw: `{"enabled":true,"destOverride":[]}`, Need: needDomains,
		Verdict: protocol.SniffInsufficient, Reason: "dest_override_missing:http"},
	{Name: "no override key", Raw: `{"enabled":true}`, Need: needDomains,
		Verdict: protocol.SniffInsufficient, Reason: "dest_override_missing:http"},
	{Name: "domainsExcluded blocks domain matching", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"domainsExcluded":["full:a.example"]}`,
		Need: needDomains, Verdict: protocol.SniffInsufficient, Reason: "domains_excluded"},
	{Name: "override is checked before domainsExcluded", Raw: `{"enabled":true,"destOverride":["http"],"domainsExcluded":["full:a.example"]}`,
		Need: needDomains, Verdict: protocol.SniffInsufficient, Reason: "dest_override_missing:tls"},

	{Name: "metadataOnly, domains", Raw: `{"enabled":true,"metadataOnly":true,"destOverride":["http","tls","quic"]}`, Need: needDomains,
		Verdict: protocol.SniffInsufficient, Reason: "metadata_only"},
	{Name: "metadataOnly, protocols", Raw: `{"enabled":true,"metadataOnly":true}`, Need: needProtocols,
		Verdict: protocol.SniffInsufficient, Reason: "metadata_only"},
	{Name: "metadataOnly is checked before override", Raw: `{"enabled":true,"metadataOnly":true}`, Need: needDomains,
		Verdict: protocol.SniffInsufficient, Reason: "metadata_only"},
	{Name: "metadataOnly while disabled still needs injection", Raw: `{"enabled":false,"metadataOnly":true}`, Need: needProtocols,
		Verdict: protocol.SniffInject, Reason: "sniffing_disabled"},

	{Name: "protocols need no destOverride", Raw: `{"enabled":true}`, Need: needProtocols, Verdict: protocol.SniffOK},
	{Name: "protocols ignore a narrow destOverride", Raw: `{"enabled":true,"destOverride":["http"]}`, Need: needProtocols, Verdict: protocol.SniffOK},
	{Name: "protocols ignore domainsExcluded", Raw: `{"enabled":true,"domainsExcluded":["full:a.example"]}`, Need: needProtocols, Verdict: protocol.SniffOK},
	{Name: "domains and protocols need the domain rules", Raw: `{"enabled":true,"destOverride":["http"]}`, Need: needDomains | needProtocols,
		Verdict: protocol.SniffInsufficient, Reason: "dest_override_missing:tls"},
	{Name: "domains and protocols, satisfied", Raw: `{"enabled":true,"destOverride":["http","tls","quic"]}`, Need: needDomains | needProtocols,
		Verdict: protocol.SniffOK},

	// --- SniffForResolvedIPs (IPOnDemand) --------------------------------------
	// Xray resolves the name the router sees. With routeOnly the sniffed name
	// replaces the real target for that resolution while the connection still
	// goes to the real address, so a fake SNI picks the addresses that are
	// judged. Sniffing that is off or metadata-only changes no target, and this
	// need asks the node to inject nothing.
	{Name: "resolve: absent", Raw: "", Need: needResolved, Verdict: protocol.SniffOK},
	{Name: "resolve: disabled", Raw: `{"enabled":false}`, Need: needResolved, Verdict: protocol.SniffOK},
	{Name: "resolve: enabled with routeOnly false", Raw: `{"enabled":true,"routeOnly":false}`, Need: needResolved, Verdict: protocol.SniffOK},
	{Name: "resolve: metadataOnly", Raw: `{"enabled":true,"metadataOnly":true}`, Need: needResolved, Verdict: protocol.SniffOK},
	{Name: "resolve: routeOnly", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}`, Need: needResolved,
		Verdict: protocol.SniffInsufficient, Reason: "route_only_resolve"},
	// With routeOnly, xray-core's dispatcher sets the route target only when
	// shouldOverride accepts a sniffed domain for a destOverride entry. An empty
	// list, or fakedns alone, never does (a fakedns result replaces the target
	// itself, not the route target), so nothing is substituted.
	{Name: "resolve: routeOnly with an empty override never sets a route target", Raw: `{"enabled":true,"routeOnly":true}`, Need: needResolved, Verdict: protocol.SniffOK},
	{Name: "resolve: routeOnly with an empty list", Raw: `{"enabled":true,"destOverride":[],"routeOnly":true}`, Need: needResolved, Verdict: protocol.SniffOK},
	{Name: "resolve: routeOnly with fakedns only", Raw: `{"enabled":true,"destOverride":["fakedns"],"routeOnly":true}`, Need: needResolved, Verdict: protocol.SniffOK},
	{Name: "resolve: routeOnly with fakedns and http", Raw: `{"enabled":true,"destOverride":["fakedns","http"],"routeOnly":true}`, Need: needResolved,
		Verdict: protocol.SniffInsufficient, Reason: "route_only_resolve"},
	{Name: "resolve: routeOnly with tls alone", Raw: `{"enabled":true,"destOverride":["tls"],"routeOnly":true}`, Need: needResolved,
		Verdict: protocol.SniffInsufficient, Reason: "route_only_resolve"},
	{Name: "resolve with domains: disabled is still injected", Raw: `{"enabled":false}`, Need: needResolved | needDomains,
		Verdict: protocol.SniffInject, Reason: "sniffing_disabled"},
	{Name: "resolve with domains: routeOnly keeps the domain reason", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}`,
		Need: needResolved | needDomains, Verdict: protocol.SniffInsufficient, Reason: "route_only"},
	{Name: "resolve with domains: satisfied", Raw: `{"enabled":true,"destOverride":["http","tls","quic"]}`, Need: needResolved | needDomains, Verdict: protocol.SniffOK},
	{Name: "resolve with protocols: metadataOnly is insufficient for the protocols", Raw: `{"enabled":true,"metadataOnly":true}`,
		Need: needResolved | needProtocols, Verdict: protocol.SniffInsufficient, Reason: "metadata_only"},
	{Name: "resolve with protocols: routeOnly", Raw: `{"enabled":true,"destOverride":["http"],"routeOnly":true}`, Need: needResolved | needProtocols,
		Verdict: protocol.SniffInsufficient, Reason: "route_only_resolve"},
	{Name: "resolve: malformed", Raw: `{"enabled":`, Need: needResolved, Malformed: true},

	{Name: "truncated json", Raw: `{"enabled":true`, Need: needDomains, Malformed: true},
	{Name: "array is not an object", Raw: `[]`, Need: needDomains, Malformed: true},
	{Name: "string is not an object", Raw: `"on"`, Need: needProtocols, Malformed: true},
	{Name: "enabled must be a boolean", Raw: `{"enabled":"yes"}`, Need: needDomains, Malformed: true},
	{Name: "destOverride must be a list or a string", Raw: `{"enabled":true,"destOverride":7}`, Need: needDomains, Malformed: true},
	{Name: "unknown destOverride entry", Raw: `{"enabled":true,"destOverride":["http","tls","quic","dns"]}`, Need: needDomains, Malformed: true},
	{Name: "unknown destOverride entry, protocols", Raw: `{"enabled":true,"destOverride":["bogus"]}`, Need: needProtocols, Malformed: true},
	{Name: "unknown destOverride entry while disabled", Raw: `{"enabled":false,"destOverride":["bogus"]}`, Need: needProtocols, Malformed: true},
	{Name: "empty destOverride string is an unknown entry", Raw: `{"enabled":true,"destOverride":""}`, Need: needDomains, Malformed: true},
	// Entries xray-core would refuse at load (infra/conf SniffingConfig.Build, via
	// geodata.ParseDomainRules and ParseIPRules) are malformed, not insufficient.
	// Whether a geosite or geoip file or code exists is not checked: that needs the
	// asset files.
	{Name: "domainsExcluded regexp that does not compile", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"domainsExcluded":["regexp:("]}`, Need: needDomains, Malformed: true},
	{Name: "domainsExcluded dotless with a dot", Raw: `{"enabled":true,"domainsExcluded":["dotless:a.b"]}`, Need: needProtocols, Malformed: true},
	{Name: "domainsExcluded geosite without a code", Raw: `{"enabled":true,"domainsExcluded":["geosite:"]}`, Need: needProtocols, Malformed: true},
	{Name: "domainsExcluded geosite with an empty attribute", Raw: `{"enabled":true,"domainsExcluded":["geosite:cn@"]}`, Need: needProtocols, Malformed: true},
	{Name: "domainsExcluded geosite with a doubled attribute marker", Raw: `{"enabled":true,"domainsExcluded":["geosite:cn@@x"]}`, Need: needProtocols, Malformed: true},
	{Name: "domainsExcluded ext without a code", Raw: `{"enabled":true,"domainsExcluded":["ext:mydomains.dat"]}`, Need: needProtocols, Malformed: true},
	{Name: "domainsExcluded ext without a file", Raw: `{"enabled":true,"domainsExcluded":["ext::cn"]}`, Need: needProtocols, Malformed: true},
	{Name: "ipsExcluded prefix too long", Raw: `{"enabled":true,"ipsExcluded":["10.0.0.0/33"]}`, Need: needProtocols, Malformed: true},
	{Name: "ipsExcluded v6 prefix too long", Raw: `{"enabled":true,"ipsExcluded":["::1/129"]}`, Need: needProtocols, Malformed: true},
	{Name: "ipsExcluded prefix is not a number", Raw: `{"enabled":true,"ipsExcluded":["10.0.0.0/x"]}`, Need: needProtocols, Malformed: true},
	{Name: "ipsExcluded is not an address", Raw: `{"enabled":true,"ipsExcluded":["example.com"]}`, Need: needProtocols, Malformed: true},
	{Name: "ipsExcluded geoip without a code", Raw: `{"enabled":true,"ipsExcluded":["geoip:"]}`, Need: needProtocols, Malformed: true},
	{Name: "ipsExcluded geoip with only a reverse marker", Raw: `{"enabled":true,"ipsExcluded":["geoip:!"]}`, Need: needProtocols, Malformed: true},
	{Name: "ipsExcluded ext without a code", Raw: `{"enabled":true,"ipsExcluded":["ext:geoip.dat"]}`, Need: needProtocols, Malformed: true},
	{Name: "domainsExcluded entries xray accepts", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"domainsExcluded":["geosite:cn@ads","ext:x.dat:cn","regexp:^a$","dotless:","dotless:corp","full:a.example","plain","keyword:k","domain:d"]}`,
		Need: needDomains, Verdict: protocol.SniffInsufficient, Reason: "domains_excluded"},
	{Name: "ipsExcluded entries xray accepts", Raw: `{"enabled":true,"destOverride":["http","tls","quic"],"ipsExcluded":["geoip:private","!geoip:cn","10.0.0.0/8","::1","1.2.3.4/","[::1]/128","ext-ip:x.dat:cn"]}`,
		Need: needDomains, Verdict: protocol.SniffInsufficient, Reason: "ips_excluded"},
	{Name: "malformed exclusions are refused even when the verdict would be an earlier one", Raw: `{"enabled":true,"destOverride":["http"],"domainsExcluded":["regexp:("]}`, Need: needDomains, Malformed: true},
	{Name: "trailing garbage", Raw: `{"enabled":true} x`, Need: needDomains, Malformed: true},
}

// DestinationMatchVector is one MatchDestination case. Steps, when set, pins
// the whole trace in order; otherwise only the outcome is pinned.
type DestinationMatchVector struct {
	Name        string
	Policy      *protocol.DestinationPolicy
	Input       protocol.MatchInput
	Verdict     protocol.MatchVerdict
	Terminated  string
	ExemptHit   bool
	Conditional bool
	Notes       []protocol.MatchNote
	Steps       []protocol.MatchStep
}

func policyOf(rules ...protocol.DestinationRule) *protocol.DestinationPolicy {
	return &protocol.DestinationPolicy{Rules: rules}
}

// onDemandOf is policyOf with Resolve set to on_demand.
func onDemandOf(rules ...protocol.DestinationRule) *protocol.DestinationPolicy {
	return &protocol.DestinationPolicy{Rules: rules, Resolve: protocol.ResolveOnDemand}
}

func hit(id, entry string) protocol.MatchStep {
	return protocol.MatchStep{RuleID: id, Result: protocol.StepHit, Entry: entry}
}

func step(id string, result protocol.MatchStepResult) protocol.MatchStep {
	return protocol.MatchStep{RuleID: id, Result: result}
}

// builtinStep is the node-internal trailing-dot rule's step.
func builtinStep(result protocol.MatchStepResult) protocol.MatchStep {
	return protocol.MatchStep{Builtin: protocol.BuiltinTrailingDot, Result: result}
}

func exemptStep(result protocol.MatchStepResult) protocol.MatchStep {
	return protocol.MatchStep{Exempt: true, Result: result}
}

var (
	blockExample = protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}}
	// blockOther is a block rule over domains the trailing-dot targets never
	// match, so what a vector shows is the builtin and not this rule.
	blockCIDR10 = protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"10.0.0.0/8"}}
	blockOther  = protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"full:other.example"}}
	usr1        = protocol.NewSubjectKey(1)
	usr2        = protocol.NewSubjectKey(2)
	lst1        = protocol.NewListenerKey(1)
	lst2        = protocol.NewListenerKey(2)
)

// DestinationMatchVectors cover every clause of the matching semantics. Each
// expected value is derived from the rule in the spec, never from a run.
var DestinationMatchVectors = []DestinationMatchVector{
	// --- domains ----------------------------------------------------------
	{Name: "domain suffix on label boundary", Policy: policyOf(blockExample),
		Input: protocol.MatchInput{Target: "www.example.com"}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{builtinStep("miss"), hit("p1", "domain:example.com")}},
	{Name: "domain matches itself", Policy: policyOf(blockExample),
		Input: protocol.MatchInput{Target: "example.com"}, Verdict: "block", Terminated: "p1"},
	// --- the trailing-dot builtin ----------------------------------------------
	// A host with a trailing dot is not normalised: every matcher sees it as
	// written, as xray-core's does. What closes the hole is a node-internal rule
	// between the exempt list and the block rules that blocks any such host.
	{Name: "trailing dot: domain does not match, the builtin blocks", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"domain:example.com"}}, blockOther),
		Input: protocol.MatchInput{Target: "www.example.com."}, Verdict: "block",
		Steps: []protocol.MatchStep{step("p1", "miss"), builtinStep("hit"), step("p2", "skipped")}},
	{Name: "trailing dot: full does not match, the builtin blocks", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:example.com"}}, blockOther),
		Input: protocol.MatchInput{Target: "example.com."}, Verdict: "block",
		Steps: []protocol.MatchStep{step("p1", "miss"), builtinStep("hit"), step("p2", "skipped")}},
	{Name: "trailing dot: anchored regexp does not match, the builtin blocks", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleAllow, Domains: []string{`regexp:^example\.com$`}}, blockOther),
		Input: protocol.MatchInput{Target: "example.com."}, Verdict: "block",
		Steps: []protocol.MatchStep{step("p1", "miss"), builtinStep("hit"), step("p2", "skipped")}},
	{Name: "trailing dot: keyword still matches the host as written", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"keyword:example"}}, blockOther),
		Input: protocol.MatchInput{Target: "example.com."}, Verdict: "allow", Terminated: "p1",
		Steps: []protocol.MatchStep{hit("p1", "keyword:example"), builtinStep("shadowed"), step("p2", "skipped")}},
	{Name: "trailing dot: unanchored regexp still matches the host as written", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleAllow, Domains: []string{`regexp:example\.com`}}, blockOther),
		Input: protocol.MatchInput{Target: "example.com."}, Verdict: "allow", Terminated: "p1"},
	{Name: "trailing dot: the builtin sits after the exempt list", Policy: &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{blockOther}, Exempt: []protocol.SubjectKey{usr1}},
		Input: protocol.MatchInput{Target: "x.example.", Subject: usr1}, Verdict: "allow", ExemptHit: true,
		Steps: []protocol.MatchStep{{Exempt: true, Result: "hit"}, builtinStep("shadowed"), step("p2", "skipped")}},
	{Name: "trailing dot: the builtin sits before block rules", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"keyword:example"}}),
		Input: protocol.MatchInput{Target: "example.com."}, Verdict: "block",
		Steps: []protocol.MatchStep{builtinStep("hit"), {RuleID: "p1", Result: "shadowed"}}},
	{Name: "trailing dot: two dots are blocked too", Policy: policyOf(blockOther),
		Input: protocol.MatchInput{Target: "example.com.."}, Verdict: "block"},
	{Name: "trailing dot: no builtin without a block rule over domains", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}),
		Input: protocol.MatchInput{Target: "example.com.", Port: 80}, Verdict: "default",
		Steps: []protocol.MatchStep{step("p1", "miss")}},
	{Name: "trailing dot: no builtin for an observe-only domain rule", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleObserve, Domains: []string{"full:other.example"}}),
		Input: protocol.MatchInput{Target: "example.com."}, Verdict: "default",
		Steps: []protocol.MatchStep{step("p1", "miss")}},
	{Name: "trailing dot: an address with a dot is a hostname", Policy: policyOf(blockOther),
		Input: protocol.MatchInput{Target: "10.0.0.1."}, Verdict: "block"},
	{Name: "trailing dot: an address is not touched", Policy: policyOf(blockOther),
		Input: protocol.MatchInput{Target: "10.0.0.1"}, Verdict: "default",
		Steps: []protocol.MatchStep{builtinStep("miss"), step("p2", "miss")}},
	{Name: "trailing dot: a host without one is not touched", Policy: policyOf(blockOther),
		Input: protocol.MatchInput{Target: "example.com"}, Verdict: "default",
		Steps: []protocol.MatchStep{builtinStep("miss"), step("p2", "miss")}},
	{Name: "uppercase host is lowercased, as xray-core's router does", Policy: policyOf(blockExample),
		Input: protocol.MatchInput{Target: "WWW.Example.COM"}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{builtinStep("miss"), hit("p1", "domain:example.com")}},
	{Name: "uppercase host with a trailing dot", Policy: policyOf(blockExample),
		Input: protocol.MatchInput{Target: "WWW.Example.COM."}, Verdict: "block"},
	{Name: "surrounding spaces are trimmed", Policy: policyOf(blockExample),
		Input: protocol.MatchInput{Target: "  www.example.com "}, Verdict: "block", Terminated: "p1"},
	{Name: "bracketed ipv6 target", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"fc00::/7"}}),
		Input: protocol.MatchInput{Target: "[fd00::1]"}, Verdict: "block", Terminated: "p1"},
	{Name: "ipv4 with a leading zero is a hostname", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"10.0.0.0/8"}}),
		Input: protocol.MatchInput{Target: "010.1.1.1"}, Verdict: "default", Notes: []protocol.MatchNote{protocol.NoteHostnameSkipsIPRules}},
	{Name: "brackets are stripped before the space trim, as xray-core does", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"fc00::/7"}}),
		Input: protocol.MatchInput{Target: " [fd00::1] "}, Verdict: "default", Notes: []protocol.MatchNote{protocol.NoteHostnameSkipsIPRules}},
	{Name: "spaces inside brackets are trimmed", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"fc00::/7"}}),
		Input: protocol.MatchInput{Target: "[ fd00::1 ]"}, Verdict: "block", Terminated: "p1"},
	{Name: "ipv6 with a zone is a hostname", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true}),
		Input: protocol.MatchInput{Target: "fe80::1%eth0"}, Verdict: "default", Notes: []protocol.MatchNote{protocol.NoteHostnameSkipsIPRules}},
	{Name: "network is case-insensitive", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Network: "tcp"}),
		Input: protocol.MatchInput{Target: "example.com", Port: 25, Network: "TCP"}, Verdict: "block", Terminated: "p1"},
	{Name: "unknown network value is untestable", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Network: "tcp"}),
		Input: protocol.MatchInput{Target: "example.com", Port: 25, Network: "icmp"}, Verdict: "default", Conditional: true,
		Steps: []protocol.MatchStep{step("p1", "untestable")}},
	{Name: "unknown network value does not affect a rule without network", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}),
		Input: protocol.MatchInput{Target: "example.com", Port: 25, Network: "icmp"}, Verdict: "block", Terminated: "p1"},
	{Name: "domain suffix not mid-label", Policy: policyOf(blockExample),
		Input: protocol.MatchInput{Target: "notexample.com"}, Verdict: "default",
		Steps: []protocol.MatchStep{builtinStep("miss"), step("p1", "miss")}},
	{Name: "full requires equality", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"full:example.com"}}),
		Input: protocol.MatchInput{Target: "www.example.com"}, Verdict: "default"},
	{Name: "full matches itself", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"full:example.com"}}),
		Input: protocol.MatchInput{Target: "example.com"}, Verdict: "block", Terminated: "p1"},
	{Name: "keyword is a substring", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"keyword:torr"}}),
		Input: protocol.MatchInput{Target: "mytorrent.net"}, Verdict: "block", Terminated: "p1"},
	{Name: "regexp is unanchored", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"regexp:ab+c"}}),
		Input: protocol.MatchInput{Target: "xxabbcyy.net"}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{builtinStep("miss"), hit("p1", "regexp:ab+c")}},
	{Name: "regexp anchors are the policy's own", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"regexp:^ab+c$"}}),
		Input: protocol.MatchInput{Target: "xxabbcyy.net"}, Verdict: "default"},

	// --- hostname versus address -------------------------------------------
	{Name: "hostname never matches cidrs", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"0.0.0.0/0"}}),
		Input: protocol.MatchInput{Target: "example.com"}, Verdict: "default",
		Notes: []protocol.MatchNote{protocol.NoteHostnameSkipsIPRules}, Steps: []protocol.MatchStep{step("p1", "miss")}},
	{Name: "ip matches cidrs", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"0.0.0.0/0"}}),
		Input: protocol.MatchInput{Target: "1.2.3.4"}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{hit("p1", "0.0.0.0/0")}},
	{Name: "hostname never matches private", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true}),
		Input: protocol.MatchInput{Target: "localhost"}, Verdict: "default",
		Notes: []protocol.MatchNote{protocol.NoteHostnameSkipsIPRules}, Steps: []protocol.MatchStep{step("p1", "miss")}},
	{Name: "hostname against private and cidr rules gets one note", Policy: policyOf(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"10.0.0.0/8"}},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Private: true}),
		Input: protocol.MatchInput{Target: "internal.example"}, Verdict: "default",
		Notes: []protocol.MatchNote{protocol.NoteHostnameSkipsIPRules}},
	{Name: "an address gets no hostname note", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true}),
		Input: protocol.MatchInput{Target: "8.8.8.8"}, Verdict: "default"},
	{Name: "a hostname that hits a domain rule gets no note", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock,
		Domains: []string{"full:a.example"}, CIDRs: []string{"10.0.0.0/8"}}),
		Input: protocol.MatchInput{Target: "a.example"}, Verdict: "block", Terminated: "p1"},
	{Name: "ip never matches domains", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"keyword:1"}}),
		Input: protocol.MatchInput{Target: "1.2.3.4"}, Verdict: "default"},
	{Name: "ipv4-mapped ipv6 is unmapped", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"10.0.0.0/8"}}),
		Input: protocol.MatchInput{Target: "::ffff:10.1.2.3"}, Verdict: "block", Terminated: "p1"},
	{Name: "ipv6 target against v4 cidr", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"10.0.0.0/8"}}),
		Input: protocol.MatchInput{Target: "2001:db8::1"}, Verdict: "default"},
	{Name: "domains and cidrs are alternatives, by host", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock,
		Domains: []string{"full:a.example"}, CIDRs: []string{"10.0.0.0/8"}}),
		Input: protocol.MatchInput{Target: "a.example"}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{builtinStep("miss"), hit("p1", "full:a.example")}},
	{Name: "domains and cidrs are alternatives, by ip", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock,
		Domains: []string{"full:a.example"}, CIDRs: []string{"10.0.0.0/8"}}),
		Input: protocol.MatchInput{Target: "10.9.9.9"}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{builtinStep("miss"), hit("p1", "10.0.0.0/8")}},

	// --- the private table ---------------------------------------------------
	{Name: "private table hit", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true}),
		Input: protocol.MatchInput{Target: "192.168.1.1"}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{hit("p1", "192.168.0.0/16")}},
	{Name: "private table hit, v6", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true}),
		Input: protocol.MatchInput{Target: "fd00::1"}, Verdict: "block", Terminated: "p1"},
	{Name: "private table includes multicast and reserved space", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true}),
		Input: protocol.MatchInput{Target: "239.1.1.1"}, Verdict: "block", Terminated: "p1"},
	{Name: "private table miss", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true}),
		Input: protocol.MatchInput{Target: "8.8.8.8"}, Verdict: "default"},
	{Name: "private table v6 boundary, loopback", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true}),
		Input: protocol.MatchInput{Target: "::1"}, Verdict: "block", Terminated: "p1"},
	{Name: "private table v6 boundary, ::2 is outside ::/127", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true}),
		Input: protocol.MatchInput{Target: "::2"}, Verdict: "default"},

	// --- untestable ----------------------------------------------------------
	{Name: "protocols are untestable", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}}),
		Input: protocol.MatchInput{Target: "example.com"}, Verdict: "default", Conditional: true,
		Steps: []protocol.MatchStep{step("p1", "untestable")}},
	{Name: "ports unknown is untestable", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}),
		Input: protocol.MatchInput{Target: "example.com"}, Verdict: "default", Conditional: true,
		Steps: []protocol.MatchStep{step("p1", "untestable")}},
	{Name: "inbound unknown is untestable", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock,
		Domains: []string{"full:a.example"}, Inbounds: []protocol.ListenerKey{lst1}}),
		Input: protocol.MatchInput{Target: "a.example"}, Verdict: "default", Conditional: true,
		Steps: []protocol.MatchStep{builtinStep("miss"), step("p1", "untestable")}},
	{Name: "source unknown is untestable", Policy: policyOf(protocol.DestinationRule{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"203.0.113.0/24"}}),
		Input: protocol.MatchInput{Target: "example.com"}, Verdict: "default", Conditional: true,
		Steps: []protocol.MatchStep{step("s1", "untestable")}},
	{Name: "network unknown is untestable", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Network: "tcp"}),
		Input: protocol.MatchInput{Target: "example.com", Port: 25}, Verdict: "default", Conditional: true,
		Steps: []protocol.MatchStep{step("p1", "untestable")}},
	{Name: "a definite miss beats an untestable field", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock,
		Domains: []string{"full:a.example"}, Ports: "25"}),
		Input: protocol.MatchInput{Target: "b.example"}, Verdict: "default",
		Steps: []protocol.MatchStep{builtinStep("miss"), step("p1", "miss")}},
	{Name: "conditional after untestable", Policy: policyOf(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}}),
		Input: protocol.MatchInput{Target: "www.example.com"}, Verdict: "block", Terminated: "p2", Conditional: true,
		Steps: []protocol.MatchStep{builtinStep("miss"), step("p1", "untestable"), hit("p2", "domain:example.com")}},

	// --- ports, network, fields ------------------------------------------------
	{Name: "port range", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25,6881-6889"}),
		Input: protocol.MatchInput{Target: "example.com", Port: 6885}, Verdict: "block", Terminated: "p1"},
	{Name: "port outside range", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25,6881-6889"}),
		Input: protocol.MatchInput{Target: "example.com", Port: 6890}, Verdict: "default"},
	{Name: "port list member", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25,6881-6889"}),
		Input: protocol.MatchInput{Target: "example.com", Port: 25}, Verdict: "block", Terminated: "p1"},
	{Name: "network mismatch", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Network: "tcp"}),
		Input: protocol.MatchInput{Target: "example.com", Port: 25, Network: "udp"}, Verdict: "default"},
	{Name: "network match", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Network: "tcp"}),
		Input: protocol.MatchInput{Target: "example.com", Port: 25, Network: "tcp"}, Verdict: "block", Terminated: "p1"},
	{Name: "fields are anded", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock,
		Domains: []string{"domain:example.com"}, Ports: "443", Network: "tcp"}),
		Input: protocol.MatchInput{Target: "example.com", Port: 80, Network: "tcp"}, Verdict: "default"},
	{Name: "fields are anded, all hold", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock,
		Domains: []string{"domain:example.com"}, Ports: "443", Network: "tcp"}),
		Input: protocol.MatchInput{Target: "example.com", Port: 443, Network: "tcp"}, Verdict: "block", Terminated: "p1"},
	{Name: "inbound scoping", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock,
		Domains: []string{"full:a.example"}, Inbounds: []protocol.ListenerKey{lst1}}),
		Input: protocol.MatchInput{Target: "a.example", Inbound: lst2}, Verdict: "default"},
	{Name: "inbound scoping, member", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock,
		Domains: []string{"full:a.example"}, Inbounds: []protocol.ListenerKey{lst1}}),
		Input: protocol.MatchInput{Target: "a.example", Inbound: lst1}, Verdict: "block", Terminated: "p1"},
	{Name: "source cidr hit", Policy: policyOf(protocol.DestinationRule{ID: "s1", Action: protocol.RuleBlock,
		SourceCIDRs: []string{"203.0.113.0/24"}, Inbounds: []protocol.ListenerKey{lst1}}),
		Input: protocol.MatchInput{Target: "anything.example", Source: "203.0.113.5", Inbound: lst1}, Verdict: "block", Terminated: "s1",
		Steps: []protocol.MatchStep{hit("s1", "203.0.113.0/24")}},
	{Name: "source cidr miss", Policy: policyOf(protocol.DestinationRule{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"203.0.113.0/24"}}),
		Input: protocol.MatchInput{Target: "anything.example", Source: "198.51.100.5"}, Verdict: "default"},

	// --- subjects --------------------------------------------------------------
	{Name: "subjects restrict the rule", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock,
		Domains: []string{"full:a.example"}, Subjects: []protocol.SubjectKey{usr1}}),
		Input: protocol.MatchInput{Target: "a.example", Subject: usr2}, Verdict: "default",
		Steps: []protocol.MatchStep{builtinStep("miss"), step("p1", "miss")}},
	{Name: "subject in the list hits", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock,
		Domains: []string{"full:a.example"}, Subjects: []protocol.SubjectKey{usr1}}),
		Input: protocol.MatchInput{Target: "a.example", Subject: usr1}, Verdict: "block", Terminated: "p1"},
	{Name: "unknown subject misses a subject-scoped rule", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock,
		Domains: []string{"full:a.example"}, Subjects: []protocol.SubjectKey{usr1}}),
		Input: protocol.MatchInput{Target: "a.example"}, Verdict: "default"},
	{Name: "empty subjects mean everyone", Policy: policyOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}),
		Input: protocol.MatchInput{Target: "example.com", Port: 25}, Verdict: "block", Terminated: "p1"},

	// --- phases, exempt, shadowing ---------------------------------------------
	{Name: "allow beats block", Policy: policyOf(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"domain:example.com"}},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}}),
		Input: protocol.MatchInput{Target: "example.com"}, Verdict: "allow", Terminated: "p1",
		Steps: []protocol.MatchStep{hit("p1", "domain:example.com"), builtinStep("skipped"), {RuleID: "p2", Result: "shadowed"}}},
	{Name: "exempt beats block", Policy: &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{blockExample}, Exempt: []protocol.SubjectKey{usr1}},
		Input: protocol.MatchInput{Target: "example.com", Subject: usr1}, Verdict: "allow", ExemptHit: true,
		Steps: []protocol.MatchStep{{Exempt: true, Result: "hit"}, builtinStep("skipped"), {RuleID: "p1", Result: "shadowed"}}},
	{Name: "exempt hit marks the result", Policy: &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{}, Exempt: []protocol.SubjectKey{usr1}},
		Input: protocol.MatchInput{Target: "example.com", Subject: usr1}, Verdict: "allow", ExemptHit: true,
		Steps: []protocol.MatchStep{{Exempt: true, Result: "hit"}}},
	{Name: "exempt miss for another subject", Policy: &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{blockExample}, Exempt: []protocol.SubjectKey{usr1}},
		Input: protocol.MatchInput{Target: "example.com", Subject: usr2}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{exemptStep("miss"), builtinStep("miss"), hit("p1", "domain:example.com")}},
	{Name: "exempt does not beat allow order", Policy: &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"domain:example.com"}},
			{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}}},
		Exempt: []protocol.SubjectKey{usr1}},
		Input: protocol.MatchInput{Target: "example.com", Subject: usr1}, Verdict: "allow", Terminated: "p1",
		Steps: []protocol.MatchStep{hit("p1", "domain:example.com"), {Exempt: true, Result: "shadowed"}, builtinStep("skipped"), {RuleID: "p2", Result: "shadowed"}}},
	{Name: "source deny runs first", Policy: &protocol.DestinationPolicy{
		Rules:  []protocol.DestinationRule{{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"203.0.113.0/24"}}},
		Exempt: []protocol.SubjectKey{usr1}},
		Input: protocol.MatchInput{Target: "example.com", Subject: usr1, Source: "203.0.113.9"}, Verdict: "block", Terminated: "s1",
		Steps: []protocol.MatchStep{hit("s1", "203.0.113.0/24"), {Exempt: true, Result: "shadowed"}}},
	{Name: "group allow after global block", Policy: policyOf(
		blockExample,
		protocol.DestinationRule{ID: "g1x1", Action: protocol.RuleAllow, Domains: []string{"full:example.com"}, Subjects: []protocol.SubjectKey{usr1}},
		protocol.DestinationRule{ID: "g1", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{usr1}, CatchAll: true}),
		Input: protocol.MatchInput{Target: "example.com", Subject: usr1}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{builtinStep("miss"), hit("p1", "domain:example.com"), {RuleID: "g1x1", Result: "shadowed"}, {RuleID: "g1", Result: "shadowed"}}},
	{Name: "group allow inside its own group", Policy: policyOf(
		protocol.DestinationRule{ID: "g1x1", Action: protocol.RuleAllow, Domains: []string{"full:a.example"}, Subjects: []protocol.SubjectKey{usr1}},
		protocol.DestinationRule{ID: "g1", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{usr1}, CatchAll: true}),
		Input: protocol.MatchInput{Target: "a.example", Subject: usr1}, Verdict: "allow", Terminated: "g1x1"},
	{Name: "catch-all group block", Policy: policyOf(
		protocol.DestinationRule{ID: "g1x1", Action: protocol.RuleAllow, Domains: []string{"full:a.example"}, Subjects: []protocol.SubjectKey{usr1}},
		protocol.DestinationRule{ID: "g1", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{usr1}, CatchAll: true}),
		Input: protocol.MatchInput{Target: "b.example", Subject: usr1}, Verdict: "block", Terminated: "g1",
		Steps: []protocol.MatchStep{step("g1x1", "miss"), hit("g1", "")}},
	{Name: "catch-all group ignores non-members", Policy: policyOf(
		protocol.DestinationRule{ID: "g1", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{usr1}, CatchAll: true}),
		Input: protocol.MatchInput{Target: "b.example", Subject: usr2}, Verdict: "default"},
	{Name: "observe is recorded and terminates", Policy: policyOf(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"full:a.example"}},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleObserve, Domains: []string{"domain:example.com"}}),
		Input: protocol.MatchInput{Target: "www.example.com"}, Verdict: "observe", Terminated: "p2",
		Steps: []protocol.MatchStep{builtinStep("miss"), step("p1", "miss"), hit("p2", "domain:example.com")}},
	{Name: "block beats observe", Policy: policyOf(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleObserve, Domains: []string{"domain:example.com"}}),
		Input: protocol.MatchInput{Target: "example.com"}, Verdict: "block", Terminated: "p1"},
	{Name: "later hit is shadowed", Policy: policyOf(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"keyword:example"}}),
		Input: protocol.MatchInput{Target: "example.com"}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{builtinStep("miss"), hit("p1", "domain:example.com"), {RuleID: "p2", Result: "shadowed"}}},
	{Name: "later miss is skipped", Policy: policyOf(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"full:other.example"}}),
		Input: protocol.MatchInput{Target: "example.com"}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{builtinStep("miss"), hit("p1", "domain:example.com"), {RuleID: "p2", Result: "skipped"}}},
	{Name: "later untestable is skipped", Policy: policyOf(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Ports: "25"}),
		Input: protocol.MatchInput{Target: "example.com"}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{builtinStep("miss"), hit("p1", "domain:example.com"), {RuleID: "p2", Result: "skipped"}}},
	{Name: "default when nothing hits", Policy: policyOf(blockExample),
		Input: protocol.MatchInput{Target: "other.net"}, Verdict: "default",
		Steps: []protocol.MatchStep{builtinStep("miss"), step("p1", "miss")}},
	{Name: "nil policy is the default", Policy: nil,
		Input: protocol.MatchInput{Target: "other.net"}, Verdict: "default"},

	// --- Resolve: on_demand ------------------------------------------------------
	// Under on_demand the core resolves a hostname the first time a rule asks for
	// its addresses, so the CIDR and Private alternatives of a rule are tried on
	// the resolved addresses (any one is enough), in rule order. The result is the
	// reference answer with those addresses as input. Resolved nil means the
	// caller has none, which makes those alternatives untestable; Resolved empty
	// means the lookup came back with nothing.
	{Name: "on_demand: a resolved address in a blocked cidr blocks the hostname", Policy: onDemandOf(blockCIDR10),
		Input: protocol.MatchInput{Target: "a.example", Resolved: []string{"10.1.1.1"}}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{hit("p1", "10.0.0.0/8")}},
	{Name: "on_demand: any resolved address is enough", Policy: onDemandOf(blockCIDR10),
		Input: protocol.MatchInput{Target: "a.example", Resolved: []string{"8.8.8.8", "10.1.1.1"}}, Verdict: "block", Terminated: "p1"},
	{Name: "on_demand: private table on a resolved address", Policy: onDemandOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true}),
		Input: protocol.MatchInput{Target: "a.example", Resolved: []string{"127.0.0.1"}}, Verdict: "block", Terminated: "p1",
		Steps: []protocol.MatchStep{hit("p1", "127.0.0.0/8")}},
	{Name: "on_demand: resolved addresses that miss", Policy: onDemandOf(blockCIDR10),
		Input: protocol.MatchInput{Target: "a.example", Resolved: []string{"8.8.8.8"}}, Verdict: "default",
		Steps: []protocol.MatchStep{step("p1", "miss")}},
	{Name: "on_demand: an allow on a resolved cidr precedes a block", Policy: onDemandOf(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleAllow, CIDRs: []string{"8.8.8.0/24"}},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Private: true}),
		Input: protocol.MatchInput{Target: "a.example", Resolved: []string{"8.8.8.8"}}, Verdict: "allow", Terminated: "p1",
		Steps: []protocol.MatchStep{hit("p1", "8.8.8.0/24"), step("p2", "skipped")}},
	{Name: "on_demand: observe on a resolved range is recorded", Policy: onDemandOf(protocol.DestinationRule{ID: "p1", Action: protocol.RuleObserve, CIDRs: []string{"10.0.0.0/8"}}),
		Input: protocol.MatchInput{Target: "a.example", Resolved: []string{"10.1.1.1"}}, Verdict: "observe", Terminated: "p1"},
	{Name: "on_demand: no resolution given makes the ip rule untestable", Policy: onDemandOf(blockCIDR10),
		Input: protocol.MatchInput{Target: "a.example"}, Verdict: "default", Conditional: true,
		Notes: []protocol.MatchNote{protocol.NoteHostnameNeedsResolution},
		Steps: []protocol.MatchStep{step("p1", "untestable")}},
	{Name: "on_demand: an untestable ip rule does not stop a later domain rule", Policy: onDemandOf(blockCIDR10,
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"full:a.example"}}),
		Input: protocol.MatchInput{Target: "a.example"}, Verdict: "block", Terminated: "p2", Conditional: true,
		Notes: []protocol.MatchNote{protocol.NoteHostnameNeedsResolution},
		Steps: []protocol.MatchStep{builtinStep("miss"), step("p1", "untestable"), hit("p2", "full:a.example")}},
	{Name: "on_demand: the domain alternative of a rule hits without resolution", Policy: onDemandOf(protocol.DestinationRule{
		ID: "p1", Action: protocol.RuleBlock, Domains: []string{"full:a.example"}, CIDRs: []string{"10.0.0.0/8"}}),
		Input: protocol.MatchInput{Target: "a.example"}, Verdict: "block", Terminated: "p1"},
	{Name: "on_demand: an empty resolution misses and is engine dependent", Policy: onDemandOf(blockCIDR10),
		Input: protocol.MatchInput{Target: "nx.example", Resolved: []string{}}, Verdict: "default",
		Notes: []protocol.MatchNote{protocol.NoteResolutionFailedEngineDependent},
		Steps: []protocol.MatchStep{step("p1", "miss")}},
	{Name: "on_demand: an address target is matched as it is", Policy: onDemandOf(blockCIDR10),
		Input: protocol.MatchInput{Target: "10.1.1.1", Resolved: []string{"8.8.8.8"}}, Verdict: "block", Terminated: "p1"},
	{Name: "as_is: resolved addresses are ignored", Policy: policyOf(blockCIDR10),
		Input: protocol.MatchInput{Target: "a.example", Resolved: []string{"10.1.1.1"}}, Verdict: "default",
		Notes: []protocol.MatchNote{protocol.NoteHostnameSkipsIPRules},
		Steps: []protocol.MatchStep{step("p1", "miss")}},
}
