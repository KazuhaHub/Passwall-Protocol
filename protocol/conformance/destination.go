package conformance

import (
	"encoding/json"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// DestinationMatchVector pins pure destination preview semantics shared by PSP
// and Node. Input policies are already canonical; no DNS or IDNA library runs.
type DestinationMatchVector struct {
	Name    string
	Policy  *protocol.DestinationPolicy
	Subject protocol.SubjectKey
	Target  string
	Port    uint16
	Network string
	Want    protocol.MatchResult
}

func matchPolicy(rules ...protocol.DestinationRule) *protocol.DestinationPolicy {
	return &protocol.DestinationPolicy{Rules: rules}
}
func previewStep(id string, action protocol.RuleAction, result string) protocol.MatchStep {
	return protocol.MatchStep{RuleID: id, Action: action, Result: result}
}
func preview(verdict string, steps ...protocol.MatchStep) protocol.MatchResult {
	return protocol.MatchResult{Verdict: verdict, Steps: steps}
}

// DestinationMatchVectors are test data, never templates for live provisioning.
var DestinationMatchVectors = []DestinationMatchVector{
	{Name: "nil policy", Target: "example.com", Port: 443, Network: "tcp", Want: preview("direct", previewStep("psp-exempt", protocol.RuleAllow, "n/a"), previewStep("", protocol.RuleAllow, "hit"))},
	{Name: "allow before exempt and block", Policy: &protocol.DestinationPolicy{Exempt: []protocol.SubjectKey{"usr_1"}, Rules: []protocol.DestinationRule{{ID: "p9", Action: protocol.RuleAllow, Domains: []string{"domain:example.com"}}, {ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}}}}, Subject: "usr_1", Target: "www.example.com", Port: 443, Network: "tcp", Want: preview("allow", previewStep("p9", protocol.RuleAllow, "hit"), previewStep("psp-exempt", protocol.RuleAllow, "shadowed"), previewStep("p1", protocol.RuleBlock, "shadowed"), previewStep("", protocol.RuleAllow, "skipped"))},
	{Name: "exemption precedes block", Policy: &protocol.DestinationPolicy{Exempt: []protocol.SubjectKey{"usr_1"}, Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Private: true}}}, Subject: "usr_1", Target: "169.254.169.254", Port: 80, Network: "tcp", Want: preview("exempt", previewStep("psp-exempt", protocol.RuleAllow, "hit"), previewStep("p1", protocol.RuleBlock, "shadowed"), previewStep("", protocol.RuleAllow, "skipped"))},
	{Name: "domain label boundary", Policy: matchPolicy(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}}), Target: "badexample.com", Port: 443, Network: "tcp", Want: preview("direct", previewStep("psp-exempt", protocol.RuleAllow, "n/a"), previewStep("p1", protocol.RuleBlock, "miss"), previewStep("", protocol.RuleAllow, "hit"))},
	{Name: "unanchored regex", Policy: matchPolicy(protocol.DestinationRule{ID: "p1", Action: protocol.RuleObserve, Domains: []string{"regexp:example"}}), Target: "www.example.com", Port: 443, Network: "tcp", Want: preview("observe", previewStep("psp-exempt", protocol.RuleAllow, "n/a"), previewStep("p1", protocol.RuleObserve, "hit"), previewStep("", protocol.RuleAllow, "skipped"))},
	{Name: "no DNS for literal rule", Policy: matchPolicy(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"169.254.0.0/16"}, Private: true}), Target: "169.254.169.254.nip.io", Port: 80, Network: "tcp", Want: preview("direct", previewStep("psp-exempt", protocol.RuleAllow, "n/a"), previewStep("p1", protocol.RuleBlock, "miss"), previewStep("", protocol.RuleAllow, "hit"))},
	{Name: "scope must not widen", Policy: matchPolicy(protocol.DestinationRule{ID: "g1", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{"usr_1"}, CatchAll: true}), Subject: "usr_2", Target: "example.com", Port: 443, Network: "tcp", Want: preview("direct", previewStep("psp-exempt", protocol.RuleAllow, "n/a"), previewStep("g1", protocol.RuleBlock, "n/a"), previewStep("", protocol.RuleAllow, "hit"))},
	{Name: "whitelist blocks before global observe", Policy: matchPolicy(protocol.DestinationRule{ID: "g1", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{"usr_1"}, CatchAll: true}, protocol.DestinationRule{ID: "p1", Action: protocol.RuleObserve, Domains: []string{"domain:example.com"}}), Subject: "usr_1", Target: "example.com", Port: 443, Network: "tcp", Want: preview("block", previewStep("psp-exempt", protocol.RuleAllow, "n/a"), previewStep("g1", protocol.RuleBlock, "hit"), previewStep("p1", protocol.RuleObserve, "shadowed"), previewStep("", protocol.RuleAllow, "skipped"))},
	{Name: "protocol cannot promise direct", Policy: matchPolicy(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}}), Target: "example.com", Port: 443, Network: "tcp", Want: preview("untestable", previewStep("psp-exempt", protocol.RuleAllow, "n/a"), previewStep("p1", protocol.RuleBlock, "untestable"), previewStep("", protocol.RuleAllow, "hit"))},
}

// SniffingVector describes Xray preflight only. Disabled or absent sniffing can
// be safely injected; enabled but insufficient sniffing must not be rewritten.
type SniffingVector struct {
	Name       string
	Sniffing   json.RawMessage
	Sufficient bool
	Inject     bool
	Reason     string
}

var SniffingVectors = []SniffingVector{
	{Name: "absent", Sufficient: true, Inject: true},
	{Name: "disabled", Sniffing: json.RawMessage(`{"enabled":false}`), Sufficient: true, Inject: true},
	{Name: "complete route-only", Sniffing: json.RawMessage(`{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}`), Sufficient: true},
	{Name: "PSP default", Sniffing: json.RawMessage(`{"enabled":true,"destOverride":["http","tls","quic","fakedns"],"routeOnly":false}`), Sufficient: true},
	{Name: "metadata-only", Sniffing: json.RawMessage(`{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":true}`), Reason: "metadata_only"},
	{Name: "missing QUIC", Sniffing: json.RawMessage(`{"enabled":true,"destOverride":["http","tls"]}`), Reason: "missing_dest_override"},
	{Name: "excluded domains", Sniffing: json.RawMessage(`{"enabled":true,"destOverride":["http","tls","quic"],"domainsExcluded":["example.com"]}`), Reason: "domains_excluded"},
	{Name: "invalid object", Sniffing: json.RawMessage(`[]`), Reason: "invalid_config"},
}
