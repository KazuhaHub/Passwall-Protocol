package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SniffNeed is what a policy needs the core's sniffer to provide.
type SniffNeed int

const (
	// SniffForDomains: the policy has domain rules, which match the sniffed
	// host of a connection made to an IP.
	SniffForDomains SniffNeed = 1 << iota
	// SniffForProtocols: the policy has protocol rules (bittorrent).
	SniffForProtocols
	// SniffForResolvedIPs: the policy resolves hostnames at routing time
	// (DestinationPolicy.Resolve is ResolveOnDemand) and has IP rules, so the
	// name the router resolves must be the name the connection goes to. It asks
	// for nothing to be turned on, and sniffing that is off or metadata-only is
	// fine (metadataOnly runs only the fakedns sniffer, which replaces the
	// target itself, so the name judged is the name reached). What it refuses is
	// a sniffed name used for routing only, while the connection goes to the
	// requested address; see CheckXraySniffing.
	SniffForResolvedIPs
)

// SniffVerdict is CheckXraySniffing's answer.
type SniffVerdict string

const (
	// SniffInject: sniffing is off on this inbound, and the node may turn it on.
	// What it injects is {"enabled":true,"destOverride":["http","tls","quic"],
	// "routeOnly":false}. routeOnly is false because a policy that matches on
	// the sniffed host while the connection still goes to the requested address
	// can be bypassed with a fake SNI or Host header; with it false the
	// connection goes where the sniffed host says, so what is blocked is what
	// is reached.
	SniffInject SniffVerdict = "inject"
	// SniffOK: the inbound's own sniffing already supplies what is needed.
	SniffOK SniffVerdict = "ok"
	// SniffInsufficient: sniffing is on but configured so that it cannot supply
	// it, and the operator's setting is not the node's to override.
	SniffInsufficient SniffVerdict = "insufficient"
)

// XraySniffingInjection is the "sniffing" object a node writes into an inbound
// whose verdict is SniffInject, verbatim: it is the one shape CheckXraySniffing
// calls sufficient without further conditions, so a node that wrote anything
// else could pass the check and fail the policy.
//
// ROUTEONLY IS FALSE, AND THAT HAS A CONSEQUENCE. With it false, xray-core
// substitutes the sniffed host for the connection's destination, so the core
// CONNECTS to the sniffed host (resolving it itself) instead of the address the
// client asked for. Enabling it therefore re-routes traffic on an inbound that
// had sniffing off, for any client whose connection carries a recognisable
// host: a connection to an IP with an SNI that points elsewhere now goes to the
// SNI. That is what makes a domain rule mean what it says (the host blocked is
// the host reached), and it is the reason routeOnly true is reported as
// insufficient rather than injected.
func XraySniffingInjection() string {
	return `{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":false}`
}

// xraySniffing is the part of an inbound's "sniffing" object that decides what
// the sniffer can supply. Unknown keys are ignored.
type xraySniffing struct {
	Enabled         bool       `json:"enabled"`
	MetadataOnly    bool       `json:"metadataOnly"`
	DestOverride    stringList `json:"destOverride"`
	DomainsExcluded stringList `json:"domainsExcluded"`
	IPsExcluded     stringList `json:"ipsExcluded"`
	RouteOnly       bool       `json:"routeOnly"`
}

// stringList mirrors StringList in xray-core's infra/conf/common.go, and the
// alias and case handling in CheckXraySniffing mirrors SniffingConfig.Build in
// infra/conf/xray.go (both read at v1.260327.1-0.20260711155151-50231eaff98c).
// It reads a list the way xray-core's StringList does: a JSON array, or
// one string holding comma-separated entries. An operator's config can use
// either, so a check that read only arrays would call a working config
// insufficient.
type stringList []string

func (list *stringList) UnmarshalJSON(data []byte) error {
	var array []string
	if err := json.Unmarshal(data, &array); err == nil {
		*list = array
		return nil
	}
	var joined string
	if err := json.Unmarshal(data, &joined); err == nil {
		*list = strings.Split(joined, ",")
		return nil
	}
	return fmt.Errorf("unknown format of a string list: %s", data)
}

// CheckXraySniffing inspects an Xray inbound's "sniffing" object (raw JSON;
// empty or null means absent, which is disabled) against what a policy needs.
// The reason is a stable token for the report; the error is for malformed JSON,
// which a node must treat as a refusal rather than guess at.
//
// The rules follow xray-core's dispatcher: content.Protocol is set whenever
// sniffing is enabled and a sniffer matched, independent of destOverride; with
// metadataOnly only the fakedns sniffer runs; the bittorrent and utp sniffers
// are always registered. Domains are different: a domain rule can match only a
// host the core actually substitutes, which takes destOverride to include every
// protocol the client might speak (http, tls, quic), no excluded domains or
// addresses, and routeOnly off, since a host used only for routing lets a fake
// SNI or Host header past a block.
//
// IF THE VERDICT IS SniffInject, the node writes XraySniffingInjection(), which
// sets routeOnly false: the core then connects to the sniffed host instead of
// the requested address, which changes where that inbound's traffic goes.
//
// The parsing mirrors xray-core's infra/conf (see stringList), including that
// an unknown destOverride entry makes the config unloadable, which is an error
// here rather than a verdict.
func CheckXraySniffing(raw []byte, need SniffNeed) (SniffVerdict, string, error) {
	if need == 0 {
		return SniffOK, "", nil
	}
	var sniffing xraySniffing
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 {
		if err := json.Unmarshal(trimmed, &sniffing); err != nil {
			return "", "", fmt.Errorf("sniffing: %w", err)
		}
	}
	// xray-core refuses a config with an unknown destOverride entry, enabled or
	// not, so a node holding one has a config that cannot load. That is a
	// malformed input, not an insufficient one.
	for _, entry := range sniffing.DestOverride {
		switch strings.ToLower(entry) {
		case "http", "tls", "https", "ssl", "quic", "fakedns", "fakedns+others":
		default:
			return "", "", fmt.Errorf("sniffing: unknown destOverride entry %q", entry)
		}
	}
	if err := validateXrayExclusions(sniffing); err != nil {
		return "", "", err
	}
	// SniffForResolvedIPs alone asks only that no sniffed name stands in for the
	// real target while the connection goes elsewhere. Sniffing that is off or
	// metadata-only never does, so there is nothing to inject and nothing to
	// refuse, and only routeOnly is insufficient.
	resolveOnly := need&^SniffForResolvedIPs == 0
	if !sniffing.Enabled {
		if resolveOnly {
			return SniffOK, "", nil
		}
		return SniffInject, "sniffing_disabled", nil
	}
	if sniffing.MetadataOnly {
		if resolveOnly {
			return SniffOK, "", nil
		}
		return SniffInsufficient, "metadata_only", nil
	}
	if need&SniffForDomains == 0 {
		// Only the resolved-address need can still fail here, and only on
		// routeOnly: with it, the router resolves the sniffed name while the
		// connection goes to the requested address, so a fake SNI chooses which
		// addresses the IP rules judge (xray-core features/routing/dns/context.go
		// prefers the domain over the real IP). It only happens if some destOverride
		// entry can accept a sniffed domain: see routesSniffedName.
		if need&SniffForResolvedIPs != 0 && sniffing.RouteOnly && routesSniffedName(sniffing.DestOverride) {
			return SniffInsufficient, "route_only_resolve", nil
		}
		return SniffOK, "", nil
	}
	have := make(map[string]bool, len(sniffing.DestOverride))
	for _, entry := range sniffing.DestOverride {
		// xray-core lowercases the entry and accepts https and ssl for tls.
		switch name := strings.ToLower(entry); name {
		case "https", "ssl":
			have["tls"] = true
		default:
			have[name] = true
		}
	}
	for _, want := range []string{"http", "tls", "quic"} {
		if !have[want] {
			return SniffInsufficient, "dest_override_missing:" + want, nil
		}
	}
	if len(sniffing.DomainsExcluded) > 0 {
		return SniffInsufficient, "domains_excluded", nil
	}
	// ipsExcluded skips substitution for connections to those addresses, which
	// is the same hole as domainsExcluded from the other side.
	if len(sniffing.IPsExcluded) > 0 {
		return SniffInsufficient, "ips_excluded", nil
	}
	// routeOnly keeps the sniffed host for routing while connecting to the
	// requested address, so a fake SNI or Host header gets a blocked host
	// "routed" to an allowed one. It does not matter to protocol rules, which
	// read the sniffed protocol and not a host.
	if sniffing.RouteOnly {
		return SniffInsufficient, "route_only", nil
	}
	return SniffOK, "", nil
}

// validateXrayExclusions refuses the exclusion entries xray-core would refuse at
// load, the way SniffingConfig.Build does through geodata.ParseDomainRules and
// ParseIPRules (common/geodata/rule_parser.go) and the matcher that compiles the
// result (common/geodata/domain_matcher.go), all read at
// v1.260327.1-0.20260711155151-50231eaff98c.
//
// WHAT IS NOT CHECKED: that a geosite or geoip file exists and holds the code
// (checkFile opens the asset and searches it). That needs the asset files, which
// a stdlib module that does no I/O cannot have, and which the node's own core
// will check when it loads the config. A rule that passes here can still fail
// there for that reason alone.
func validateXrayExclusions(sniffing xraySniffing) error {
	for _, rule := range sniffing.DomainsExcluded {
		if err := validateXrayDomainRule(rule); err != nil {
			return fmt.Errorf("sniffing: illegal domainsExcluded entry %q: %w", rule, err)
		}
	}
	for _, rule := range sniffing.IPsExcluded {
		if err := validateXrayIPRule(rule); err != nil {
			return fmt.Errorf("sniffing: illegal ipsExcluded entry %q: %w", rule, err)
		}
	}
	return nil
}

func validateXrayDomainRule(rule string) error {
	if rest, ok := strings.CutPrefix(rule, "geosite:"); ok {
		return validateXrayGeoRule("geosite.dat:"+rest, true)
	}
	for _, prefix := range [...]string{"ext:", "ext-domain:", "ext-site:"} {
		if rest, ok := strings.CutPrefix(rule, prefix); ok {
			return validateXrayGeoRule(rest, true)
		}
	}
	switch {
	case strings.HasPrefix(rule, "regexp:"):
		_, err := regexp.Compile(rule[len("regexp:"):])
		return err
	case strings.HasPrefix(rule, "dotless:"):
		// The rule is turned into a regexp, and a substring containing a dot is
		// refused outright.
		var pattern string
		switch substr := rule[len("dotless:"):]; {
		case substr == "":
			pattern = "^[^.]*$"
		case !strings.Contains(substr, "."):
			pattern = "^[^.]*" + substr + "[^.]*$"
		default:
			return fmt.Errorf("substr in dotless rule should not contain a dot")
		}
		_, err := regexp.Compile(pattern)
		return err
	}
	// domain:, full:, keyword: and a bare entry are taken as written.
	return nil
}

// validateXrayGeoRule checks the shape of "<file>:<code>[@attrs]" (for domains)
// or "<file>:<code>" (for addresses), which is all that can be known without the
// asset.
func validateXrayGeoRule(rule string, domains bool) error {
	file, code, ok := strings.Cut(rule, ":")
	if !ok {
		return fmt.Errorf("syntax error")
	}
	if file == "" {
		return fmt.Errorf("empty file")
	}
	if domains {
		if strings.HasSuffix(code, "@") || strings.Contains(code, "@@") {
			return fmt.Errorf("empty attr")
		}
		code, _, _ = strings.Cut(code, "@")
	} else {
		code = strings.TrimLeft(code, "!")
	}
	if code == "" {
		return fmt.Errorf("empty code")
	}
	return nil
}

func validateXrayIPRule(rule string) error {
	rule = strings.TrimLeft(rule, "!")
	if rest, ok := strings.CutPrefix(rule, "geoip:"); ok {
		return validateXrayGeoRule("geoip.dat:"+rest, false)
	}
	for _, prefix := range [...]string{"ext:", "ext-ip:"} {
		if rest, ok := strings.CutPrefix(rule, prefix); ok {
			return validateXrayGeoRule(rest, false)
		}
	}
	ip, prefix, _ := strings.Cut(rule, "/")
	addr, _, ok := parseAddress(ip)
	if !ok {
		return fmt.Errorf("unsupported address family")
	}
	max := 128
	if addr.Is4() {
		max = 32
	}
	if prefix != "" {
		bits, err := strconv.ParseUint(prefix, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid CIDR prefix length %q", prefix)
		}
		if bits > uint64(max) {
			return fmt.Errorf("CIDR prefix length %d exceeds max %d", bits, max)
		}
	}
	return nil
}

// routesSniffedName is whether routeOnly can put a sniffed name into the route
// target. In xray-core's dispatcher (app/dispatcher/default.go) the route target
// is set only after shouldOverride accepts a sniffed domain for one of the
// destOverride entries, and only when the result's protocol is not fakedns; a
// fakedns result replaces the target itself instead. An empty list accepts
// nothing. infra/conf/xray.go maps both "fakedns" and "fakedns+others" to the
// runtime protocol "fakedns", and the dispatcher excludes "fakedns+others" from
// the route-target branch too, so neither of them can. Any other entry (http,
// tls, quic) can.
func routesSniffedName(override stringList) bool {
	for _, entry := range override {
		switch strings.ToLower(entry) {
		case "fakedns", "fakedns+others":
		default:
			return true
		}
	}
	return false
}
