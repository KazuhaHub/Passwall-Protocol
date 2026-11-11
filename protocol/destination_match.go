package protocol

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// MatchStep is preview evidence, including rules shadowed by an earlier match.
// Result is hit/miss/n/a/shadowed/skipped/untestable. The implicit exemption
// step has RuleID "psp-exempt"; the final direct fallback has an empty RuleID.
type MatchStep struct {
	RuleID string     `json:"rule_id,omitempty"`
	Action RuleAction `json:"action,omitempty"`
	Result string     `json:"result"`
}

// MatchResult is a destination-only preview, never proof about a real packet.
// Verdict is allow/block/observe/exempt/direct, invalid, or untestable when an
// applicable earlier protocol rule could change the result. No DNS is queried.
type MatchResult struct {
	Steps   []MatchStep `json:"steps"`
	Verdict string      `json:"verdict"`
}

// MatchDestination evaluates the producer's rule order and inserts the exempt
// step after leading global allow rules. It evaluates later rules for trace
// evidence without allowing them to replace the first terminal match.
func MatchDestination(p *DestinationPolicy, subject SubjectKey, target string, port uint16, network string) MatchResult {
	result := MatchResult{Verdict: "direct", Steps: []MatchStep{}}
	if err := ValidateDestinationPolicy(p); err != nil {
		result.Verdict = "invalid"
		return result
	}
	if subject != "" {
		if _, err := subject.RowID(); err != nil {
			result.Verdict = "invalid"
			return result
		}
	}
	target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	addr, addrErr := netip.ParseAddr(target)
	if addrErr != nil && !canonicalDestinationHostname(target) || port == 0 || network != "tcp" && network != "udp" {
		result.Verdict = "invalid"
		return result
	}
	terminal, exemptionAdded, uncertain := false, false, false
	addExemption := func() {
		step := MatchStep{RuleID: "psp-exempt", Action: RuleAllow, Result: "n/a"}
		matched := p != nil && subject != "" && containsPolicySubject(p.Exempt, subject)
		if terminal {
			step.Result = "skipped"
			if matched {
				step.Result = "shadowed"
			}
		} else if matched {
			step.Result = "hit"
			terminal = true
			result.Verdict = "exempt"
		}
		result.Steps = append(result.Steps, step)
		exemptionAdded = true
	}
	if p != nil {
		for _, rule := range p.Rules {
			if !exemptionAdded && !(rule.Action == RuleAllow && strings.HasPrefix(rule.ID, "p")) {
				addExemption()
			}
			matched, unknown, applicable := matchDestinationRule(rule, subject, target, addr, port, network)
			step := MatchStep{RuleID: rule.ID, Action: rule.Action, Result: "miss"}
			switch {
			case unknown:
				step.Result = "untestable"
				if !terminal {
					uncertain = true
				}
			case terminal:
				step.Result = "skipped"
				if matched {
					step.Result = "shadowed"
				}
			case !applicable:
				step.Result = "n/a"
			case matched:
				step.Result = "hit"
				terminal = true
				result.Verdict = string(rule.Action)
			}
			result.Steps = append(result.Steps, step)
		}
	}
	if !exemptionAdded {
		addExemption()
	}
	fallback := MatchStep{Action: RuleAllow, Result: "hit"}
	if terminal {
		fallback.Result = "skipped"
	}
	result.Steps = append(result.Steps, fallback)
	if uncertain {
		result.Verdict = "untestable"
	}
	return result
}

func containsPolicySubject(values []SubjectKey, subject SubjectKey) bool {
	for _, value := range values {
		if value == subject {
			return true
		}
	}
	return false
}

func matchDestinationRule(r DestinationRule, subject SubjectKey, target string, addr netip.Addr, port uint16, network string) (matched, unknown, applicable bool) {
	if len(r.Subjects) > 0 && (subject == "" || !containsPolicySubject(r.Subjects, subject)) {
		return false, false, false
	}
	if r.Network != "" && r.Network != network || r.Ports != "" && !matchDestinationPort(r.Ports, port) {
		return false, false, true
	}
	if len(r.Domains) > 0 || len(r.CIDRs) > 0 || r.Private {
		addressMatch := false
		if addr.IsValid() {
			for _, raw := range r.CIDRs {
				prefix, _ := netip.ParsePrefix(raw)
				if prefix.Contains(addr) {
					addressMatch = true
					break
				}
			}
			if r.Private && privateDestination(addr) {
				addressMatch = true
			}
		} else {
			for _, entry := range r.Domains {
				kind, value, _ := strings.Cut(entry, ":")
				switch kind {
				case "domain":
					addressMatch = target == value || strings.HasSuffix(target, "."+value)
				case "full":
					addressMatch = target == value
				case "keyword":
					addressMatch = strings.Contains(target, value)
				case "regexp":
					addressMatch, _ = regexp.MatchString(value, target)
				}
				if addressMatch {
					break
				}
			}
		}
		if !addressMatch {
			return false, false, true
		}
	}
	if len(r.Protocols) > 0 {
		return false, true, true
	}
	return true, false, true
}

func matchDestinationPort(spec string, port uint16) bool {
	for _, part := range strings.Split(spec, ",") {
		left, right, isRange := strings.Cut(part, "-")
		low, _ := strconv.Atoi(left)
		high := low
		if isRange {
			high, _ = strconv.Atoi(right)
		}
		if int(port) >= low && int(port) <= high {
			return true
		}
	}
	return false
}

// The Xray private/reserved set is intentionally broader than Addr.IsPrivate.
// It is a literal-target preview only: DNS answers are never evaluated here.
var privateDestinationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/3"), netip.MustParsePrefix("::/127"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

func privateDestination(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range privateDestinationPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
