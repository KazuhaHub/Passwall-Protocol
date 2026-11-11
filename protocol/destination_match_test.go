package protocol

import "testing"

func TestDestinationMatchFieldsAndScope(t *testing.T) {
	for _, v := range []struct {
		name    string
		rule    DestinationRule
		subject SubjectKey
		target  string
		port    uint16
		network string
		want    string
	}{
		{"full exact", DestinationRule{Domains: []string{"full:example.com"}}, "", "example.com", 443, "tcp", "block"},
		{"full excludes child", DestinationRule{Domains: []string{"full:example.com"}}, "", "www.example.com", 443, "tcp", "direct"},
		{"suffix case and trailing dot", DestinationRule{Domains: []string{"domain:example.com"}}, "", "WWW.Example.COM.", 443, "tcp", "block"},
		{"keyword", DestinationRule{Domains: []string{"keyword:example"}}, "", "www.example.com", 443, "tcp", "block"},
		{"anchored expression", DestinationRule{Domains: []string{"regexp:^example$"}}, "", "www.example.com", 443, "tcp", "direct"},
		{"literal IPv4", DestinationRule{CIDRs: []string{"10.0.0.0/8"}}, "", "10.2.3.4", 443, "tcp", "block"},
		{"literal IPv6", DestinationRule{CIDRs: []string{"2001:db8::/32"}}, "", "2001:db8::7", 443, "tcp", "block"},
		{"OR domain and CIDR", DestinationRule{Domains: []string{"full:example.com"}, CIDRs: []string{"10.0.0.0/8"}}, "", "10.2.3.4", 443, "tcp", "block"},
		{"AND port excludes", DestinationRule{Domains: []string{"full:example.com"}, Ports: "25,80-90"}, "", "example.com", 443, "tcp", "direct"},
		{"port range boundary", DestinationRule{Ports: "25,80-90"}, "", "example.com", 90, "tcp", "block"},
		{"network", DestinationRule{Network: "udp"}, "", "example.com", 443, "tcp", "direct"},
		{"subject", DestinationRule{Subjects: []SubjectKey{"usr_1"}, Ports: "443"}, "usr_2", "example.com", 443, "tcp", "direct"},
		{"catch-all subject", DestinationRule{Subjects: []SubjectKey{"usr_1"}, CatchAll: true}, "usr_1", "example.com", 443, "tcp", "block"},
		{"anonymous not group", DestinationRule{Subjects: []SubjectKey{"usr_1"}, CatchAll: true}, "", "example.com", 443, "tcp", "direct"},
		{"metadata literal", DestinationRule{Private: true}, "", "169.254.169.254", 80, "tcp", "block"},
		{"CGNAT private", DestinationRule{Private: true}, "", "100.64.0.1", 80, "tcp", "block"},
		{"mapped private", DestinationRule{Private: true}, "", "::ffff:169.254.169.254", 80, "tcp", "block"},
		{"IPv6 private", DestinationRule{Private: true}, "", "fe80::1", 80, "tcp", "block"},
		{"public IP", DestinationRule{Private: true}, "", "1.1.1.1", 80, "tcp", "direct"},
		{"DNS remains unresolved", DestinationRule{Private: true}, "", "localhost", 80, "tcp", "direct"},
		{"BT scope miss is testable", DestinationRule{Subjects: []SubjectKey{"usr_1"}, Protocols: []string{"bittorrent"}}, "usr_2", "example.com", 80, "tcp", "direct"},
	} {
		t.Run(v.name, func(t *testing.T) {
			v.rule.ID = "p1"
			v.rule.Action = RuleBlock
			got := MatchDestination(&DestinationPolicy{Rules: []DestinationRule{v.rule}}, v.subject, v.target, v.port, v.network)
			if got.Verdict != v.want {
				t.Fatalf("verdict = %s, want %s", got.Verdict, v.want)
			}
		})
	}
}

func TestDestinationPreviewDoesNotMutateOrPromiseUnknownProtocol(t *testing.T) {
	p := &DestinationPolicy{Rules: []DestinationRule{{ID: "p8", Action: RuleAllow, Protocols: []string{"bittorrent"}}, {ID: "p1", Action: RuleBlock, Ports: "443"}}}
	before := PolicyDigest(p)
	if got := MatchDestination(p, "", "example.com", 443, "tcp"); got.Verdict != "untestable" {
		t.Fatalf("unknown earlier allow treated as certain block: %#v", got)
	}
	if PolicyDigest(p) != before {
		t.Fatal("preview rewrote execution order")
	}
	p.Rules[0] = DestinationRule{ID: "p8", Action: RuleAllow, Domains: []string{"full:example.com"}}
	p.Rules[1] = DestinationRule{ID: "p1", Action: RuleBlock, Protocols: []string{"bittorrent"}}
	if got := MatchDestination(p, "", "example.com", 443, "tcp"); got.Verdict != "allow" {
		t.Fatal("later unknown rule replaced certain earlier allow")
	}
	for _, v := range []struct {
		subject SubjectKey
		target  string
		port    uint16
		network string
	}{{"usr_01", "example.com", 443, "tcp"}, {"", "https://example.com/path", 443, "tcp"}, {"", "example.com", 0, "tcp"}, {"", "example.com", 443, "icmp"}} {
		if got := MatchDestination(nil, v.subject, v.target, v.port, v.network); got.Verdict != "invalid" {
			t.Fatal("invalid preview input accepted")
		}
	}
}
