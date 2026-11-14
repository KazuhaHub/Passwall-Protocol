package protocol

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The golden strings below were produced by the v0.2.1 code, before Policy
// existed. They are what an agent that never advertised
// CapabilityDestinationPolicy must keep receiving: the config ETag is a hash
// of these bytes, so one extra byte re-mints every segment in the fleet and
// every node re-applies a config that did not change.
func TestConfigBodyWithoutPolicyIsByteIdenticalToV021(t *testing.T) {
	body := ConfigBody{
		Listeners: []Listener{{Key: NewListenerKey(1), Config: RawConfig(`{"port":443}`)}},
		Core:      CoreSelection{Engine: "xray", Version: "v26.9.9"},
	}
	const want = `{"listeners":[{"key":"lst_1","config":"eyJwb3J0Ijo0NDN9"}],"coverage":{"entries":0,"entries_stale":0},"core":{"engine":"xray","version":"v26.9.9"}}`
	got, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("a ConfigBody with a nil Policy changed on the wire:\n got=%s\nwant=%s", got, want)
	}
	// The segment wraps the body, so the same bytes must survive inside it.
	segment, err := json.Marshal(Segment[ConfigBody]{Body: &body})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(segment, []byte(want)) {
		t.Fatalf("the segment does not carry the v0.2.1 body verbatim: %s", segment)
	}
}

func TestNodeReportWithoutPolicyStatusIsByteIdenticalToV021(t *testing.T) {
	report := NodeReport{AgentID: "a1", Have: map[string]StreamState{}}
	const full = `{"agent_id":"a1","partial":false,"have":{},"objects":[],"listener_counters":[],"clients":[]}`
	const partial = `{"agent_id":"a1","partial":true,"have":{}}`
	got, _ := json.Marshal(report)
	if string(got) != full {
		t.Fatalf("full report changed:\n got=%s\nwant=%s", got, full)
	}
	report.Partial = true
	got, _ = json.Marshal(report)
	if string(got) != partial {
		t.Fatalf("partial report changed:\n got=%s\nwant=%s", got, partial)
	}
}

func TestConfigBodyCarriesPolicyWhenSet(t *testing.T) {
	body := ConfigBody{Policy: &DestinationPolicy{Rules: []DestinationRule{}, Collect: CollectHits}}
	got, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"policy":{"rules":[],"collect":"hits"}`) {
		t.Fatalf("policy missing from the config body: %s", got)
	}
}

// validPolicy is one policy that exercises every phase and every rule shape.
func validPolicy() *DestinationPolicy {
	return &DestinationPolicy{
		Rules: []DestinationRule{
			{ID: "s1", Action: RuleBlock, SourceCIDRs: []string{"203.0.113.0/24"}, Inbounds: []ListenerKey{"lst_1"}},
			{ID: "p1", Action: RuleAllow, Domains: []string{"domain:example.com"}},
			{ID: "p2x1", Action: RuleBlock, Ports: "25,465,587", Network: "tcp"},
			{ID: "p2x2", Action: RuleBlock, Protocols: []string{"bittorrent"}, Inbounds: []ListenerKey{"lst_1", "lst_2"}},
			{ID: "g5x1", Action: RuleAllow, Subjects: []SubjectKey{"usr_1"}, Domains: []string{"full:a.example"}},
			{ID: "g5", Action: RuleBlock, Subjects: []SubjectKey{"usr_1"}, CatchAll: true},
			{ID: "s2", Action: RuleObserve, SourceCIDRs: []string{"198.51.100.0/24"}},
			{ID: "p3", Action: RuleObserve, Private: true, CIDRs: []string{"10.0.0.0/8", "fc00::/7"}},
		},
		Exempt:  []SubjectKey{"usr_2", "usr_3"},
		Collect: CollectHitsAndUsage,
	}
}

func TestValidateDestinationPolicyAcceptsNilAndValid(t *testing.T) {
	if err := ValidateDestinationPolicy(nil); err != nil {
		t.Fatalf("nil policy: %v", err)
	}
	if err := ValidateDestinationPolicy(validPolicy()); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	if err := ValidateDestinationPolicy(&DestinationPolicy{Rules: []DestinationRule{}}); err != nil {
		t.Fatalf("empty policy: %v", err)
	}
	// JSON null decodes to nil Rules; it is not the same document as [].
	var fromNull DestinationPolicy
	if err := json.Unmarshal([]byte(`{"rules":null}`), &fromNull); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDestinationPolicy(&fromNull); err == nil {
		t.Fatal("accepted a policy whose rules are null")
	}
}

func TestValidateDestinationPolicyRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(p *DestinationPolicy)
	}{
		{"unknown action", func(p *DestinationPolicy) { p.Rules[1].Action = "deny" }},
		{"unknown collect", func(p *DestinationPolicy) { p.Collect = "all" }},
		{"empty id", func(p *DestinationPolicy) { p.Rules[1].ID = "" }},
		{"id wrong prefix", func(p *DestinationPolicy) { p.Rules[1].ID = "z1" }},
		{"id no digits", func(p *DestinationPolicy) { p.Rules[1].ID = "p" }},
		{"id too many digits", func(p *DestinationPolicy) { p.Rules[1].ID = "p1234567890123" }},
		{"id suffix too long", func(p *DestinationPolicy) { p.Rules[2].ID = "p2x12345" }},
		{"id empty suffix", func(p *DestinationPolicy) { p.Rules[2].ID = "p2x" }},
		{"id trailing junk", func(p *DestinationPolicy) { p.Rules[1].ID = "p1 " }},
		{"duplicate id", func(p *DestinationPolicy) { p.Rules[2].ID = "p1" }},
		{"s rule with suffix", func(p *DestinationPolicy) { p.Rules[0].ID = "s1x1" }},
		{"s rule allow", func(p *DestinationPolicy) { p.Rules[0].Action = RuleAllow }},
		{"s rule without source", func(p *DestinationPolicy) { p.Rules[0].SourceCIDRs = nil }},
		{"s rule with subjects", func(p *DestinationPolicy) { p.Rules[0].Subjects = []SubjectKey{"usr_1"} }},
		{"s rule with domains", func(p *DestinationPolicy) { p.Rules[0].Domains = []string{"full:a"} }},
		{"s rule with cidrs", func(p *DestinationPolicy) { p.Rules[0].CIDRs = []string{"10.0.0.0/8"} }},
		{"s rule with ports", func(p *DestinationPolicy) { p.Rules[0].Ports = "80" }},
		{"s rule with network", func(p *DestinationPolicy) { p.Rules[0].Network = "tcp" }},
		{"s rule with protocols", func(p *DestinationPolicy) { p.Rules[0].Protocols = []string{"bittorrent"} }},
		{"s rule with private", func(p *DestinationPolicy) { p.Rules[0].Private = true }},
		{"s rule catch-all", func(p *DestinationPolicy) { p.Rules[0].CatchAll = true }},
		{"source cidrs on p rule", func(p *DestinationPolicy) { p.Rules[1].SourceCIDRs = []string{"10.0.0.0/8"} }},
		{"source cidrs on g rule", func(p *DestinationPolicy) { p.Rules[4].SourceCIDRs = []string{"10.0.0.0/8"} }},
		{"inbounds on g rule", func(p *DestinationPolicy) { p.Rules[4].Inbounds = []ListenerKey{"lst_1"} }},
		{"inbounds on g catch-all", func(p *DestinationPolicy) { p.Rules[5].Inbounds = []ListenerKey{"lst_1"} }},
		{"g rule block with suffix", func(p *DestinationPolicy) { p.Rules[4].Action = RuleBlock }},
		{"g rule observe with suffix", func(p *DestinationPolicy) { p.Rules[4].Action = RuleObserve }},
		{"g bare allow", func(p *DestinationPolicy) { p.Rules[5].Action = RuleAllow }},
		{"g bare not catch-all", func(p *DestinationPolicy) { p.Rules[5].CatchAll = false; p.Rules[5].Domains = []string{"full:a"} }},
		{"p rule inbounds only", func(p *DestinationPolicy) {
			p.Rules[1] = DestinationRule{ID: "p1", Action: RuleAllow, Inbounds: []ListenerKey{"lst_1"}}
		}},
		{"p rule with nothing", func(p *DestinationPolicy) { p.Rules[1] = DestinationRule{ID: "p1", Action: RuleAllow} }},
		{"catch-all without subjects", func(p *DestinationPolicy) { p.Rules[5].Subjects = nil }},
		{"catch-all with match field", func(p *DestinationPolicy) { p.Rules[5].Ports = "80" }},
		{"phase order: allow after block", func(p *DestinationPolicy) { p.Rules[1], p.Rules[2] = p.Rules[2], p.Rules[1] }},
		{"phase order: s block after p", func(p *DestinationPolicy) { p.Rules[0], p.Rules[1] = p.Rules[1], p.Rules[0] }},
		{"phase order: g before p block", func(p *DestinationPolicy) { p.Rules[2], p.Rules[4] = p.Rules[4], p.Rules[2] }},
		{"phase order: observe before g", func(p *DestinationPolicy) { p.Rules[4], p.Rules[7] = p.Rules[7], p.Rules[4] }},
		{"protocols with domains", func(p *DestinationPolicy) { p.Rules[3].Domains = []string{"full:a.example"} }},
		{"unknown protocol", func(p *DestinationPolicy) { p.Rules[3].Protocols = []string{"http"} }},
		{"domain no prefix", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"example.com"} }},
		{"domain unknown prefix", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"geosite:cn"} }},
		{"domain uppercase", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"domain:Example.com"} }},
		{"domain empty value", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"domain:"} }},
		{"domain leading dot", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"domain:.example.com"} }},
		{"domain trailing dot", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"full:example.com."} }},
		{"domain bad char", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"domain:exa mple.com"} }},
		{"domain too long", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"full:" + strings.Repeat("a", 254)} }},
		{"keyword empty", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"keyword:"} }},
		{"keyword uppercase", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"keyword:Tor"} }},
		{"keyword too long", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"keyword:" + strings.Repeat("a", 254)} }},
		{"regexp does not compile", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"regexp:(unclosed"} }},
		{"regexp too long", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"regexp:" + strings.Repeat("a", 1025)} }},
		{"domains unsorted", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"full:b", "full:a"} }},
		{"domains duplicate", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"full:a", "full:a"} }},
		{"cidr not canonical", func(p *DestinationPolicy) { p.Rules[7].CIDRs = []string{"10.0.0.1/8"} }},
		{"cidr bare address", func(p *DestinationPolicy) { p.Rules[7].CIDRs = []string{"10.0.0.1"} }},
		{"cidr upper-case v6", func(p *DestinationPolicy) { p.Rules[7].CIDRs = []string{"FC00::/7"} }},
		{"cidr garbage", func(p *DestinationPolicy) { p.Rules[7].CIDRs = []string{"nope"} }},
		{"cidrs unsorted", func(p *DestinationPolicy) { p.Rules[7].CIDRs = []string{"fc00::/7", "10.0.0.0/8"} }},
		{"source cidr not canonical", func(p *DestinationPolicy) { p.Rules[0].SourceCIDRs = []string{"203.0.113.5/24"} }},
		{"ports empty entry", func(p *DestinationPolicy) { p.Rules[2].Ports = "25,,587" }},
		{"ports zero", func(p *DestinationPolicy) { p.Rules[2].Ports = "0" }},
		{"ports too big", func(p *DestinationPolicy) { p.Rules[2].Ports = "65536" }},
		{"ports reversed range", func(p *DestinationPolicy) { p.Rules[2].Ports = "90-80" }},
		{"ports trailing comma", func(p *DestinationPolicy) { p.Rules[2].Ports = "25," }},
		{"ports space", func(p *DestinationPolicy) { p.Rules[2].Ports = "25, 80" }},
		{"ports six digits", func(p *DestinationPolicy) { p.Rules[2].Ports = "000025" }},
		{"ports open range", func(p *DestinationPolicy) { p.Rules[2].Ports = "80-" }},
		{"ports double range", func(p *DestinationPolicy) { p.Rules[2].Ports = "1-2-3" }},
		{"ports leading zero", func(p *DestinationPolicy) { p.Rules[2].Ports = "0080" }},
		{"ports leading zero in range", func(p *DestinationPolicy) { p.Rules[2].Ports = "25,0080-90" }},
		{"ports equal range ends", func(p *DestinationPolicy) { p.Rules[2].Ports = "80-80" }},
		{"nil rules", func(p *DestinationPolicy) { p.Rules = nil }},
		{"cidr ipv4-mapped", func(p *DestinationPolicy) { p.Rules[7].CIDRs = []string{"::ffff:10.0.0.0/104"} }},
		{"source cidr ipv4-mapped", func(p *DestinationPolicy) { p.Rules[0].SourceCIDRs = []string{"::ffff:203.0.113.0/120"} }},
		{"g member catch-all", func(p *DestinationPolicy) {
			p.Rules[4] = DestinationRule{ID: "g5x1", Action: RuleAllow, Subjects: []SubjectKey{"usr_1"}, CatchAll: true}
		}},
		{"ports descending", func(p *DestinationPolicy) { p.Rules[2].Ports = "587,25" }},
		{"ports duplicate", func(p *DestinationPolicy) { p.Rules[2].Ports = "25,25" }},
		{"ports overlapping", func(p *DestinationPolicy) { p.Rules[2].Ports = "20-30,25" }},
		{"ports overlapping ranges", func(p *DestinationPolicy) { p.Rules[2].Ports = "20-30,30-40" }},
		{"ports range after contained port", func(p *DestinationPolicy) { p.Rules[2].Ports = "25,20-30" }},
		{"id leading zero", func(p *DestinationPolicy) { p.Rules[1].ID = "p01" }},
		{"id leading zero 007", func(p *DestinationPolicy) { p.Rules[1].ID = "p007" }},
		{"id suffix leading zero", func(p *DestinationPolicy) { p.Rules[4].ID = "g5x01" }},
		{"id suffix double zero", func(p *DestinationPolicy) { p.Rules[2].ID = "p2x00" }},
		{"domain empty label", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"domain:a..b"} }},
		{"full empty label", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"full:a..b"} }},
		{"domain label too long", func(p *DestinationPolicy) {
			p.Rules[1].Domains = []string{"domain:" + strings.Repeat("a", 64) + ".com"}
		}},
		{"regexp empty", func(p *DestinationPolicy) { p.Rules[1].Domains = []string{"regexp:"} }},
		{"group member without subjects", func(p *DestinationPolicy) { p.Rules[4].Subjects = nil }},
		{"network unknown", func(p *DestinationPolicy) { p.Rules[2].Network = "icmp" }},
		{"network uppercase", func(p *DestinationPolicy) { p.Rules[2].Network = "TCP" }},
		{"subject bad key", func(p *DestinationPolicy) { p.Rules[4].Subjects = []SubjectKey{"cli_1"} }},
		{"subject non-canonical", func(p *DestinationPolicy) { p.Rules[4].Subjects = []SubjectKey{"usr_01"} }},
		{"exempt bad key", func(p *DestinationPolicy) { p.Exempt = []SubjectKey{"usr_x"} }},
		{"exempt unsorted", func(p *DestinationPolicy) { p.Exempt = []SubjectKey{"usr_3", "usr_2"} }},
		{"exempt duplicate", func(p *DestinationPolicy) { p.Exempt = []SubjectKey{"usr_2", "usr_2"} }},
		{"subjects duplicate", func(p *DestinationPolicy) { p.Rules[4].Subjects = []SubjectKey{"usr_1", "usr_1"} }},
		{"inbound bad key", func(p *DestinationPolicy) { p.Rules[0].Inbounds = []ListenerKey{"usr_1"} }},
		{"inbounds unsorted", func(p *DestinationPolicy) { p.Rules[3].Inbounds = []ListenerKey{"lst_2", "lst_1"} }},
		{"protocols duplicate", func(p *DestinationPolicy) { p.Rules[3].Protocols = []string{"bittorrent", "bittorrent"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := validPolicy()
			tc.mutate(policy)
			if err := ValidateDestinationPolicy(policy); err == nil {
				t.Fatalf("accepted: %+v", policy)
			}
		})
	}
}

func TestValidateDestinationPolicyAcceptsEdgeShapes(t *testing.T) {
	cases := map[string]func(p *DestinationPolicy){
		"port range and list": func(p *DestinationPolicy) { p.Rules[2].Ports = "25,6881-6889,65535" },
		"all domain kinds": func(p *DestinationPolicy) {
			p.Rules[1].Domains = []string{"domain:a-b.example", "full:x_y.example", "keyword:tor", "regexp:^a.*b$"}
		},
		"udp network":          func(p *DestinationPolicy) { p.Rules[2].Network = "udp" },
		"empty network":        func(p *DestinationPolicy) { p.Rules[2].Network = "" },
		"collect off":          func(p *DestinationPolicy) { p.Collect = CollectOff },
		"collect hits":         func(p *DestinationPolicy) { p.Collect = CollectHits },
		"no exempt":            func(p *DestinationPolicy) { p.Exempt = nil },
		"p rule with inbounds": func(p *DestinationPolicy) { p.Rules[1].Inbounds = []ListenerKey{"lst_9"} },
		"port list, adjacent":  func(p *DestinationPolicy) { p.Rules[2].Ports = "10,80,81-82" },
		"p catch-all block": func(p *DestinationPolicy) {
			p.Rules[2] = DestinationRule{ID: "p2", Action: RuleBlock, Subjects: []SubjectKey{"usr_1"}, CatchAll: true}
		},
		"v6 source":           func(p *DestinationPolicy) { p.Rules[0].SourceCIDRs = []string{"2001:db8::/32"} },
		"observe source rule": func(p *DestinationPolicy) { p.Rules[6].Inbounds = []ListenerKey{"lst_3"} },
		"label of 63 bytes": func(p *DestinationPolicy) {
			p.Rules[1].Domains = []string{"domain:" + strings.Repeat("a", 63) + ".com"}
		},
		"id zero":           func(p *DestinationPolicy) { p.Rules[1].ID = "p0" },
		"max-width rule id": func(p *DestinationPolicy) { p.Rules[1].ID = "p123456789012x9999" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			policy := validPolicy()
			mutate(policy)
			if err := ValidateDestinationPolicy(policy); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

func TestValidateDestinationPolicyLimits(t *testing.T) {
	t.Run("rules", func(t *testing.T) {
		p := &DestinationPolicy{}
		for i := 0; i <= MaxPolicyRules; i++ {
			p.Rules = append(p.Rules, DestinationRule{ID: "p" + itoa(i), Action: RuleBlock, Ports: "80"})
		}
		if err := ValidateDestinationPolicy(p); err == nil {
			t.Fatal("accepted one rule over the limit")
		}
		p.Rules = p.Rules[:MaxPolicyRules]
		if err := ValidateDestinationPolicy(p); err != nil {
			t.Fatalf("rejected exactly the limit: %v", err)
		}
	})
	t.Run("domains summed across rules", func(t *testing.T) {
		p := &DestinationPolicy{}
		// Two rules, each under any plausible per-rule cap, over the sum.
		half := MaxPolicyDomains/2 + 1
		p.Rules = []DestinationRule{
			{ID: "p1", Action: RuleBlock, Domains: sortedDomains(0, half)},
			{ID: "p2", Action: RuleBlock, Domains: sortedDomains(half, half)},
		}
		if err := ValidateDestinationPolicy(p); err == nil {
			t.Fatal("accepted a domain sum over the limit")
		}
	})
	t.Run("regexps", func(t *testing.T) {
		var domains []string
		for i := 0; i <= MaxPolicyRegexps; i++ {
			domains = append(domains, "regexp:^a"+pad(i)+"$")
		}
		p := &DestinationPolicy{Rules: []DestinationRule{{ID: "p1", Action: RuleBlock, Domains: domains}}}
		if err := ValidateDestinationPolicy(p); err == nil {
			t.Fatal("accepted one regexp over the limit")
		}
		p.Rules[0].Domains = domains[:MaxPolicyRegexps]
		if err := ValidateDestinationPolicy(p); err != nil {
			t.Fatalf("rejected exactly the limit: %v", err)
		}
	})
	t.Run("subjects plus exempt", func(t *testing.T) {
		p := &DestinationPolicy{
			Rules:  []DestinationRule{{ID: "g1x1", Action: RuleAllow, Domains: []string{"full:a"}, Subjects: sortedSubjects(0, MaxPolicySubjects)}},
			Exempt: sortedSubjects(MaxPolicySubjects, 1),
		}
		if err := ValidateDestinationPolicy(p); err == nil {
			t.Fatal("accepted subjects+exempt over the limit")
		}
	})
	t.Run("destination cidrs", func(t *testing.T) {
		p := &DestinationPolicy{Rules: []DestinationRule{{ID: "p1", Action: RuleBlock, CIDRs: sortedV4(MaxPolicyCIDRs + 1)}}}
		if err := ValidateDestinationPolicy(p); err == nil {
			t.Fatal("accepted destination cidrs over the limit")
		}
		p.Rules[0].CIDRs = p.Rules[0].CIDRs[:MaxPolicyCIDRs]
		if err := ValidateDestinationPolicy(p); err != nil {
			t.Fatalf("rejected exactly the limit: %v", err)
		}
	})
	t.Run("source cidrs", func(t *testing.T) {
		p := &DestinationPolicy{Rules: []DestinationRule{{ID: "s1", Action: RuleBlock, SourceCIDRs: sortedV4(MaxPolicySourceCIDRs + 1)}}}
		if err := ValidateDestinationPolicy(p); err == nil {
			t.Fatal("accepted source cidrs over the limit")
		}
	})
	t.Run("inbounds", func(t *testing.T) {
		var inbounds []ListenerKey
		for i := 0; i <= MaxPolicyInbounds; i++ {
			inbounds = append(inbounds, ListenerKey("lst_"+itoa(1000000+i)))
		}
		p := &DestinationPolicy{Rules: []DestinationRule{{ID: "p1", Action: RuleBlock, Ports: "80", Inbounds: inbounds}}}
		if err := ValidateDestinationPolicy(p); err == nil {
			t.Fatal("accepted inbounds over the limit")
		}
	})
	t.Run("bytes", func(t *testing.T) {
		// Within every count limit and every per-entry limit, over MaxPolicyBytes:
		// 4 rules of 12k regexp-free 253-byte domains would be ~12 MiB, so the
		// count limit (50k domains) is what a policy must also stay under; use
		// the widest legal entries.
		// Four labels of at most 60 bytes keep every entry under the per-entry
		// and per-label limits, so only the total can be what rejects it.
		long := strings.Repeat("a", 60) + "." + strings.Repeat("a", 60) + "." + strings.Repeat("a", 60) + "." + strings.Repeat("a", 52)
		var rules []DestinationRule
		for r := 0; r < 4; r++ {
			var domains []string
			for i := 0; i < 5000; i++ {
				domains = append(domains, "full:"+long+pad(r*5000+i))
			}
			rules = append(rules, DestinationRule{ID: "p" + itoa(r+1), Action: RuleBlock, Domains: domains})
		}
		p := &DestinationPolicy{Rules: rules}
		err := ValidateDestinationPolicy(p)
		if err == nil {
			t.Fatalf("accepted a policy of %d bytes", len(mustMarshal(t, p)))
		}
		if !strings.Contains(err.Error(), "bytes") {
			t.Fatalf("rejected for another reason than size: %v", err)
		}
	})
}

func TestPolicyDigest(t *testing.T) {
	if got := PolicyDigest(nil); got != "" {
		t.Fatalf("nil policy digest = %q, want empty", got)
	}
	p := validPolicy()
	d := PolicyDigest(p)
	if err := validateDigest(d); err != nil {
		t.Fatalf("digest %q: %v", d, err)
	}
	if d != PolicyDigest(validPolicy()) {
		t.Fatal("digest is not deterministic")
	}
	changed := validPolicy()
	changed.Rules[1].Domains = []string{"domain:example.org"}
	if PolicyDigest(changed) == d {
		t.Fatal("digest ignores a rule change")
	}
	changed = validPolicy()
	changed.Collect = CollectOff
	if PolicyDigest(changed) == d {
		t.Fatal("digest ignores the collect level")
	}
	// Pinned: PSP, Node and this module all compute it, so a change in the
	// field order or tags is a change to every digest ever reported.
	pinned := &DestinationPolicy{Rules: []DestinationRule{{ID: "p1", Action: RuleBlock, Ports: "25"}}}
	const want = "7ba8cd1b81f42df4393747c9b9313b48338c908d2b866e67b450ced654521d0c"
	if got := PolicyDigest(pinned); got != want {
		t.Fatalf("pinned digest = %s, want %s (wire: %s)", got, want, mustMarshal(t, pinned))
	}
}

// FuzzValidateDestinationPolicy looks for the policy nobody wrote a case for.
// A policy comes from the panel, so this is the Node's door onto it, and the
// validator is also the sender's gate: what it accepts must be bytes the other
// side re-derives identically.
//
// AN ACCEPTED POLICY MUST SURVIVE ITS OWN WIRE FORMAT. It is re-encoded,
// decoded and validated again; the second encoding must equal the first and
// the digest must not move, because the digest is what the agent reports back
// and the panel compares.
//
// Plain `go test` runs only the seeds; the weekly workflow does the fuzzing.
func FuzzValidateDestinationPolicy(fuzz *testing.F) {
	seeds := []*DestinationPolicy{
		validPolicy(),
		{Rules: []DestinationRule{}},
		{Rules: []DestinationRule{{ID: "p1", Action: RuleBlock, Domains: []string{"regexp:^(a|b)+$"}}}},
		{Rules: []DestinationRule{{ID: "p1", Action: RuleBlock, Ports: "1-65535", Network: "udp"}}},
	}
	for index, seed := range seeds {
		if err := ValidateDestinationPolicy(seed); err != nil {
			fuzz.Fatalf("seed %d is rejected, so it seeds nothing past the check that rejects it: %v", index, err)
		}
		fuzz.Add(mustMarshal(fuzz, seed))
	}
	fuzz.Add([]byte(`{"rules":null}`))
	fuzz.Add([]byte(`{"rules":[{"id":"p1","action":"allow","cidrs":["::ffff:10.0.0.0/104"]}]}`))

	fuzz.Fuzz(func(t *testing.T, body []byte) {
		var policy DestinationPolicy
		if err := json.Unmarshal(body, &policy); err != nil {
			return
		}
		if err := ValidateDestinationPolicy(&policy); err != nil {
			return
		}
		wire, err := json.Marshal(&policy)
		if err != nil {
			t.Fatalf("an accepted policy failed to encode: %v", err)
		}
		var decoded DestinationPolicy
		if err := json.Unmarshal(wire, &decoded); err != nil {
			t.Fatalf("an accepted policy failed to decode its own encoding: %v\n%s", err, wire)
		}
		if err := ValidateDestinationPolicy(&decoded); err != nil {
			t.Fatalf("an accepted policy became invalid after a round trip: %v\n%s", err, wire)
		}
		again, err := json.Marshal(&decoded)
		if err != nil {
			t.Fatalf("a round-tripped policy failed to encode: %v", err)
		}
		if !bytes.Equal(wire, again) {
			t.Fatalf("an accepted policy does not re-encode to the same bytes:\n first=%s\nsecond=%s", wire, again)
		}
		if PolicyDigest(&policy) != PolicyDigest(&decoded) {
			t.Fatalf("the digest moved across a round trip:\n%s", wire)
		}
		if len(wire) > MaxPolicyBytes {
			t.Fatalf("an accepted policy is %d bytes, over MaxPolicyBytes", len(wire))
		}
	})
}

// --- helpers -----------------------------------------------------------

func itoa(n int) string { return strconv.Itoa(n) }

// pad renders n as fixed-width decimal so lexicographic order equals numeric
// order, which is what "sorted bytewise" asks of generated entries.
func pad(n int) string {
	s := strconv.Itoa(n)
	return strings.Repeat("0", 8-len(s)) + s
}

func sortedDomains(start, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "full:h" + pad(start+i) + ".example"
	}
	return out
}

// sortedSubjects returns n distinct canonical keys in bytewise order. Canonical
// row ids have no zero padding, so numeric order is not bytewise order and the
// slice is sorted after the fact.
func sortedSubjects(start, n int) []SubjectKey {
	out := make([]SubjectKey, n)
	for i := range out {
		out[i] = NewSubjectKey(int64(start + i + 1))
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// sortedV4 returns n distinct canonical /32s in bytewise order.
func sortedV4(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "10." + strconv.Itoa(i/65536) + "." + strconv.Itoa(i/256%256) + "." + strconv.Itoa(i%256) + "/32"
	}
	sort.Strings(out)
	return out
}

func mustMarshal(tb testing.TB, v any) []byte {
	tb.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// Rules of one group are contiguous: the members first, the catch-all last.
// Phase order alone would let a catch-all sit between two groups' members, and
// "block everything else for this group" would then also swallow another
// group's allows.
func TestValidateDestinationPolicyGroupContiguity(t *testing.T) {
	// Each group's subject is its own gid, so groups do not overlap.
	member := func(gid, k string) DestinationRule {
		return DestinationRule{ID: "g" + gid + "x" + k, Action: RuleAllow, Domains: []string{"full:a.example"}, Subjects: []SubjectKey{SubjectKey("usr_" + gid)}}
	}
	catchAll := func(gid string) DestinationRule {
		return DestinationRule{ID: "g" + gid, Action: RuleBlock, Subjects: []SubjectKey{SubjectKey("usr_" + gid)}, CatchAll: true}
	}
	observe := DestinationRule{ID: "p9", Action: RuleObserve, Ports: "80"}
	for name, rules := range map[string][]DestinationRule{
		"two groups in turn":    {member("1", "1"), member("1", "2"), catchAll("1"), member("2", "1"), catchAll("2")},
		"catch-all alone":       {catchAll("3")},
		"gid 1 and 10 differ":   {member("1", "1"), catchAll("1"), member("10", "1"), catchAll("10")},
		"observe after a group": {member("1", "1"), catchAll("1"), observe},
	} {
		if err := ValidateDestinationPolicy(&DestinationPolicy{Rules: rules}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, rules := range map[string][]DestinationRule{
		"members without a catch-all":         {member("1", "1")},
		"members, then another phase":         {member("1", "1"), observe},
		"interleaved groups":                  {member("1", "1"), member("2", "1"), catchAll("1"), catchAll("2")},
		"member after its catch-all":          {member("1", "1"), catchAll("1"), member("1", "2")},
		"member of a closed group, later":     {member("1", "1"), catchAll("1"), member("2", "1"), catchAll("2"), member("1", "2")},
		"catch-all before a group's members":  {catchAll("1"), member("1", "1")},
		"group left open before the next one": {member("1", "1"), member("2", "1"), catchAll("2")},
		"two catch-alls for one gid":          {member("1", "1"), catchAll("1"), catchAll("1")},
		"member subjects differ from the catch-all": {
			func() DestinationRule { r := member("1", "1"); r.Subjects = []SubjectKey{"usr_2"}; return r }(), catchAll("1")},
		"member subjects differ from each other": {
			member("1", "1"), func() DestinationRule { r := member("1", "2"); r.Subjects = []SubjectKey{"usr_1", "usr_2"}; return r }(), catchAll("1")},
		"catch-all has more subjects than its members": {
			member("1", "1"), func() DestinationRule { r := catchAll("1"); r.Subjects = []SubjectKey{"usr_1", "usr_2"}; return r }()},
		"a subject in two groups": {
			catchAll("1"), func() DestinationRule { r := catchAll("2"); r.Subjects = []SubjectKey{"usr_1"}; return r }()},
		"a subject shared by two groups' members": {
			member("1", "1"), catchAll("1"),
			func() DestinationRule { r := member("2", "1"); r.Subjects = []SubjectKey{"usr_1"}; return r }(),
			func() DestinationRule { r := catchAll("2"); r.Subjects = []SubjectKey{"usr_1"}; return r }()},
	} {
		if err := ValidateDestinationPolicy(&DestinationPolicy{Rules: rules}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCapabilityDestinationGroupsIsNotAnUpgradeCapability(t *testing.T) {
	if CapabilityDestinationGroups != "policy.destination.groups.v1" {
		t.Fatalf("capability name changed: %q", CapabilityDestinationGroups)
	}
	// Like the destination policy itself, lacking it says nothing about whether
	// the agent can take an upgrade.
	for _, upgrade := range AgentUpgradeCapabilities() {
		if upgrade == CapabilityDestinationGroups {
			t.Fatalf("%s is an upgrade capability", upgrade)
		}
	}
}

func TestValidate_ResolveValues(t *testing.T) {
	for _, tc := range []struct {
		mode    ResolveMode
		wantErr string
	}{
		{mode: ResolveAsIs},
		{mode: ResolveOnDemand},
		{mode: "if_non_match", wantErr: "if_non_match"},
		{mode: "IPIfNonMatch", wantErr: "resolve"},
		{mode: "on_demand ", wantErr: "resolve"},
		{mode: "ON_DEMAND", wantErr: "resolve"},
		{mode: "as_is", wantErr: "resolve"},
	} {
		p := validPolicy()
		p.Resolve = tc.mode
		err := ValidateDestinationPolicy(p)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("resolve %q: %v", tc.mode, err)
		case tc.wantErr != "" && err == nil:
			t.Errorf("resolve %q accepted", tc.mode)
		case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
			t.Errorf("resolve %q: error %q does not mention %q", tc.mode, err, tc.wantErr)
		}
	}
	if ResolveAsIs != "" || ResolveOnDemand != "on_demand" {
		t.Fatalf("wire values changed: %q %q", ResolveAsIs, ResolveOnDemand)
	}
	// "if_non_match" must be refused with a reason, not as an unknown value.
	p := validPolicy()
	p.Resolve = "if_non_match"
	if err := ValidateDestinationPolicy(p); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("if_non_match error = %v, want an explanation that it is not supported", err)
	}
}

// AsIs is the absence of the field, so every digest minted before Resolve
// existed is still the digest of the same policy.
func TestDigest_AsIsUnchanged(t *testing.T) {
	p := validPolicy()
	if strings.Contains(string(mustMarshal(t, p)), "resolve") {
		t.Fatalf("AsIs is encoded: %s", mustMarshal(t, p))
	}
	// Pinned before the field was added.
	const want = "8981e141555807a9d8e9487203e52cb00120dfa0bc8f6220193e8d86e2a2b3b5"
	if got := PolicyDigest(p); got != want {
		t.Fatalf("digest of the v0.4 policy = %s, want %s", got, want)
	}
	p.Resolve = ResolveOnDemand
	if got := PolicyDigest(p); got == want {
		t.Fatal("digest ignores resolve")
	}
	if !strings.Contains(string(mustMarshal(t, p)), `"resolve":"on_demand"`) {
		t.Fatalf("on_demand is not encoded: %s", mustMarshal(t, p))
	}
	var decoded DestinationPolicy
	if err := json.Unmarshal(mustMarshal(t, p), &decoded); err != nil || decoded.Resolve != ResolveOnDemand {
		t.Fatalf("round trip: %+v %v", decoded, err)
	}
}

func TestCapabilityDestinationResolveIsNotAnUpgradeCapability(t *testing.T) {
	if CapabilityDestinationResolve != "policy.resolve.v1" {
		t.Fatalf("capability = %q", CapabilityDestinationResolve)
	}
	for _, c := range AgentUpgradeCapabilities() {
		if c == CapabilityDestinationResolve {
			t.Fatal("policy.resolve.v1 must not gate upgrades")
		}
	}
}
