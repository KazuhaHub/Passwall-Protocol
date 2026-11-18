package protocol

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestSourceGuardCapabilityName(t *testing.T) {
	if CapabilitySourceGuard != "transit.source_guard.v1" {
		t.Fatalf("capability name changed: %q", CapabilitySourceGuard)
	}
	for _, upgrade := range AgentUpgradeCapabilities() {
		if upgrade == CapabilitySourceGuard {
			t.Fatalf("%s is an upgrade capability", upgrade)
		}
	}
}

func TestSourceSetKey(t *testing.T) {
	good := []string{"src_a", "src_0", "src_line-12", "src_cf_cdn", "src_" + strings.Repeat("a", 48)}
	for _, key := range good {
		if err := SourceSetKey(key).Validate(); err != nil {
			t.Errorf("%q refused: %v", key, err)
		}
	}
	bad := []string{"", "src_", "a", "src_-a", "src__a", "src_A", "src_a.b", "src_a b", "SRC_a", "lst_1",
		"src_" + strings.Repeat("a", 49)}
	for _, key := range bad {
		if err := SourceSetKey(key).Validate(); err == nil {
			t.Errorf("%q accepted", key)
		}
	}
	key, err := NewSourceSetKey("line-1")
	if err != nil || key != "src_line-1" || key.Suffix() != "line-1" {
		t.Fatalf("NewSourceSetKey = %q, %v", key, err)
	}
	if _, err := NewSourceSetKey("Bad"); err == nil {
		t.Error("NewSourceSetKey accepted an uppercase suffix")
	}
}

func TestValidateTransitSourceSets(t *testing.T) {
	many := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24).String()
		}
		return out
	}
	tests := []struct {
		name string
		sets []SourceSet
		ok   bool
	}{
		{"one v4", []SourceSet{{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}}}, true},
		{"host and v6", []SourceSet{{Key: "src_a", CIDRs: []string{"1.2.3.4/32", "2001:db8::/32", "::/0"}}}, true},
		{"two sets", []SourceSet{{Key: "src_a", CIDRs: []string{"1.0.0.0/8"}}, {Key: "src_b", CIDRs: []string{"1.0.0.0/8"}}}, true},
		{"max cidrs", []SourceSet{{Key: "src_a", CIDRs: many(MaxSourceSetCIDRs)}}, true},
		{"too many cidrs", []SourceSet{{Key: "src_a", CIDRs: many(MaxSourceSetCIDRs + 1)}}, false},
		{"empty cidrs", []SourceSet{{Key: "src_a"}}, false},
		{"bad key", []SourceSet{{Key: "a", CIDRs: []string{"1.0.0.0/8"}}}, false},
		{"duplicate key", []SourceSet{{Key: "src_a", CIDRs: []string{"1.0.0.0/8"}}, {Key: "src_a", CIDRs: []string{"2.0.0.0/8"}}}, false},
		{"duplicate cidr", []SourceSet{{Key: "src_a", CIDRs: []string{"1.0.0.0/8", "1.0.0.0/8"}}}, false},
		{"host bits", []SourceSet{{Key: "src_a", CIDRs: []string{"1.2.3.4/24"}}}, false},
		{"bare address", []SourceSet{{Key: "src_a", CIDRs: []string{"1.2.3.4"}}}, false},
		{"zone", []SourceSet{{Key: "src_a", CIDRs: []string{"fe80::1%eth0/64"}}}, false},
		{"non canonical v6", []SourceSet{{Key: "src_a", CIDRs: []string{"2001:DB8::/32"}}}, false},
		{"mapped", []SourceSet{{Key: "src_a", CIDRs: []string{"::ffff:1.2.3.0/120"}}}, false},
		{"garbage", []SourceSet{{Key: "src_a", CIDRs: []string{"nope"}}}, false},
	}
	for _, test := range tests {
		err := ValidateTransit(&Transit{SourceSets: test.sets})
		if (err == nil) != test.ok {
			t.Errorf("%s: err = %v, want ok=%v", test.name, err, test.ok)
		}
	}
	sets := make([]SourceSet, MaxSourceSets+1)
	for i := range sets {
		sets[i] = SourceSet{Key: SourceSetKey("src_s" + itoa(i)), CIDRs: []string{"1.0.0.0/8"}}
	}
	if err := ValidateTransit(&Transit{SourceSets: sets[:MaxSourceSets]}); err != nil {
		t.Errorf("max sets refused: %v", err)
	}
	if err := ValidateTransit(&Transit{SourceSets: sets}); err == nil {
		t.Error("too many sets accepted")
	}
}

func TestTransitWithoutSourceSetsIsByteIdentical(t *testing.T) {
	wire, err := json.Marshal(&Transit{Forwards: []Forward{validForward()}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "source_sets") {
		t.Fatalf("empty source sets encoded: %s", wire)
	}
	wire, err = json.Marshal(Client{Key: "cli_1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "source_guard") {
		t.Fatalf("nil guard encoded: %s", wire)
	}
}

func TestValidateClientSourceGuard(t *testing.T) {
	keys := func(n int) []SourceSetKey {
		out := make([]SourceSetKey, n)
		for i := range out {
			out[i] = SourceSetKey("src_k" + itoa(i))
		}
		return out
	}
	tests := []struct {
		name  string
		guard *ClientSourceGuard
		ok    bool
	}{
		{"nil", nil, true},
		{"allow", &ClientSourceGuard{AllowFrom: "src_a"}, true},
		{"deny", &ClientSourceGuard{DenyFrom: []SourceSetKey{"src_a", "src_b"}}, true},
		{"deny max", &ClientSourceGuard{DenyFrom: keys(MaxSourceGuardDenyFrom)}, true},
		{"deny too many", &ClientSourceGuard{DenyFrom: keys(MaxSourceGuardDenyFrom + 1)}, false},
		{"neither", &ClientSourceGuard{}, false},
		{"empty deny", &ClientSourceGuard{DenyFrom: []SourceSetKey{}}, false},
		{"both", &ClientSourceGuard{AllowFrom: "src_a", DenyFrom: []SourceSetKey{"src_b"}}, false},
		{"bad allow", &ClientSourceGuard{AllowFrom: "a"}, false},
		{"bad deny", &ClientSourceGuard{DenyFrom: []SourceSetKey{"src_a", "nope"}}, false},
		{"duplicate deny", &ClientSourceGuard{DenyFrom: []SourceSetKey{"src_a", "src_a"}}, false},
	}
	for _, test := range tests {
		if err := ValidateClientSourceGuard(test.guard); (err == nil) != test.ok {
			t.Errorf("%s: err = %v, want ok=%v", test.name, err, test.ok)
		}
	}
}

func guardReport(partial bool) NodeReport {
	return NodeReport{
		AgentID: "a1", ProtocolVersion: ProtocolVersion1, Have: emptyHave(),
		Capabilities: []string{CapabilitySourceGuard}, Partial: partial,
		SourceGuardHits: []SourceGuardHit{
			{Set: "src_a", Listener: "lst_1", SourceIP: "203.0.113.9", Count: 3, LastSeenMS: 1700000000000},
			{Set: "src_a", Listener: "lst_2", SourceIP: "2001:db8::1", Count: 1, LastSeenMS: 1700000000001},
		},
		InterfaceAddresses: []string{"1.2.3.4", "8.8.8.8", "2606:4700::1"},
	}
}

func TestSourceGuardObservationsInReport(t *testing.T) {
	// 203.0.113.9 and 2001:db8::1 are documentation addresses, fine as a hit
	// source (any address can knock) but never as an interface address.
	if err := ValidateNodeReport(guardReport(false)); err != nil {
		t.Fatalf("valid report refused: %v", err)
	}
	wire, err := json.Marshal(guardReport(false))
	if err != nil {
		t.Fatal(err)
	}
	var decoded NodeReport
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.SourceGuardHits) != 2 || len(decoded.InterfaceAddresses) != 3 {
		t.Fatalf("did not round trip: %s", wire)
	}
}

func TestSourceGuardObservationsNeverOnPartialReport(t *testing.T) {
	wire, err := json.Marshal(guardReport(true))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "source_guard_hits") || strings.Contains(string(wire), "interface_addresses") {
		t.Fatalf("partial report encodes guard observations: %s", wire)
	}
	if err := ValidateNodeReportBase(guardReport(true)); err == nil {
		t.Error("partial report carrying guard observations accepted")
	}
}

func TestSourceGuardObservationsNeedTheCapabilityOnTheSender(t *testing.T) {
	report := guardReport(false)
	report.Capabilities = nil
	if err := ValidateNodeReport(report); err == nil {
		t.Error("guard observations accepted without the capability")
	}
	if err := ValidateNodeReportBase(report); err != nil {
		t.Errorf("base check refused a capability-less report: %v", err)
	}
	report.SourceGuardHits = nil
	if err := ValidateNodeReport(report); err == nil {
		t.Error("interface addresses accepted without the capability")
	}
}

func TestValidateSourceGuardHits(t *testing.T) {
	good := SourceGuardHit{Set: "src_a", Listener: "lst_1", SourceIP: "1.2.3.4", Count: 1, LastSeenMS: 1}
	mutate := func(f func(*SourceGuardHit)) []SourceGuardHit {
		hit := good
		f(&hit)
		return []SourceGuardHit{hit}
	}
	tests := []struct {
		name string
		hits []SourceGuardHit
		ok   bool
	}{
		{"none", nil, true},
		{"good", []SourceGuardHit{good}, true},
		{"bad set", mutate(func(h *SourceGuardHit) { h.Set = "x" }), false},
		{"bad listener", mutate(func(h *SourceGuardHit) { h.Listener = "cli_1" }), false},
		{"non canonical ip", mutate(func(h *SourceGuardHit) { h.SourceIP = "2001:DB8::1" }), false},
		{"not an ip", mutate(func(h *SourceGuardHit) { h.SourceIP = "x" }), false},
		{"zero count", mutate(func(h *SourceGuardHit) { h.Count = 0 }), false},
		{"zero last seen", mutate(func(h *SourceGuardHit) { h.LastSeenMS = 0 }), false},
		{"duplicate", []SourceGuardHit{good, good}, false},
	}
	for _, test := range tests {
		if err := ValidateSourceGuardHits(test.hits); (err == nil) != test.ok {
			t.Errorf("%s: err = %v, want ok=%v", test.name, err, test.ok)
		}
	}
	hits := make([]SourceGuardHit, MaxSourceGuardHits+1)
	for i := range hits {
		hits[i] = good
		hits[i].SourceIP = netip.AddrFrom4([4]byte{1, 0, byte(i >> 8), byte(i)}).String()
	}
	if err := ValidateSourceGuardHits(hits[:MaxSourceGuardHits]); err != nil {
		t.Errorf("max hits refused: %v", err)
	}
	if err := ValidateSourceGuardHits(hits); err == nil {
		t.Error("too many hits accepted")
	}
}

func TestValidateInterfaceAddresses(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		ok   bool
	}{
		{"none", nil, true},
		{"v4 and v6", []string{"1.2.3.4", "2606:4700::1"}, true},
		{"unsorted", []string{"8.8.8.8", "1.2.3.4"}, false},
		{"duplicate", []string{"1.2.3.4", "1.2.3.4"}, false},
		{"loopback", []string{"127.0.0.1"}, false},
		{"loopback v6", []string{"::1"}, false},
		{"link local", []string{"169.254.1.1"}, false},
		{"link local v6", []string{"fe80::1"}, false},
		{"rfc1918", []string{"10.0.0.1"}, false},
		{"rfc1918 b", []string{"172.16.0.1"}, false},
		{"rfc1918 c", []string{"192.168.1.1"}, false},
		{"cgnat", []string{"100.64.0.1"}, false},
		{"ula", []string{"fd00::1"}, false},
		{"multicast", []string{"224.0.0.1"}, false},
		{"unspecified", []string{"0.0.0.0"}, false},
		{"documentation", []string{"203.0.113.1"}, false},
		{"documentation v6", []string{"2001:db8::1"}, false},
		{"mapped", []string{"::ffff:1.2.3.4"}, false},
		{"non canonical", []string{"2606:4700:0:0::1"}, false},
		{"zone", []string{"fe80::1%eth0"}, false},
		{"garbage", []string{"x"}, false},
	}
	for _, test := range tests {
		if err := ValidateInterfaceAddresses(test.in); (err == nil) != test.ok {
			t.Errorf("%s: err = %v, want ok=%v", test.name, err, test.ok)
		}
	}
	many := make([]string, MaxInterfaceAddresses+1)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)}).String()
	}
	if err := ValidateInterfaceAddresses(many[:MaxInterfaceAddresses]); err != nil {
		t.Errorf("max addresses refused: %v", err)
	}
	if err := ValidateInterfaceAddresses(many); err == nil {
		t.Error("too many addresses accepted")
	}
}
