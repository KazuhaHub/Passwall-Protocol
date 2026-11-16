package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func validForward() Forward {
	return Forward{
		Key: NewForwardKey(7), Port: 20443,
		Target: "landing.example.com", TargetPort: 443, Network: ForwardNetworkTCP,
	}
}

func TestForwardKeyRoundTripsAndIsNotAListenerKey(t *testing.T) {
	key := NewForwardKey(42)
	if key != "fwd_42" {
		t.Fatalf("minted %q", key)
	}
	if id, err := key.RowID(); err != nil || id != 42 {
		t.Fatalf("RowID = %d, %v", id, err)
	}
	// A forward key never parses as a listener, so its counters cannot be
	// booked against a nodes row.
	if _, err := ListenerKey(key).RowID(); err == nil {
		t.Fatal("a forward key parsed as a listener key")
	}
	for _, bad := range []ForwardKey{"fwd_0", "fwd_01", "fwd_-1", "fwd_+1", "lst_1", "fwd_"} {
		if _, err := bad.RowID(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidateTransit(t *testing.T) {
	if err := ValidateTransit(nil); err != nil {
		t.Fatalf("nil transit: %v", err)
	}
	ok := []func(*Forward){
		func(f *Forward) {},
		func(f *Forward) { f.Listen = "0.0.0.0" },
		func(f *Forward) { f.Listen = "2001:db8::1" },
		func(f *Forward) { f.Target = "203.0.113.9" },
		func(f *Forward) { f.Target = "2001:db8::2" },
		func(f *Forward) { f.Target = "landing" },
		func(f *Forward) { f.Target = "1.example.com" },
		func(f *Forward) { f.Target = "xn--fiqs8s.example" },
		func(f *Forward) { f.Network = ForwardNetworkTCPUDP },
		func(f *Forward) { f.Port, f.TargetPort = 65535, 1 },
	}
	for i, mutate := range ok {
		forward := validForward()
		mutate(&forward)
		if err := ValidateTransit(&Transit{Forwards: []Forward{forward}}); err != nil {
			t.Errorf("valid case %d (%+v): %v", i, forward, err)
		}
	}
	bad := map[string]func(*Forward){
		"bad key":              func(f *Forward) { f.Key = "lst_7" },
		"port zero":            func(f *Forward) { f.Port = 0 },
		"port high":            func(f *Forward) { f.Port = 65536 },
		"target port zero":     func(f *Forward) { f.TargetPort = 0 },
		"noncanonical listen":  func(f *Forward) { f.Listen = "2001:0db8::1" },
		"listen name":          func(f *Forward) { f.Listen = "localhost" },
		"empty target":         func(f *Forward) { f.Target = "" },
		"uppercase target":     func(f *Forward) { f.Target = "Landing.example.com" },
		"target with port":     func(f *Forward) { f.Target = "landing.example.com:443" },
		"bracketed target":     func(f *Forward) { f.Target = "[2001:db8::2]" },
		"trailing dot":         func(f *Forward) { f.Target = "landing.example.com." },
		"empty label":          func(f *Forward) { f.Target = "landing..example.com" },
		"hyphen edge":          func(f *Forward) { f.Target = "-landing.example.com" },
		"numeric last label":   func(f *Forward) { f.Target = "1.2.3" },
		"hex last label":       func(f *Forward) { f.Target = "0x7f000001" },
		"mapped ipv6":          func(f *Forward) { f.Target = "::ffff:192.0.2.1" },
		"zoned target":         func(f *Forward) { f.Target = "fe80::1%eth0" },
		"noncanonical v6":      func(f *Forward) { f.Target = "2001:0db8::2" },
		"oversized target":     func(f *Forward) { f.Target = strings.Repeat("a.", 127) + "com" },
		"unknown network":      func(f *Forward) { f.Network = "udp" },
		"empty network":        func(f *Forward) { f.Network = "" },
		"target is a url path": func(f *Forward) { f.Target = "landing.example.com/x" },
	}
	for name, mutate := range bad {
		forward := validForward()
		mutate(&forward)
		if err := ValidateTransit(&Transit{Forwards: []Forward{forward}}); err == nil {
			t.Errorf("%s: %+v accepted", name, forward)
		}
	}
	duplicate := &Transit{Forwards: []Forward{validForward(), validForward()}}
	if err := ValidateTransit(duplicate); err == nil {
		t.Error("duplicate forward key accepted")
	}
}

// A server with no transit lines must keep the exact config bytes it had
// before transit existed; otherwise every agent re-applies on upgrade.
func TestConfigWithoutTransitIsByteIdentical(t *testing.T) {
	b, err := json.Marshal(ConfigBody{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "transit") {
		t.Fatalf("empty config mentions transit: %s", b)
	}
	b, err = json.Marshal(ConfigBody{Transit: &Transit{Forwards: []Forward{validForward()}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"transit":{"forwards":[{"key":"fwd_7"`) {
		t.Fatalf("transit not encoded: %s", b)
	}
}

func TestForwardCountersFollowTheEnumerationRules(t *testing.T) {
	counters := []ForwardCounters{{Key: NewForwardKey(1), Present: true, UpBytes: 10, DownBytes: 20, CounterEpoch: 3}}

	full := NodeReport{
		AgentID: "a1", ProtocolVersion: ProtocolVersion1, Have: emptyHave(),
		Capabilities: []string{CapabilityTransitForward}, ForwardCounters: counters,
	}
	if err := ValidateNodeReport(full); err != nil {
		t.Fatalf("full report with forward counters: %v", err)
	}

	// Without the capability the panel sent no forwards, so counting any is a
	// producer bug. The receiver's base check does not see capabilities.
	noCapability := full
	noCapability.Capabilities = nil
	if err := ValidateNodeReport(noCapability); err == nil {
		t.Error("forward counters without the capability accepted by the sender check")
	}
	if err := ValidateNodeReportBase(noCapability); err != nil {
		t.Errorf("base check must not depend on capabilities: %v", err)
	}

	partial := full
	partial.Partial = true
	if err := ValidateNodeReportBase(partial); err == nil {
		t.Error("partial report carrying forward counters accepted")
	}
	b, err := json.Marshal(NodeReport{AgentID: "a1", Partial: true, Have: emptyHave(), ForwardCounters: counters})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "forward_counters") {
		t.Errorf("partial shape carries forward counters: %s", b)
	}

	for name, bad := range map[string][]ForwardCounters{
		"negative":     {{Key: NewForwardKey(1), DownBytes: -1}},
		"bad key":      {{Key: "lst_1"}},
		"duplicate":    {{Key: NewForwardKey(1)}, {Key: NewForwardKey(1)}},
		"noncanonical": {{Key: "fwd_01"}},
	} {
		report := full
		report.ForwardCounters = bad
		if err := ValidateNodeReportBase(report); err == nil {
			t.Errorf("%s forward counters accepted", name)
		}
	}
}

func TestForwardObjectsAreConfigObjects(t *testing.T) {
	report := NodeReport{AgentID: "a1", ProtocolVersion: ProtocolVersion1, Have: emptyHave()}
	report.Objects = []ObjectStatus{
		{Stream: StreamConfig, Key: string(NewForwardKey(3)), State: ObjectApplied, SinceVersion: Version{Epoch: 1, Version: 1}},
		{Stream: StreamConfig, Key: string(NewForwardKey(4)), State: ObjectRejected, SinceVersion: Version{Epoch: 1, Version: 1}, FirstFailedAtMS: 1, IssueCode: "core_config_rejected"},
		{Stream: StreamConfig, Key: string(NewListenerKey(3)), State: ObjectApplied, SinceVersion: Version{Epoch: 1, Version: 1}},
	}
	if err := ValidateNodeReportBase(report); err != nil {
		t.Fatalf("forward and listener objects: %v", err)
	}
	for _, bad := range []ObjectStatus{
		// A forward is never a roster object.
		{Stream: StreamRoster, Key: string(NewForwardKey(3)), State: ObjectApplied, SinceVersion: Version{Epoch: 1, Version: 1}},
		{Stream: StreamConfig, Key: "fwd_03", State: ObjectApplied, SinceVersion: Version{Epoch: 1, Version: 1}},
	} {
		report.Objects = []ObjectStatus{bad}
		if err := ValidateNodeReportBase(report); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
