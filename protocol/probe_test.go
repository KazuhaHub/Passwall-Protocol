package protocol

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func probeResult(key, kind string) ProbeResult {
	return ProbeResult{Key: key, Kind: kind, Attempts: 10, Failures: 1, RTTMinMS: 5, RTTMedianMS: 7, RTTMaxMS: 9,
		LastError: ProbeErrorTimeout, LastSuccessMS: 1700000000000}
}

func probeReport(partial bool) NodeReport {
	return NodeReport{
		AgentID: "a1", ProtocolVersion: ProtocolVersion1, Have: emptyHave(),
		Capabilities: []string{CapabilityTransitProbe, CapabilityTransitLink, CapabilityTransitForward},
		Partial:      partial,
		Probes: []ProbeResult{
			probeResult("lnk_1", ProbeKindE2E), probeResult("lnk_1", ProbeKindTransport), probeResult("fwd_7", ProbeKindForward),
		},
	}
}

func TestProbeCapabilityName(t *testing.T) {
	if CapabilityTransitProbe != "transit.probe.v1" {
		t.Fatalf("capability name changed: %q", CapabilityTransitProbe)
	}
	for _, upgrade := range AgentUpgradeCapabilities() {
		if upgrade == CapabilityTransitProbe {
			t.Fatalf("%s is an upgrade capability", upgrade)
		}
	}
}

// The golden strings were written from the v0.8.x encoding, before Probe and
// Probes existed. A server that is not probed must keep producing exactly
// these bytes, or every agent in the fleet re-applies its config.
func TestTransitWithoutProbeIsByteIdenticalToV08(t *testing.T) {
	transit := Transit{Forwards: []Forward{validForward()}}
	const want = `{"forwards":[{"key":"fwd_7","port":20443,"target":"landing.example.com","target_port":443,"network":"tcp"}]}`
	got, err := json.Marshal(transit)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("transit without Probe changed on the wire:\n got=%s\nwant=%s", got, want)
	}
}

func TestNodeReportWithoutProbesIsByteIdenticalToV08(t *testing.T) {
	report := NodeReport{
		AgentID: "a1", ProtocolVersion: ProtocolVersion1, Have: map[string]StreamState{"config": {ETag: "e3"}},
		Capabilities: []string{CapabilityTransitLink},
		LinkCounters: []LinkCounters{{Key: "lnk_1", Present: true, UpBytes: 1, DownBytes: 2, CounterEpoch: 3}},
	}
	const full = `{"agent_id":"a1","protocol_version":1,"capabilities":["transit.link.v1"],"partial":false,"have":{"config":{"applied":{"epoch":0,"version":0},"etag":"e3"}},"objects":[],"listener_counters":[],"link_counters":[{"key":"lnk_1","present":true,"up_bytes":1,"down_bytes":2,"counter_epoch":3}],"clients":[]}`
	const partial = `{"agent_id":"a1","protocol_version":1,"capabilities":["transit.link.v1"],"partial":true,"have":{"config":{"applied":{"epoch":0,"version":0},"etag":"e3"}}}`
	got, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != full {
		t.Fatalf("a full report without Probes changed on the wire:\n got=%s\nwant=%s", got, full)
	}
	report.Partial = true
	got, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != partial {
		t.Fatalf("a partial report without Probes changed on the wire:\n got=%s\nwant=%s", got, partial)
	}
}

func TestProbesRoundTripOnFullReport(t *testing.T) {
	report := probeReport(false)
	wire, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"probes":[{"key":"lnk_1","kind":"e2e","attempts":10`) {
		t.Fatalf("probes missing from %s", wire)
	}
	var decoded NodeReport
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Probes, report.Probes) {
		t.Fatalf("probes did not round trip:\n got=%+v\nwant=%+v", decoded.Probes, report.Probes)
	}
	if err := ValidateNodeReport(report); err != nil {
		t.Fatalf("full report with probes: %v", err)
	}
}

// Probes are a full-report enumeration. The partial shape is a second,
// hand-written struct, so this test is the guard that nobody adds Probes to it:
// a partial report that carried them would be the cadence split undone.
func TestProbesAreNeverOnAPartialReport(t *testing.T) {
	wire, err := json.Marshal(probeReport(true))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "probes") {
		t.Fatalf("a partial report encodes probes: %s", wire)
	}
	if err := ValidateNodeReportBase(probeReport(true)); err == nil {
		t.Error("partial report carrying probes accepted")
	}
}

func TestProbesNeedTheCapabilityOnTheSender(t *testing.T) {
	report := probeReport(false)
	report.Capabilities = []string{CapabilityTransitLink, CapabilityTransitForward}
	if err := ValidateNodeReport(report); err == nil {
		t.Error("probes accepted without the capability")
	}
	// The receiver's base check does not bind capabilities, like link counters.
	if err := ValidateNodeReportBase(report); err != nil {
		t.Errorf("base check refused a capability-less report: %v", err)
	}
}

func TestProbeResultsInReportAreValidated(t *testing.T) {
	report := probeReport(false)
	report.Probes[0].Failures = report.Probes[0].Attempts + 1
	if err := ValidateNodeReportBase(report); err == nil {
		t.Error("report with an invalid probe accepted")
	}
}

func TestProbeResultsCountLimit(t *testing.T) {
	results := make([]ProbeResult, 0, MaxProbes+1)
	for i := 0; i <= MaxProbes; i++ {
		results = append(results, ProbeResult{Key: string(NewForwardKey(int64(i + 1))), Kind: ProbeKindForward})
	}
	if err := ValidateProbeResults(results[:MaxProbes]); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if err := ValidateProbeResults(results); err == nil {
		t.Error("over the limit accepted")
	}
}

func TestProbeSettingsInTransit(t *testing.T) {
	settings := func() *ProbeSettings {
		return &ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000, LinkURL: "https://example.com/generate_204",
			Forwards: []ProbeTarget{{Key: NewForwardKey(7), Method: ProbeMethodTCP}}}
	}
	transit := Transit{Forwards: []Forward{validForward()}, Probe: settings()}
	if err := ValidateTransit(&transit); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(transit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"probe":{"interval_seconds":60,"timeout_ms":3000,"link_url":"https://example.com/generate_204","forwards":[{"key":"fwd_7","method":"tcp"}]}`) {
		t.Fatalf("unexpected encoding: %s", wire)
	}

	// Only LinksOut makes probing meaningful on a server with no forwards.
	linkOnly := Transit{LinksOut: []LinkOut{ssLinkOut(1)}, Probe: &ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000}}
	if err := ValidateTransit(&linkOnly); err != nil {
		t.Fatalf("probing links only: %v", err)
	}
	// A LinkIn is not probed from here, so it does not make settings meaningful.
	exitOnly := Transit{LinksIn: []LinkIn{ssLinkIn(1, 30001)}, Probe: &ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000}}
	if err := ValidateTransit(&exitOnly); err == nil {
		t.Error("probe settings on an exit-only server accepted")
	}
	if err := ValidateTransit(&Transit{Probe: settings()}); err == nil {
		t.Error("probe settings on an empty transit accepted")
	}
	long := Transit{Forwards: []Forward{validForward()}, Probe: &ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000,
		LinkURL: "https://example.com/" + strings.Repeat("a", MaxProbeLinkURLBytes)}}
	if err := ValidateTransit(&long); err == nil {
		t.Error("oversized link_url accepted")
	}
}

// Forwards that exist but are not named are not probed, so settings that name
// none and have no link to probe measure nothing.
func TestProbeSettingsNeedSomethingNamedToProbe(t *testing.T) {
	bare := &ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000}
	if err := ValidateTransit(&Transit{Forwards: []Forward{validForward()}, Probe: bare}); err == nil {
		t.Fatal("settings naming no forward, on a server with no links out, accepted")
	}
	if err := ValidateTransit(&Transit{Forwards: []Forward{validForward()}, LinksOut: []LinkOut{ssLinkOut(1)}, Probe: bare}); err != nil {
		t.Fatalf("a link out is something to probe: %v", err)
	}
}

func TestQUICProbeNeedsAForwardWithUDP(t *testing.T) {
	quic := &ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000, Forwards: []ProbeTarget{{Key: NewForwardKey(7), Method: ProbeMethodQUIC}}}
	tcpOnly := validForward()
	if err := ValidateTransit(&Transit{Forwards: []Forward{tcpOnly}, Probe: quic}); err == nil {
		t.Fatal("a quic probe of a tcp-only forward accepted")
	}
	withUDP := validForward()
	withUDP.Network = ForwardNetworkTCPUDP
	if err := ValidateTransit(&Transit{Forwards: []Forward{withUDP}, Probe: quic}); err != nil {
		t.Fatalf("a quic probe of a tcp,udp forward rejected: %v", err)
	}
	// TCP probes any forward.
	tcp := &ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000, Forwards: []ProbeTarget{{Key: NewForwardKey(7), Method: ProbeMethodTCP}}}
	if err := ValidateTransit(&Transit{Forwards: []Forward{tcpOnly}, Probe: tcp}); err != nil {
		t.Fatalf("a tcp probe rejected: %v", err)
	}
}
