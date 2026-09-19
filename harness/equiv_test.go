// Package equiv proves the extracted Passwall-Protocol package behaves the same
// as the passwall-node/protocol package it was copied from.
//
// It is an ISOLATED HARNESS, not a dependency of either product: it imports both
// implementations at once and compares them, which neither product can do. The
// source-level proof (diff shows only three import paths changed) is necessary
// but not sufficient — what matters is that the observable behaviour is the same,
// and the pieces that are easiest to break silently are the digests and the
// canonical encodings, neither of which a reader can eyeball.
package equiv

import (
	"encoding/json"
	"reflect"
	"testing"

	old "github.com/KazuhaHub/passwall-node/protocol"
	new_ "github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestConstantsAreIdentical(t *testing.T) {
	for _, c := range []struct {
		name     string
		oldValue any
		newValue any
	}{
		{"ProtocolVersion1", old.ProtocolVersion1, new_.ProtocolVersion1},
		{"MaxSyncBodyBytes", old.MaxSyncBodyBytes, new_.MaxSyncBodyBytes},
		{"DiagnosticsSchemaVersion", old.DiagnosticsSchemaVersion, new_.DiagnosticsSchemaVersion},
		{"CapabilityHostTelemetry", old.CapabilityHostTelemetry, new_.CapabilityHostTelemetry},
		{"TaskKindAgentUpgradeV1", old.TaskKindAgentUpgradeV1, new_.TaskKindAgentUpgradeV1},
		{"TaskKindDiagnosticsCollectV1", old.TaskKindDiagnosticsCollectV1, new_.TaskKindDiagnosticsCollectV1},
		{"IssueHostTelemetryFailed", old.IssueHostTelemetryFailed, new_.IssueHostTelemetryFailed},
	} {
		if !reflect.DeepEqual(c.oldValue, c.newValue) {
			t.Errorf("%s: old=%v new=%v", c.name, c.oldValue, c.newValue)
		}
	}
}

// The task input digest is the value a node and a panel must agree on exactly:
// it is what makes a replayed task the same task and a changed task a different
// one. It is computed over a domain-separated byte string, so a changed domain
// constant, a changed encoding or a changed separator all show up here.
func TestTaskInputDigestsAreIdentical(t *testing.T) {
	kinds := []string{
		old.TaskKindAgentUpgradeV1,
		old.TaskKindDiagnosticsCollectV1,
		"task.unknown.v9",
		"",
	}
	args := []string{
		`{"version":"v0.0.1-beta11","expected_version":"v0.0.1-beta9"}`,
		`{"sections":["system","network"]}`,
		`{}`,
		`null`,
		`[1,2,3]`,
		`{"z":1,"a":{"nested":[true,null,"é"]}}`,
		"",
	}
	for _, kind := range kinds {
		for _, a := range args {
			got := old.ComputeTaskInputSHA256(kind, []byte(a))
			want := new_.ComputeTaskInputSHA256(kind, []byte(a))
			if got != want {
				t.Errorf("digest mismatch kind=%q args=%q: old=%s new=%s", kind, a, got, want)
			}
			// Guard against a vacuous pass: the digest must actually vary.
			if other := old.ComputeTaskInputSHA256(kind+"x", []byte(a)); other == got {
				t.Errorf("digest did not change with the kind: kind=%q args=%q", kind, a)
			}
		}
	}
}

func TestCapabilityAndCompatibilitySurfacesAgree(t *testing.T) {
	if !reflect.DeepEqual(old.AgentUpgradeCapabilities(), new_.AgentUpgradeCapabilities()) {
		t.Fatalf("AgentUpgradeCapabilities: %v vs %v", old.AgentUpgradeCapabilities(), new_.AgentUpgradeCapabilities())
	}
	caps := [][]string{
		nil,
		{},
		old.AgentUpgradeCapabilities(),
		{old.CapabilityTaskExecutionV1},
		{old.CapabilityTaskExpiryV1, old.TaskCapability(old.TaskKindAgentUpgradeV1)},
		{"task.unknown.v9"},
	}
	for reported := -1; reported <= 3; reported++ {
		for _, c := range caps {
			// The two Compatibility types are DISTINCT named types, so they are
			// not comparable and reflect.DeepEqual would report a difference
			// even for identical fields. Compare what travels: the JSON.
			a, _ := json.Marshal(old.AssessCompatibility(reported, c))
			b, _ := json.Marshal(new_.AssessCompatibility(reported, c))
			if string(a) != string(b) {
				t.Errorf("AssessCompatibility(%d, %v):\n old=%s\n new=%s", reported, c, a, b)
			}
		}
		if old.EffectiveProtocolVersion(reported) != new_.EffectiveProtocolVersion(reported) {
			t.Errorf("EffectiveProtocolVersion(%d) differs", reported)
		}
	}
}

func TestSchedulingAndKeyHelpersAgree(t *testing.T) {
	for _, n := range []int{-1, 0, 1, 60, 300, 86400} {
		if old.EffectiveFullReportPeriod(n, 60) != new_.EffectiveFullReportPeriod(n, 60) {
			t.Errorf("EffectiveFullReportPeriod(%d,60) differs", n)
		}
		if old.EffectiveHostReportPeriod(n, 60) != new_.EffectiveHostReportPeriod(n, 60) {
			t.Errorf("EffectiveHostReportPeriod(%d,60) differs", n)
		}
		if old.ShouldSendFull(old.Envelope{}, n) != new_.ShouldSendFull(new_.Envelope{}, n) {
			t.Errorf("ShouldSendFull(%d) differs", n)
		}
		if old.ShouldSendHost(old.Envelope{}, n) != new_.ShouldSendHost(new_.Envelope{}, n) {
			t.Errorf("ShouldSendHost(%d) differs", n)
		}
	}
	for _, kind := range []string{"agent.upgrade.v1", "", "x.y"} {
		if old.TaskCapability(kind) != new_.TaskCapability(kind) {
			t.Errorf("TaskCapability(%q) differs", kind)
		}
	}
	for _, id := range []int64{0, 1, -1, 1 << 40} {
		// The key types are distinct named types in the two packages, so compare
		// their textual form -- which is also what travels on the wire.
		if string(old.NewListenerKey(id)) != string(new_.NewListenerKey(id)) ||
			string(old.NewClientKey(id)) != string(new_.NewClientKey(id)) ||
			string(old.NewSubjectKey(id)) != string(new_.NewSubjectKey(id)) {
			t.Errorf("key construction differs at id=%d", id)
		}
	}
	if !(old.Converged("a", "a") == new_.Converged("a", "a") && old.Converged("a", "b") == new_.Converged("a", "b")) {
		t.Error("Converged differs")
	}
	for _, s := range []string{"", "system", "nope"} {
		if old.IsDiagnosticsSection(s) != new_.IsDiagnosticsSection(s) {
			t.Errorf("IsDiagnosticsSection(%q) differs", s)
		}
		if old.IsDiagnosticsEventCode(s) != new_.IsDiagnosticsEventCode(s) {
			t.Errorf("IsDiagnosticsEventCode(%q) differs", s)
		}
	}
}

// JSON is the wire. Round-tripping the same document through each package and
// comparing the re-encoded bytes proves the tags, omitempty choices and field
// types all still agree — which a source diff of struct tags could, but only if
// the reader noticed every one.
func TestCanonicalJSONIsByteIdentical(t *testing.T) {
	type pair struct {
		name string
		doc  string
	}
	docs := []pair{
		{"envelope", `{"protocol_version":1,"node_id":7,"etag":"abc","full_report_seconds":300,"host_report_seconds":60}`},
		{"node-report-empty", `{}`},
		{"node-report-config", `{"envelope":{"protocol_version":1,"node_id":7,"etag":"abc"},"config":{"etag":"abc","want":{"inbounds":[]}}}`},
		{"host-observation", `{"deployment":"systemd","resource_scope":"system","platform":{"os":"linux","arch":"amd64"},"cpu":{"system":{"user_percent":1.5},"cgroup":{"limit_cores":2,"quota_percent":12.5}},"load":{"one":0.5},"memory":{"system":{"total_bytes":1024,"available_bytes":512}}} `},
		{"diagnostics-result", `{"schema_version":1,"task_id":"t1","sections":["system"],"checks":[{"name":"c","status":"ok"}],"events":[]}`},
	}
	for _, d := range docs {
		t.Run(d.name, func(t *testing.T) {
			compareRoundTrip(t, d.doc)
		})
	}
}

// compareRoundTrip decodes the document into each package's own types, re-encodes
// it, and requires the bytes to match. It also requires both packages to accept
// or reject the document together, so a validation rule that moved or changed is
// visible here rather than at a node.
func compareRoundTrip(t *testing.T, doc string) {
	t.Helper()
	oldJSON := reencode[old.NodeReport](t, doc)
	newJSON := reencode[new_.NodeReport](t, doc)
	if oldJSON != newJSON {
		t.Errorf("NodeReport re-encode differs:\n old=%s\n new=%s", oldJSON, newJSON)
	}
	oldEnv := reencode[old.Envelope](t, doc)
	newEnv := reencode[new_.Envelope](t, doc)
	if oldEnv != newEnv {
		t.Errorf("Envelope re-encode differs:\n old=%s\n new=%s", oldEnv, newEnv)
	}
	oldHost := reencode[old.HostObservation](t, doc)
	newHost := reencode[new_.HostObservation](t, doc)
	if oldHost != newHost {
		t.Errorf("HostObservation re-encode differs:\n old=%s\n new=%s", oldHost, newHost)
	}
}

func reencode[T any](t *testing.T, doc string) string {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		return "unmarshal-error: " + err.Error()
	}
	out, err := json.Marshal(v)
	if err != nil {
		return "marshal-error: " + err.Error()
	}
	return string(out)
}
