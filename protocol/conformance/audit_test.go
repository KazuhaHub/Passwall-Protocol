package conformance

import (
	"encoding/json"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// The vectors are shared with Node and PSP, so this is the one place the
// protocol package is held to them. The whole receiver path is exercised: a
// decode error counts as a rejection, as it does on the panel.
func TestAuditVectors(t *testing.T) {
	if len(AuditVectors) == 0 {
		t.Fatal("no audit vectors")
	}
	seen := map[string]bool{}
	for _, vector := range AuditVectors {
		if seen[vector.Name] {
			t.Fatalf("duplicate vector name %q", vector.Name)
		}
		seen[vector.Name] = true
		t.Run(vector.Name, func(t *testing.T) {
			var observation protocol.AuditObservation
			err := json.Unmarshal([]byte(vector.JSON), &observation)
			if err == nil {
				err = protocol.ValidateAuditObservation(observation)
			}
			if vector.Valid && err != nil {
				t.Fatalf("rejected %s: %v", vector.JSON, err)
			}
			if !vector.Valid && err == nil {
				t.Fatalf("accepted %s", vector.JSON)
			}
		})
	}
}

// Every per-field rule must have a vector that breaks only it, or the three
// implementations are free to disagree on it. The names are the checklist.
func TestAuditVectorsCoverTheFieldRules(t *testing.T) {
	have := map[string]bool{}
	for _, vector := range AuditVectors {
		have[vector.Name] = true
	}
	for _, name := range []string{
		"no rows", "batch id too short", "hour not on the hour", "rule id of no known kind",
		"source rule block hit", "report-only hit on a source rule carries subject and destination",
		"report-only hit on a block policy is a would-have-been-blocked hit",
		"action allow", "block hit without a subject", "trial row for a site", "trial row for an address",
		"trial row with a subject", "trial row with a port", "trial row with an ipv4 address",
		"destination with a port", "port zero on a hit that is not a trial row", "port above 65535",
		"count zero", "first after last", "last in the next hour",
		"duplicate hit key", "duplicate usage key", "same key but another action is another row",
		"usage row for an address", "usage site is an ipv4 address", "ip token on a hit that is not a trial row",
		"source rule with a suffix", "group allow rule never hits", "ipv4-mapped ipv6 destination",
		"ipv6 destination", "idn destination in punycode", "single-label destination", "port 1",
		"destination of 253 bytes", "destination of 254 bytes", "destination label of 64 bytes",
		"dropped_hits above int64", "dropped_trial above int64", "dropped_usage above int64",
		"usage site that is a single-label host", "usage site that is a public suffix",
		"trial row for a host that is a public suffix", "usage site with a numeric last label",
		"usage site with a numeric first label", "usage site as a hex number", "trial row with padded octets",
	} {
		if !have[name] {
			t.Errorf("no vector named %q", name)
		}
	}
}
