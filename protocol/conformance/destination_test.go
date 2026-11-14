package conformance

import (
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// The vectors are shared with Node and PSP, so this is the one place the
// protocol package is held to them.
func TestSniffingVectors(t *testing.T) {
	if len(SniffingVectors) == 0 {
		t.Fatal("no sniffing vectors")
	}
	seen := map[string]bool{}
	for _, vector := range SniffingVectors {
		if seen[vector.Name] {
			t.Fatalf("duplicate vector name %q", vector.Name)
		}
		seen[vector.Name] = true
		t.Run(vector.Name, func(t *testing.T) {
			verdict, reason, err := protocol.CheckXraySniffing([]byte(vector.Raw), vector.Need)
			if vector.Malformed {
				if err == nil {
					t.Fatalf("accepted malformed sniffing %q: %s %s", vector.Raw, verdict, reason)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict != vector.Verdict || reason != vector.Reason {
				t.Fatalf("got (%s, %q), want (%s, %q)", verdict, reason, vector.Verdict, vector.Reason)
			}
		})
	}
}

func TestDestinationMatchVectors(t *testing.T) {
	if len(DestinationMatchVectors) == 0 {
		t.Fatal("no match vectors")
	}
	seen := map[string]bool{}
	for _, vector := range DestinationMatchVectors {
		if seen[vector.Name] {
			t.Fatalf("duplicate vector name %q", vector.Name)
		}
		seen[vector.Name] = true
		t.Run(vector.Name, func(t *testing.T) {
			// A vector over an invalid policy would pin behaviour no peer can
			// ever be asked to exhibit.
			if err := protocol.ValidateDestinationPolicy(vector.Policy); err != nil {
				t.Fatalf("vector policy is invalid: %v", err)
			}
			got := protocol.MatchDestination(vector.Policy, vector.Input)
			if got.Verdict != vector.Verdict || got.Terminated != vector.Terminated ||
				got.ExemptHit != vector.ExemptHit || got.Conditional != vector.Conditional {
				t.Fatalf("got verdict=%s terminated=%q exempt=%v conditional=%v, want verdict=%s terminated=%q exempt=%v conditional=%v\nsteps=%+v",
					got.Verdict, got.Terminated, got.ExemptHit, got.Conditional,
					vector.Verdict, vector.Terminated, vector.ExemptHit, vector.Conditional, got.Steps)
			}
			if len(got.Notes) != len(vector.Notes) {
				t.Fatalf("notes: got %v, want %v", got.Notes, vector.Notes)
			}
			for i, want := range vector.Notes {
				if got.Notes[i] != want {
					t.Fatalf("note %d: got %q, want %q", i, got.Notes[i], want)
				}
			}
			if len(vector.Steps) == 0 {
				return
			}
			if len(got.Steps) != len(vector.Steps) {
				t.Fatalf("got %d steps, want %d: %+v", len(got.Steps), len(vector.Steps), got.Steps)
			}
			for i, want := range vector.Steps {
				if got.Steps[i] != want {
					t.Fatalf("step %d: got %+v, want %+v", i, got.Steps[i], want)
				}
			}
		})
	}
}

// Every bullet of the matching semantics must be covered by a vector. The
// names are the checklist: a bullet with no vector is a behaviour the three
// implementations are free to disagree on.
func TestDestinationMatchVectorsCoverTheSemantics(t *testing.T) {
	have := map[string]bool{}
	for _, vector := range DestinationMatchVectors {
		have[vector.Name] = true
	}
	for _, name := range []string{
		"domain suffix on label boundary", "domain suffix not mid-label", "domain matches itself",
		"full requires equality", "keyword is a substring", "regexp is unanchored",
		"hostname never matches cidrs", "trailing dot: domain does not match, the builtin blocks", "trailing dot: full does not match, the builtin blocks",
		"trailing dot: anchored regexp does not match, the builtin blocks", "trailing dot: keyword still matches the host as written",
		"trailing dot: unanchored regexp still matches the host as written", "trailing dot: the builtin sits after the exempt list",
		"trailing dot: the builtin sits before block rules", "trailing dot: no builtin without a block rule over domains",
		"uppercase host is lowercased, as xray-core's router does", "hostname against private and cidr rules gets one note",
		"a hostname that hits a domain rule gets no note",
		"surrounding spaces are trimmed", "bracketed ipv6 target", "ipv4 with a leading zero is a hostname",
		"ipv6 with a zone is a hostname", "unknown network value is untestable", "hostname never matches private", "ip never matches domains",
		"ipv4-mapped ipv6 is unmapped",
		"private table hit", "private table miss",
		"protocols are untestable", "ports unknown is untestable", "inbound unknown is untestable",
		"source unknown is untestable", "network unknown is untestable",
		"subjects restrict the rule", "empty subjects mean everyone",
		"allow beats block", "exempt beats block", "exempt does not beat allow order",
		"exempt hit marks the result", "source deny runs first", "group allow after global block",
		"catch-all group block", "observe is recorded and terminates",
		"later hit is shadowed", "later miss is skipped", "conditional after untestable",
		"on_demand: a resolved address in a blocked cidr blocks the hostname", "on_demand: any resolved address is enough",
		"on_demand: private table on a resolved address", "on_demand: no resolution given makes the ip rule untestable",
		"on_demand: an empty resolution misses and is engine dependent", "as_is: resolved addresses are ignored",
		"default when nothing hits", "fields are anded", "port range", "network mismatch",
	} {
		if !have[name] {
			t.Errorf("no vector named %q", name)
		}
	}
}
