package conformance

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func checkVectors(t *testing.T, vectors []ProbeVector, validate func(string) error) {
	t.Helper()
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	seen := map[string]bool{}
	for _, vector := range vectors {
		if seen[vector.Name] {
			t.Fatalf("duplicate vector name %q", vector.Name)
		}
		seen[vector.Name] = true
		t.Run(vector.Name, func(t *testing.T) {
			err := validate(vector.JSON)
			if vector.Valid && err != nil {
				t.Fatalf("rejected %s: %v", vector.JSON, err)
			}
			if !vector.Valid && err == nil {
				t.Fatalf("accepted %s", vector.JSON)
			}
		})
	}
}

// The vectors are shared with Node and PSP; a decode error counts as a
// rejection, as it does on the receiving side.
func TestProbeTransitVectors(t *testing.T) {
	checkVectors(t, ProbeTransitVectors, func(raw string) error {
		var transit protocol.Transit
		if err := json.Unmarshal([]byte(raw), &transit); err != nil {
			return err
		}
		return protocol.ValidateTransit(&transit)
	})
}

func TestRouteTransitVectors(t *testing.T) {
	checkVectors(t, RouteTransitVectors, func(raw string) error {
		var transit protocol.Transit
		if err := json.Unmarshal([]byte(raw), &transit); err != nil {
			return err
		}
		return protocol.ValidateTransit(&transit)
	})
}

func TestRouteExitsVectors(t *testing.T) {
	checkVectors(t, RouteExitsVectors, func(raw string) error {
		var policy protocol.DestinationPolicy
		if err := json.Unmarshal([]byte(raw), &policy); err != nil {
			return err
		}
		return protocol.ValidateDestinationPolicy(&policy)
	})
}

func TestRouteMatchVectors(t *testing.T) {
	if err := protocol.ValidateTransit(&routeTransit); err != nil {
		t.Fatalf("the vectors' transit is invalid: %v", err)
	}
	seen := map[string]bool{}
	for _, vector := range RouteMatchVectors {
		if seen[vector.Name] {
			t.Fatalf("duplicate vector name %q", vector.Name)
		}
		seen[vector.Name] = true
		t.Run(vector.Name, func(t *testing.T) {
			got, known := protocol.MatchRoute(vector.Transit, vector.Listener, vector.Input, vector.Resolve)
			if got != vector.Exit || known == vector.Conditional {
				t.Fatalf("exit = %q known=%v, want %q conditional=%v", got, known, vector.Exit, vector.Conditional)
			}
		})
	}
}

func TestIntersectVectors(t *testing.T) {
	seen := map[string]bool{}
	for _, vector := range IntersectVectors {
		if seen[vector.Name] {
			t.Fatalf("duplicate vector name %q", vector.Name)
		}
		seen[vector.Name] = true
		t.Run(vector.Name, func(t *testing.T) {
			got, exact := protocol.IntersectDestinations(vector.A, vector.B)
			if exact != vector.Exact || !reflect.DeepEqual(got, vector.Want) {
				t.Fatalf("got %+v exact=%v, want %+v exact=%v", got, exact, vector.Want, vector.Exact)
			}
		})
	}
}

func TestProbeResultVectors(t *testing.T) {
	checkVectors(t, ProbeResultVectors, func(raw string) error {
		var results []protocol.ProbeResult
		if err := json.Unmarshal([]byte(raw), &results); err != nil {
			return err
		}
		return protocol.ValidateProbeResults(results)
	})
}
