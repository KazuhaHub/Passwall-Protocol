package protocol_test

import (
	"reflect"
	"testing"

	protocol "github.com/KazuhaHub/passwall-protocol/protocol"
)

// The point of GenerationRange is that a shared-library upgrade cannot widen a
// product's supported generations. These tests hold that: the same observation
// is supported or not depending on what the CALLER declared, and the deprecated
// wrapper keeps the old compiled range rather than becoming permissive.
func TestSupportFollowsTheCallersDeclaredRange(t *testing.T) {
	caps := protocol.AgentUpgradeCapabilities()

	// A product that speaks only generation 1.
	narrow := protocol.AssessCompatibilityIn(2, caps, protocol.GenerationRange{Min: 1, Max: 1})
	if narrow.ProtocolSupported || narrow.AgentUpgrade {
		t.Fatalf("a generation-1 product accepted a generation-2 report: %+v", narrow)
	}
	if narrow.EffectiveProtocolVersion != 2 {
		t.Fatalf("the reported generation must be carried through unchanged: %+v", narrow)
	}

	// The same report, from a product that has declared it speaks generation 2.
	wide := protocol.AssessCompatibilityIn(2, caps, protocol.GenerationRange{Min: 1, Max: 2})
	if !wide.ProtocolSupported || !wide.AgentUpgrade {
		t.Fatalf("a generation-2 product refused a generation-2 report: %+v", wide)
	}
}

func TestTheDeprecatedWrapperKeepsTheOldRange(t *testing.T) {
	// This is the one that matters for existing callers: the wrapper must not
	// have become "supports everything" as a side effect of the refactor.
	compiled := protocol.SupportedGenerationRange()
	if compiled.Min != protocol.MinSupportedProtocolVersion || compiled.Max != protocol.MaxSupportedProtocolVersion {
		t.Fatalf("SupportedGenerationRange = %+v, want the compiled %d..%d",
			compiled, protocol.MinSupportedProtocolVersion, protocol.MaxSupportedProtocolVersion)
	}
	caps := protocol.AgentUpgradeCapabilities()
	for reported := -1; reported <= 3; reported++ {
		deprecated := protocol.AssessCompatibility(reported, caps)
		explicit := protocol.AssessCompatibilityIn(reported, caps, compiled)
		if !reflect.DeepEqual(deprecated, explicit) {
			t.Fatalf("reported=%d: the deprecated wrapper and the explicit call disagree: %+v vs %+v",
				reported, deprecated, explicit)
		}
	}
}

// A generation the package does not know is NOT supported merely because it was
// passed in: EffectiveProtocolVersion carries the legacy zero mapping and
// nothing else, so an unknown number stays unknown.
func TestUnknownGenerationsAreNotMappedIntoSupport(t *testing.T) {
	if got := protocol.EffectiveProtocolVersion(0); got != protocol.ProtocolVersion1 {
		t.Fatalf("the legacy zero mapping changed: 0 -> %d", got)
	}
	if got := protocol.EffectiveProtocolVersion(7); got != 7 {
		t.Fatalf("an unknown generation was rewritten: 7 -> %d", got)
	}
	comp := protocol.AssessCompatibilityIn(7, protocol.AgentUpgradeCapabilities(), protocol.GenerationRange{Min: 1, Max: 1})
	if comp.ProtocolSupported {
		t.Fatal("generation 7 was reported as supported")
	}
}
