package protocol

// MinSupportedProtocolVersion and MaxSupportedProtocolVersion bound the wire
// generations that may share /v1/node/sync. ProtocolVersion1 is additive, so
// this range advances only after an explicit compatibility review. A breaking
// generation uses a parallel endpoint instead of silently widening this range.
const (
	MinSupportedProtocolVersion = ProtocolVersion1
	MaxSupportedProtocolVersion = ProtocolVersion1
)

// Compatibility is the control plane's interpretation of one authenticated
// report. It deliberately separates the base sync protocol from optional task
// capabilities: an older agent may remain fully usable for configuration and
// traffic while being ineligible for remote upgrade.
type Compatibility struct {
	ReportedProtocolVersion  int
	EffectiveProtocolVersion int
	ProtocolSupported        bool
	TaskExecution            bool
	TaskExpiry               bool
	AgentUpgrade             bool
	MissingAgentUpgrade      []string
}

// EffectiveProtocolVersion maps the omitted version used by the first v1
// peers to v1. This legacy rule is part of the public wire contract and must be
// removed only with an explicit compatibility-matrix change.
func EffectiveProtocolVersion(reported int) int {
	if reported == 0 {
		return ProtocolVersion1
	}
	return reported
}

// AgentUpgradeCapabilities returns the complete fail-closed capability set
// required before PSP may create an agent.upgrade.v1 task. A new optional
// upgrade generation must introduce a new task capability rather than changing
// the meaning of this list in place.
func AgentUpgradeCapabilities() []string {
	return []string{
		CapabilityTaskExecutionV1,
		CapabilityTaskExpiryV1,
		TaskCapability(TaskKindAgentUpgradeV1),
	}
}

// GenerationRange is the range of wire generations a PRODUCT declares it
// supports.
//
// IT IS THE CALLER'S, NOT THIS PACKAGE'S. This package defines what the wire
// generations are and what an assessment means; which of them a given binary
// speaks is a property of that binary. When the two were the same value, adding
// a generation here silently widened every consumer's support — a shared
// dependency upgrade would have granted a capability no product had reviewed.
// A product that supports a new generation now has to say so, and the change is
// visible in its own repository rather than arriving through a version bump.
type GenerationRange struct {
	Min int
	Max int
}

// SupportedGenerationRange is the range THIS PACKAGE was compiled against. It is
// the historical value, kept so the deprecated AssessCompatibility below keeps
// its exact behaviour. New code should pass its own range to
// AssessCompatibilityIn.
func SupportedGenerationRange() GenerationRange {
	return GenerationRange{Min: MinSupportedProtocolVersion, Max: MaxSupportedProtocolVersion}
}

// AssessCompatibilityIn evaluates a durable protocol/capability observation
// against a range the CALLER declares.
//
// It is intentionally pure so PSP's server DTO, task admission and migration
// tooling can all use the same decision without drifting.
func AssessCompatibilityIn(reported int, capabilities []string, supported GenerationRange) Compatibility {
	effective := EffectiveProtocolVersion(reported)
	result := Compatibility{
		ReportedProtocolVersion:  reported,
		EffectiveProtocolVersion: effective,
		ProtocolSupported:        effective >= supported.Min && effective <= supported.Max,
	}
	present := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		present[capability] = struct{}{}
	}
	_, result.TaskExecution = present[CapabilityTaskExecutionV1]
	_, result.TaskExpiry = present[CapabilityTaskExpiryV1]
	for _, required := range AgentUpgradeCapabilities() {
		if _, ok := present[required]; !ok {
			result.MissingAgentUpgrade = append(result.MissingAgentUpgrade, required)
		}
	}
	result.AgentUpgrade = result.ProtocolSupported && len(result.MissingAgentUpgrade) == 0
	return result
}

// AssessCompatibility evaluates an observation against the range compiled into
// this package.
//
// Deprecated: it lets a shared-library upgrade decide a product's supported
// generations. Use AssessCompatibilityIn with the caller's own range. This
// wrapper is kept because removing it is a public API change with its own
// notice period, and it deliberately keeps the OLD semantics — it does not
// become "supports everything".
func AssessCompatibility(reported int, capabilities []string) Compatibility {
	return AssessCompatibilityIn(reported, capabilities, SupportedGenerationRange())
}
