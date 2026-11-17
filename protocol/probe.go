package protocol

import (
	"fmt"
	"net/url"
)

// CapabilityTransitProbe says the agent runs the link and forward self-test
// described by Transit.Probe and enumerates NodeReport.Probes on full reports.
//
// IT GATES SENDING. An agent that does not know the field ignores it, so the
// panel would show "never probed" for a line that nobody is measuring, which
// reads as a healthy silence. PSP must send Transit.Probe only to an agent that
// declared it, and an agent that did not declare it must never send Probes
// (ValidateNodeReport refuses them). ValidateTransit cannot see capabilities.
//
// It is not an upgrade capability.
const CapabilityTransitProbe = "transit.probe.v1"

// Probe kinds. A link has two results because they answer different questions:
// "transport" is whether the tunnel to the exit is up, "e2e" is whether
// traffic gets through the exit to the internet. Telling them apart is what
// lets the panel say which half is broken.
const (
	ProbeKindE2E       = "e2e"
	ProbeKindTransport = "transport"
	ProbeKindForward   = "forward"
)

// Probe methods for a forward. A forward is probed by dialing it, never by
// sending anything through it, so the landing sees no traffic it could mistake
// for a user.
const (
	ProbeMethodTCP  = "tcp"
	ProbeMethodQUIC = "quic"
	// ProbeMethodTLS sends a ClientHello naming a server name of the forward's
	// front route, and succeeds on a ServerHello. The name is the first of the
	// first route, in Front.Routes order and across Transit.Fronts order, that
	// targets the forward (server names are sorted, so "first" is the least).
	// It is what a forward behind a front must be probed with: a plain TCP
	// connect would only show that the front is up, not that the route reaches
	// the landing, so ProbeMethodTCP is refused for it. Valid only for a forward
	// that is a front route target; one that is only a front's default has no
	// name to send and may be probed with ProbeMethodTCP, which then reaches the
	// default.
	ProbeMethodTLS = "tls"
)

// Probe error classes. A stable set and not free text: the panel groups and
// alerts on these, and a free-form string would let one agent's wording become
// another's separate alert.
const (
	ProbeErrorTimeout          = "timeout"
	ProbeErrorRefused          = "refused"
	ProbeErrorTLS              = "tls"
	ProbeErrorHTTPStatus       = "http_status"
	ProbeErrorDNS              = "dns"
	ProbeErrorProbeUnavailable = "probe_unavailable"
	ProbeErrorOther            = "other"
)

// Limits on probing. The bounds exist so a bad config cannot turn the self-test
// into load: at the floor every link and forward is touched twice a minute.
const (
	MinProbeIntervalSeconds = 30
	MaxProbeIntervalSeconds = 3600
	MinProbeTimeoutMS       = 500
	MaxProbeTimeoutMS       = 10000
	MaxProbeLinkURLBytes    = 512
	// MaxProbeAttempts bounds one result's window. Attempts and failures are
	// counts of that window, so an unbounded value is a producer bug.
	MaxProbeAttempts = 1000
	// MaxProbes is two results per link (e2e and transport) plus one per
	// forward. An agent holds only its LinksOut, so this is generous.
	MaxProbes = 2*MaxLinks + MaxForwards
)

// ProbeSettings tells an agent what to measure and how often. It is desired
// state like the rest of Transit; what the agent measured goes back in
// NodeReport.Probes.
//
// THE LINKS PROBED ARE EXACTLY THE AGENT'S LinksOut. A link is probed from its
// entry, because the entry is the side that dials the exit; the exit has
// nothing to dial. There is therefore no list of links here: naming one would
// be a second source of truth that could disagree with LinksOut. Forwards, by
// contrast, are opt-in per forward, because a forward's landing may not want
// to be dialed, and each carries its method.
//
// Probe is omitempty on Transit, so a server that is not probed keeps the
// config it had before probing existed.
type ProbeSettings struct {
	// IntervalSeconds is the time between probe rounds.
	IntervalSeconds int `json:"interval_seconds"`
	// TimeoutMS bounds one attempt.
	TimeoutMS int `json:"timeout_ms"`
	// LinkURL is fetched through each link for its "e2e" result. Empty means the
	// links are probed transport-only: no "e2e" result is produced, because
	// there is nothing the agent may fetch on the operator's behalf.
	LinkURL string `json:"link_url,omitempty"`
	// Forwards lists the forwards to probe; each must be in Transit.Forwards.
	Forwards []ProbeTarget `json:"forwards,omitempty"`
}

// ProbeTarget names one forward to probe and how.
type ProbeTarget struct {
	Key ForwardKey `json:"key"`
	// Method is ProbeMethodTCP, ProbeMethodQUIC or ProbeMethodTLS. It is the
	// handshake that is timed, so "quic" is for a forward whose network carries
	// UDP and "tls" for one that is a front route target.
	Method string `json:"method"`
}

// ProbeResult is one probe's outcome over the agent's last window. It is an
// observation: the agent says what it measured, and never where it measured it
// (the target comes from the desired document, as for every health check).
//
// RTT fields are of the successful attempts and are all zero when none
// succeeded, so a zero is "no sample" and is told from a fast link by
// Attempts == Failures, never by the RTT itself.
type ProbeResult struct {
	// Key is a LinkKey for "e2e" and "transport", a ForwardKey for "forward".
	Key         string `json:"key"`
	Kind        string `json:"kind"`
	Attempts    int    `json:"attempts"`
	Failures    int    `json:"failures"`
	RTTMinMS    int    `json:"rtt_min_ms"`
	RTTMedianMS int    `json:"rtt_median_ms"`
	RTTMaxMS    int    `json:"rtt_max_ms"`
	// LastError is the class of the most recent failure, one of the
	// ProbeError* values.
	LastError string `json:"last_error,omitempty"`
	// LastSuccessMS is the agent wall clock of the last success, zero (omitted)
	// when there has been none since the agent started.
	LastSuccessMS int64 `json:"last_success_ms,omitempty"`
}

// ValidateProbeSettings checks settings in isolation. That every named forward
// exists, and that there is something to probe, depends on the Transit around
// it and is checked by ValidateTransit.
func ValidateProbeSettings(probe ProbeSettings) error {
	if probe.IntervalSeconds < MinProbeIntervalSeconds || probe.IntervalSeconds > MaxProbeIntervalSeconds {
		return fmt.Errorf("probe interval_seconds %d is outside %d..%d", probe.IntervalSeconds, MinProbeIntervalSeconds, MaxProbeIntervalSeconds)
	}
	if probe.TimeoutMS < MinProbeTimeoutMS || probe.TimeoutMS > MaxProbeTimeoutMS {
		return fmt.Errorf("probe timeout_ms %d is outside %d..%d", probe.TimeoutMS, MinProbeTimeoutMS, MaxProbeTimeoutMS)
	}
	if probe.LinkURL != "" {
		if err := validateProbeLinkURL(probe.LinkURL); err != nil {
			return fmt.Errorf("probe link_url: %w", err)
		}
	}
	if len(probe.Forwards) > MaxForwards {
		return fmt.Errorf("probe names %d forwards, maximum is %d", len(probe.Forwards), MaxForwards)
	}
	seen := make(map[ForwardKey]struct{}, len(probe.Forwards))
	for _, target := range probe.Forwards {
		if _, err := target.Key.RowID(); err != nil {
			return fmt.Errorf("probe: %w", err)
		}
		switch target.Method {
		case ProbeMethodTCP, ProbeMethodQUIC, ProbeMethodTLS:
		default:
			return fmt.Errorf("probe forward %s method %q is not %q, %q or %q", target.Key, target.Method, ProbeMethodTCP, ProbeMethodQUIC, ProbeMethodTLS)
		}
		if _, exists := seen[target.Key]; exists {
			return fmt.Errorf("probe names forward %q twice", target.Key)
		}
		seen[target.Key] = struct{}{}
	}
	return nil
}

// validateProbeSettings is ValidateProbeSettings plus what only the enclosing
// Transit can answer. The block is refused when there is nothing to probe so
// the panel never sends a setting that means nothing, which an agent could not
// tell from a misconfiguration.
func validateProbeSettings(transit *Transit) error {
	probe := transit.Probe
	if probe == nil {
		return nil
	}
	if err := ValidateProbeSettings(*probe); err != nil {
		return err
	}
	// A forward that exists but is not named is not probed, so it does not
	// count: the settings would still measure nothing.
	if len(transit.LinksOut) == 0 && len(probe.Forwards) == 0 {
		return fmt.Errorf("probe settings without any outgoing link or named forward to probe")
	}
	forwards := make(map[ForwardKey]Forward, len(transit.Forwards))
	for _, forward := range transit.Forwards {
		forwards[forward.Key] = forward
	}
	// A TLS probe needs a server name to send, and only a route has one.
	frontRouteForwards := make(map[ForwardKey]bool)
	for _, front := range transit.Fronts {
		for _, route := range front.Routes {
			if route.Target.Forward != "" {
				frontRouteForwards[route.Target.Forward] = true
			}
		}
	}
	for _, target := range probe.Forwards {
		forward, ok := forwards[target.Key]
		if !ok {
			return fmt.Errorf("probe names forward %s, which is not in this transit", target.Key)
		}
		// QUIC is UDP: a forward that relays TCP only would be probed on a port
		// nothing listens on, and report a healthy line as down.
		if target.Method == ProbeMethodQUIC && forward.Network != ForwardNetworkTCPUDP {
			return fmt.Errorf("probe forward %s method quic needs a forward whose network includes udp", target.Key)
		}
		if target.Method == ProbeMethodTLS && !frontRouteForwards[target.Key] {
			return fmt.Errorf("probe forward %s method tls needs a forward that is a front route target", target.Key)
		}
		if target.Method == ProbeMethodTCP && frontRouteForwards[target.Key] {
			return fmt.Errorf("probe forward %s is a front route target; probe it with method tls", target.Key)
		}
	}
	return nil
}

// validateProbeLinkURL accepts an absolute http or https URL with a host and no
// credentials. Credentials are refused because the URL is fetched through every
// link on a schedule and would be sent to whatever host it names.
func validateProbeLinkURL(raw string) error {
	if len(raw) > MaxProbeLinkURLBytes {
		return fmt.Errorf("exceeds %d bytes", MaxProbeLinkURLBytes)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] >= 0x7f {
			return fmt.Errorf("contains a space, control or non-ASCII byte")
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("is not a URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("scheme %q is not http or https", parsed.Scheme)
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("has no host")
	}
	if parsed.User != nil {
		return fmt.Errorf("carries credentials")
	}
	return nil
}

// ValidateProbeResults checks the Probes enumeration of a full report.
func ValidateProbeResults(results []ProbeResult) error {
	if len(results) > MaxProbes {
		return fmt.Errorf("probes has %d entries, maximum is %d", len(results), MaxProbes)
	}
	type identity struct{ key, kind string }
	seen := make(map[identity]struct{}, len(results))
	for _, result := range results {
		if err := validateProbeResult(result); err != nil {
			return err
		}
		id := identity{result.Key, result.Kind}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("duplicate probe %q of kind %q", result.Key, result.Kind)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func validateProbeResult(result ProbeResult) error {
	switch result.Kind {
	case ProbeKindE2E, ProbeKindTransport:
		// Row ids are validated through the typed keys so the canonical-form
		// rules stay in one place, and a key of the other family is refused
		// because its prefix does not parse.
		if _, err := LinkKey(result.Key).RowID(); err != nil {
			return fmt.Errorf("probe %s of kind %q: %w", result.Key, result.Kind, err)
		}
	case ProbeKindForward:
		if _, err := ForwardKey(result.Key).RowID(); err != nil {
			return fmt.Errorf("probe %s of kind %q: %w", result.Key, result.Kind, err)
		}
	default:
		return fmt.Errorf("probe %s has unknown kind %q", result.Key, result.Kind)
	}
	if result.Attempts < 0 || result.Attempts > MaxProbeAttempts {
		return fmt.Errorf("probe %s attempts %d is outside 0..%d", result.Key, result.Attempts, MaxProbeAttempts)
	}
	if result.Failures < 0 || result.Failures > result.Attempts {
		return fmt.Errorf("probe %s failures %d is outside 0..attempts (%d)", result.Key, result.Failures, result.Attempts)
	}
	if result.Failures == result.Attempts {
		if result.RTTMinMS != 0 || result.RTTMedianMS != 0 || result.RTTMaxMS != 0 {
			return fmt.Errorf("probe %s has no successful attempt but reports RTTs", result.Key)
		}
	} else if result.RTTMinMS < 0 || result.RTTMinMS > result.RTTMedianMS || result.RTTMedianMS > result.RTTMaxMS {
		return fmt.Errorf("probe %s RTTs are not ordered 0 <= min <= median <= max", result.Key)
	}
	switch result.LastError {
	case "", ProbeErrorTimeout, ProbeErrorRefused, ProbeErrorTLS, ProbeErrorHTTPStatus,
		ProbeErrorDNS, ProbeErrorProbeUnavailable, ProbeErrorOther:
	default:
		return fmt.Errorf("probe %s has unknown last_error %q", result.Key, result.LastError)
	}
	if result.LastSuccessMS < 0 {
		return fmt.Errorf("probe %s has a negative last_success_ms", result.Key)
	}
	return nil
}
