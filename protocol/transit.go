package protocol

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// CapabilityTransitForward says the agent compiles ConfigBody.Transit.Forwards
// on every engine it runs, reports each forward's convergence as a config
// object keyed by its ForwardKey, and enumerates ForwardCounters on full
// reports.
//
// IT GATES SENDING, AND THE GATE IS MANDATORY. An agent ignores a field it does
// not know, so an agent without this capability that is sent forwards would
// accept the config, open no port, and report the config applied: a relay line
// published to users that leads nowhere. PSP must send Transit only to an agent
// that declared it. ValidateTransit cannot see capabilities.
//
// It is not an upgrade capability.
const CapabilityTransitForward = "transit.forward.v1"

const forwardKeyPrefix = "fwd_"

// ForwardKey identifies one forward. Minted from PSP's transit_forwards row id.
//
// A type of its own and not a ListenerKey: a listener key resolves to a nodes
// row, and a forward is not one. Sharing the type would let a forward's
// counters be booked as some unrelated node's traffic.
type ForwardKey string

// NewForwardKey mints a forward key from a PSP transit_forwards row id.
func NewForwardKey(forwardID int64) ForwardKey {
	return ForwardKey(forwardKeyPrefix + strconv.FormatInt(forwardID, 10))
}

// RowID recovers the PSP row id a key was minted from.
func (k ForwardKey) RowID() (int64, error) { return rowID(string(k), forwardKeyPrefix, "forward") }

// Forward network values.
const (
	ForwardNetworkTCP    = "tcp"
	ForwardNetworkTCPUDP = "tcp,udp"
)

// Limits on Transit. A server is an entry for a bounded number of landings; a
// list larger than this is a PSP defect, not a deployment.
const (
	MaxForwards           = 1024
	MaxForwardTargetBytes = 253
)

// Transit is what an agent relays for other servers. It is present only for an
// agent that declared CapabilityTransitForward and only while it has something
// to relay. omitempty on ConfigBody.Transit is load-bearing for the same reason
// as Policy: a server with no transit lines must see a config byte-identical to
// the one before transit existed, or every agent in the fleet re-applies.
//
// Forwards are gated by CapabilityTransitForward; links and egress bindings by
// CapabilityTransitLink (see link.go). Multi-hop chains are a later addition,
// behind a capability of its own. Every field is omitempty, so a server that
// relays nothing keeps the config it had before transit existed.
type Transit struct {
	Forwards []Forward `json:"forwards,omitempty"`
	// LinksIn are the links this agent is the exit of.
	LinksIn []LinkIn `json:"links_in,omitempty"`
	// LinksOut are the links this agent is the entry of.
	LinksOut []LinkOut `json:"links_out,omitempty"`
	// Egress names which of this agent's listeners leave through which of its
	// LinksOut. A listener without a binding leaves from this agent itself.
	Egress []EgressBinding `json:"egress,omitempty"`
}

// Forward relays every connection arriving on Port to Target:TargetPort
// unchanged. The agent neither authenticates nor decrypts: whoever holds the
// landing's credentials uses the forward, and the landing enforces everything.
//
// The landing therefore sees this agent's address as the client's. Nothing
// here carries the original source; preserving it is a separate, later
// capability.
type Forward struct {
	Key ForwardKey `json:"key"`
	// Listen is the local address to bind; empty binds every address.
	Listen string `json:"listen,omitempty"`
	Port   int    `json:"port"`
	// Target is the landing's host: a canonical IP address or a lowercase DNS
	// name. It is resolved by the core when it dials, never by PSP.
	Target     string `json:"target"`
	TargetPort int    `json:"target_port"`
	// Network is ForwardNetworkTCP or ForwardNetworkTCPUDP.
	Network string `json:"network"`
}

// ForwardCounters is one forward's cumulative traffic. Like ListenerCounters it
// is a full-report enumeration: Present distinguishes an idle forward from a
// missing one, and CounterEpoch marks a local counter reset.
//
// This is transit traffic, not anyone's usage. The landing counts the same
// bytes against the user; booking these as well would charge them twice.
type ForwardCounters struct {
	Key          ForwardKey `json:"key"`
	Present      bool       `json:"present"`
	UpBytes      int64      `json:"up_bytes"`
	DownBytes    int64      `json:"down_bytes"`
	CounterEpoch uint64     `json:"counter_epoch"`
}

// ValidateTransit checks a Transit in isolation: canonical keys, no duplicate
// key, port in range, a well-formed target and a known network. Whether a
// forward's bind collides with a listener's is the agent's compile-time
// question, because only the agent sees the complete set of binds.
func ValidateTransit(transit *Transit) error {
	if transit == nil {
		return nil
	}
	if len(transit.Forwards) > MaxForwards {
		return fmt.Errorf("transit has %d forwards, maximum is %d", len(transit.Forwards), MaxForwards)
	}
	seen := make(map[ForwardKey]struct{}, len(transit.Forwards))
	for _, forward := range transit.Forwards {
		if err := ValidateForward(forward); err != nil {
			return err
		}
		if _, exists := seen[forward.Key]; exists {
			return fmt.Errorf("duplicate forward %q", forward.Key)
		}
		seen[forward.Key] = struct{}{}
	}
	return validateLinks(transit)
}

// ValidateForward checks one forward.
func ValidateForward(forward Forward) error {
	if _, err := forward.Key.RowID(); err != nil {
		return err
	}
	if err := validateBindAddress(forward.Listen); err != nil {
		return fmt.Errorf("forward %s listen: %w", forward.Key, err)
	}
	if forward.Port < 1 || forward.Port > 65535 {
		return fmt.Errorf("forward %s port %d is outside 1..65535", forward.Key, forward.Port)
	}
	if err := validateForwardTarget(forward.Target); err != nil {
		return fmt.Errorf("forward %s target: %w", forward.Key, err)
	}
	if forward.TargetPort < 1 || forward.TargetPort > 65535 {
		return fmt.Errorf("forward %s target_port %d is outside 1..65535", forward.Key, forward.TargetPort)
	}
	switch forward.Network {
	case ForwardNetworkTCP, ForwardNetworkTCPUDP:
	default:
		return fmt.Errorf("forward %s network %q is not %q or %q", forward.Key, forward.Network, ForwardNetworkTCP, ForwardNetworkTCPUDP)
	}
	return nil
}

// validateForwardTarget accepts a canonical IP address (no zone, IPv4-mapped
// IPv6 refused) or a lowercase DNS name. Anything a core would read as more
// than a host, such as a port, a path or brackets, is refused.
func validateForwardTarget(target string) error {
	if target == "" {
		return fmt.Errorf("is required")
	}
	if len(target) > MaxForwardTargetBytes {
		return fmt.Errorf("exceeds %d bytes", MaxForwardTargetBytes)
	}
	if addr, err := netip.ParseAddr(target); err == nil {
		if addr.Zone() != "" || addr.String() != target {
			return fmt.Errorf("%q is not a canonical IP address", target)
		}
		if addr.Is4In6() {
			return fmt.Errorf("%q is an IPv4-mapped IPv6 address; unmap it", target)
		}
		return nil
	}
	if strings.HasSuffix(target, ".") {
		return fmt.Errorf("%q has a trailing dot", target)
	}
	labels := strings.Split(target, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%q has an empty or oversized label", target)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%q has a label starting or ending with a hyphen", target)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("%q is not a lowercase DNS name", target)
			}
		}
	}
	// A name whose last label is numeric would be read as an address by some
	// resolvers (1.2.3, 0x7f000001); it is neither a valid address nor a name.
	last := labels[len(labels)-1]
	if _, err := strconv.ParseUint(last, 10, 64); err == nil {
		return fmt.Errorf("%q ends in a numeric label", target)
	}
	if hex, ok := strings.CutPrefix(last, "0x"); ok {
		if _, err := strconv.ParseUint(hex, 16, 64); err == nil || hex == "" {
			return fmt.Errorf("%q ends in a numeric label", target)
		}
	}
	return nil
}
