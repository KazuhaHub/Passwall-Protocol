package protocol

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// CapabilitySourceGuard says the agent compiles Transit.SourceSets and
// Client.SourceGuard into core routing rules that refuse a connection whose
// source address does not belong to the client's line, reports the refusals it
// can observe as NodeReport.SourceGuardHits, and reports its own public
// interface addresses as NodeReport.InterfaceAddresses.
//
// The capability is declared only where the active engine can enforce the guard.
//
// IT GATES SENDING, AND THE GATE IS MANDATORY. An agent that does not know the
// fields ignores them and accepts every connection, so a client that was meant
// to be usable only through one relay line would be usable from anywhere while
// the config reads as applied. That is exactly the bypass the guard exists to
// close. PSP must send SourceSets and Client.SourceGuard only to an agent that
// declared it. ValidateTransit cannot see capabilities.
//
// It is not an upgrade capability.
const CapabilitySourceGuard = "transit.source_guard.v1"

const sourceSetKeyPrefix = "src_"

// SourceSetKey names one set of source addresses. Form "src_<suffix>" with the
// suffix matching [a-z0-9][a-z0-9_-]{0,47}.
//
// Unlike the other keys it is not a row id: a set can be a line's own addresses
// or a shared list such as a CDN's, and PSP mints the suffix from whichever it
// is. A type of its own, so a set cannot be passed where a listener is meant.
type SourceSetKey string

var sourceSetSuffix = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)

// NewSourceSetKey mints a key from a suffix and validates it.
func NewSourceSetKey(suffix string) (SourceSetKey, error) {
	key := SourceSetKey(sourceSetKeyPrefix + suffix)
	if err := key.Validate(); err != nil {
		return "", err
	}
	return key, nil
}

// Suffix returns the part after the prefix, or "" for a malformed key.
func (k SourceSetKey) Suffix() string {
	suffix, _ := strings.CutPrefix(string(k), sourceSetKeyPrefix)
	return suffix
}

// Validate checks the key's form.
func (k SourceSetKey) Validate() error {
	suffix, ok := strings.CutPrefix(string(k), sourceSetKeyPrefix)
	if !ok || !sourceSetSuffix.MatchString(suffix) {
		return fmt.Errorf("source set key %q: want %q followed by [a-z0-9][a-z0-9_-]{0,47}", string(k), sourceSetKeyPrefix)
	}
	return nil
}

// Limits on source guards.
const (
	MaxSourceSets          = 4096
	MaxSourceSetCIDRs      = 1024
	MaxSourceGuardDenyFrom = 64
	// MaxSourceGuardHits bounds NodeReport.SourceGuardHits.
	MaxSourceGuardHits = 256
	// MaxInterfaceAddresses bounds NodeReport.InterfaceAddresses.
	MaxInterfaceAddresses = 64
)

// SourceSet is a named list of source networks. It lives in Transit, the body
// that already carries the line descriptions, and is referenced by key from the
// roster. Every CIDR is a canonical prefix (equal to its masked form), IPv4 or
// IPv6, unique within the set; the order is the producer's and is not
// significant.
type SourceSet struct {
	Key   SourceSetKey `json:"key"`
	CIDRs []string     `json:"cidrs"`
}

// ClientSourceGuard restricts where a client's connections may come from.
// At most one of AllowFrom and DenyFrom is set, and a guard with neither is
// invalid (omit the guard instead).
//
// The source is the address the core sees: for a connection that arrives
// through a front it is the address carried by the PROXY protocol header, and
// otherwise the peer address of the socket.
//
// AllowFrom: the client's connections, on any of its listeners, are accepted
// only when the source is inside the set. If the set is not in the config the
// client is refused entirely (fail closed): a relay identity whose line is not
// known must not become a direct one.
//
// DenyFrom: the client's connections are refused when the source is inside any
// listed set. A listed set that is not in the config is ignored: the sets it
// excludes are then simply unknown, and refusing would lock out a direct client
// over a line that does not exist here.
//
// The roster cannot see the config, so ValidateClientSourceGuard does not check
// that the referenced sets exist. omitempty on Client.SourceGuard is
// load-bearing: a roster without guards must stay byte-identical to the one
// before the guard existed.
type ClientSourceGuard struct {
	AllowFrom SourceSetKey   `json:"allow_from,omitempty"`
	DenyFrom  []SourceSetKey `json:"deny_from,omitempty"`
}

// SourceGuardHit is one aggregate of connections the guard refused: how many
// came from SourceIP and were matched by Set on Listener, and when the last one
// was seen. For an allow guard, Set is the set the source was outside of; for a
// deny guard, a set that contains the source.
type SourceGuardHit struct {
	Set        SourceSetKey `json:"set"`
	Listener   ListenerKey  `json:"listener"`
	SourceIP   string       `json:"source_ip"`
	Count      int64        `json:"count"`
	LastSeenMS int64        `json:"last_seen_ms"`
}

func validateSourceSets(transit *Transit) error {
	sets := transit.SourceSets
	if len(sets) == 0 {
		return nil
	}
	if len(sets) > MaxSourceSets {
		return fmt.Errorf("transit has %d source sets, maximum is %d", len(sets), MaxSourceSets)
	}
	seen := make(map[SourceSetKey]struct{}, len(sets))
	for _, set := range sets {
		if err := ValidateSourceSet(set); err != nil {
			return err
		}
		if _, exists := seen[set.Key]; exists {
			return fmt.Errorf("duplicate source set %q", set.Key)
		}
		seen[set.Key] = struct{}{}
	}
	return nil
}

// ValidateSourceSet checks one set in isolation.
func ValidateSourceSet(set SourceSet) error {
	if err := set.Key.Validate(); err != nil {
		return err
	}
	if len(set.CIDRs) < 1 || len(set.CIDRs) > MaxSourceSetCIDRs {
		return fmt.Errorf("source set %s has %d cidrs, want 1..%d", set.Key, len(set.CIDRs), MaxSourceSetCIDRs)
	}
	seen := make(map[netip.Prefix]struct{}, len(set.CIDRs))
	for _, raw := range set.CIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("source set %s: %q: %w", set.Key, raw, err)
		}
		if prefix.Addr().Zone() != "" {
			return fmt.Errorf("source set %s: %q has a zone", set.Key, raw)
		}
		// The core matches an IPv4-mapped source as IPv4, so such a prefix would
		// never hit; one network, one spelling.
		if prefix.Addr().Is4In6() {
			return fmt.Errorf("source set %s: %q is an IPv4-mapped IPv6 prefix; write the IPv4 prefix", set.Key, raw)
		}
		if prefix.Masked() != prefix || prefix.String() != raw {
			return fmt.Errorf("source set %s: %q is not canonical (want %q)", set.Key, raw, prefix.Masked().String())
		}
		if _, exists := seen[prefix]; exists {
			return fmt.Errorf("source set %s repeats cidr %q", set.Key, raw)
		}
		seen[prefix] = struct{}{}
	}
	return nil
}

// ValidateClientSourceGuard checks a guard in isolation. A nil guard is valid.
// It cannot check that the referenced sets exist; see ClientSourceGuard.
func ValidateClientSourceGuard(guard *ClientSourceGuard) error {
	if guard == nil {
		return nil
	}
	if guard.AllowFrom != "" && len(guard.DenyFrom) > 0 {
		return fmt.Errorf("source guard sets both allow_from and deny_from")
	}
	if guard.AllowFrom == "" && len(guard.DenyFrom) == 0 {
		return fmt.Errorf("source guard sets neither allow_from nor deny_from")
	}
	if guard.AllowFrom != "" {
		if err := guard.AllowFrom.Validate(); err != nil {
			return fmt.Errorf("source guard allow_from: %w", err)
		}
		return nil
	}
	if len(guard.DenyFrom) > MaxSourceGuardDenyFrom {
		return fmt.Errorf("source guard deny_from has %d entries, maximum is %d", len(guard.DenyFrom), MaxSourceGuardDenyFrom)
	}
	seen := make(map[SourceSetKey]struct{}, len(guard.DenyFrom))
	for _, key := range guard.DenyFrom {
		if err := key.Validate(); err != nil {
			return fmt.Errorf("source guard deny_from: %w", err)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("source guard deny_from repeats %q", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// ValidateSourceGuardHits checks NodeReport.SourceGuardHits.
func ValidateSourceGuardHits(hits []SourceGuardHit) error {
	if len(hits) > MaxSourceGuardHits {
		return fmt.Errorf("source_guard_hits has %d entries, maximum is %d", len(hits), MaxSourceGuardHits)
	}
	type identity struct {
		set      SourceSetKey
		listener ListenerKey
		ip       string
	}
	seen := make(map[identity]struct{}, len(hits))
	for _, hit := range hits {
		if err := hit.Set.Validate(); err != nil {
			return fmt.Errorf("source_guard_hits: %w", err)
		}
		if _, err := hit.Listener.RowID(); err != nil {
			return fmt.Errorf("source_guard_hits: %w", err)
		}
		addr, err := netip.ParseAddr(hit.SourceIP)
		if err != nil || addr.String() != hit.SourceIP {
			return fmt.Errorf("source_guard_hits: %q is not a canonical IP address", hit.SourceIP)
		}
		if hit.Count <= 0 || hit.LastSeenMS <= 0 {
			return fmt.Errorf("source_guard_hits: %s from %s needs a positive count and last_seen_ms", hit.Set, hit.SourceIP)
		}
		id := identity{hit.Set, hit.Listener, hit.SourceIP}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("source_guard_hits repeats %s on %s from %s", hit.Set, hit.Listener, hit.SourceIP)
		}
		seen[id] = struct{}{}
	}
	return nil
}

var (
	cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")
	// Documentation ranges (RFC 5737, RFC 3849) are never a real source.
	documentationPrefixes = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
)

// IsPublicSourceAddr reports whether addr can be the source of a connection on
// the public internet: a global unicast address that is not private (RFC 1918,
// IPv6 ULA), shared address space (CGNAT 100.64.0.0/10) or a documentation
// range. Loopback, link-local, multicast and unspecified addresses are not
// global unicast. It is the filter InterfaceAddresses is defined by: a private
// address on an entry server is never what a landing sees, so listing it would
// only widen a source set for no reason.
func IsPublicSourceAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" || addr.Is4In6() {
		return false
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || cgnatPrefix.Contains(addr) {
		return false
	}
	for _, prefix := range documentationPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// ValidateInterfaceAddresses checks NodeReport.InterfaceAddresses: canonical
// public source addresses (see IsPublicSourceAddr), sorted ascending by address
// and unique, at most MaxInterfaceAddresses.
func ValidateInterfaceAddresses(addresses []string) error {
	if len(addresses) > MaxInterfaceAddresses {
		return fmt.Errorf("interface_addresses has %d entries, maximum is %d", len(addresses), MaxInterfaceAddresses)
	}
	var previous netip.Addr
	for index, raw := range addresses {
		addr, err := netip.ParseAddr(raw)
		if err != nil || addr.String() != raw {
			return fmt.Errorf("interface_addresses: %q is not a canonical IP address", raw)
		}
		if !IsPublicSourceAddr(addr) {
			return fmt.Errorf("interface_addresses: %q is not a public global unicast address", raw)
		}
		if index > 0 && previous.Compare(addr) >= 0 {
			return fmt.Errorf("interface_addresses must be sorted ascending without duplicates (%q before %q)", previous, raw)
		}
		previous = addr
	}
	return nil
}
