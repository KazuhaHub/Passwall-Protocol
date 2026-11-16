package protocol

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// CapabilityTransitLink says the agent compiles Transit.LinksIn, LinksOut and
// Egress on every engine it runs, reports each link's convergence as a config
// object keyed by its LinkKey, and enumerates LinkCounters on full reports.
//
// A LINK is the tunnel of a managed relay line that terminates the user
// protocol at the entry: the entry authenticates the user with its own
// listener, then sends the user's traffic through the link to the exit server,
// which connects to the destination. One link is one ordered pair of servers;
// the exit holds its LinkIn, the entry its LinkOut, and the entry's Egress
// says which of its listeners leave through which link.
//
// IT GATES SENDING, AND THE GATE IS MANDATORY: an agent that does not know the
// fields would serve the bound listeners from its own address, quietly
// replacing the exit the user chose. It is not an upgrade capability.
const CapabilityTransitLink = "transit.link.v1"

const linkKeyPrefix = "lnk_"

// LinkKey identifies one link, minted from PSP's transit_links row id. The same
// key names the link on both servers, so its counters on either side can be
// matched. A type of its own, like ForwardKey: it never parses as a listener.
type LinkKey string

// NewLinkKey mints a link key from a PSP transit_links row id.
func NewLinkKey(linkID int64) LinkKey {
	return LinkKey(linkKeyPrefix + strconv.FormatInt(linkID, 10))
}

// RowID recovers the PSP row id a key was minted from.
func (k LinkKey) RowID() (int64, error) { return rowID(string(k), linkKeyPrefix, "link") }

// Link protocols. A link crossing a censored border needs REALITY; a link
// between two servers outside one can use the lighter Shadowsocks-2022.
const (
	LinkProtocolSS2022       = "ss2022"
	LinkProtocolVLESSReality = "vless_reality"
)

// Limits on links. A server is an entry or an exit for a bounded number of
// other servers.
const (
	MaxLinks              = 256
	MaxRealityServerNames = 16
	MaxRealityShortIDs    = 16
)

// LinkIn is the exit's half: a listener that accepts only this link's
// credential and sends what arrives straight out. It is never subject to the
// exit's destination policy as a user listener is: the entry already enforced
// the policy that applies to this traffic (PSP compiles the exit's rules into
// the entry for the listeners that leave through it).
type LinkIn struct {
	Key LinkKey `json:"key"`
	// Listen is the local address to bind; empty binds every address.
	Listen   string `json:"listen,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	// Exactly one of the following is present, matching Protocol.
	SS      *LinkSS            `json:"ss,omitempty"`
	Reality *LinkRealityServer `json:"reality,omitempty"`
}

// LinkOut is the entry's half: an outbound that dials the exit.
type LinkOut struct {
	Key LinkKey `json:"key"`
	// Address is the exit's host as the entry dials it: a canonical IP
	// address or a lowercase DNS name, resolved by the core.
	Address  string             `json:"address"`
	Port     int                `json:"port"`
	Protocol string             `json:"protocol"`
	SS       *LinkSS            `json:"ss,omitempty"`
	Reality  *LinkRealityClient `json:"reality,omitempty"`
}

// LinkSS is a single-user Shadowsocks-2022 credential. Password is the
// standard base64 encoding of exactly the method's key length.
type LinkSS struct {
	Method   string `json:"method"`
	Password string `json:"password"`
}

// LinkRealityServer is what the exit needs to accept a VLESS+REALITY link. The
// private key goes to the exit only; LinkRealityClient carries the public key.
// Keeping the halves in separate types means a LinkOut cannot carry the
// private key, so the entry never holds it.
type LinkRealityServer struct {
	UUID       string `json:"uuid"`
	PrivateKey string `json:"private_key"`
	// Target is the camouflage site, host:port, that REALITY forwards a
	// probe to.
	Target      string   `json:"target"`
	ServerNames []string `json:"server_names"`
	ShortIDs    []string `json:"short_ids"`
}

// LinkRealityClient is what the entry needs to dial a VLESS+REALITY link.
type LinkRealityClient struct {
	UUID        string `json:"uuid"`
	PublicKey   string `json:"public_key"`
	ServerName  string `json:"server_name"`
	ShortID     string `json:"short_id"`
	Fingerprint string `json:"fingerprint"`
}

// EgressBinding sends one of the entry's listeners out through a link instead
// of from the entry's own address.
//
// A LISTENER IS THE ONLY SOURCE TODAY. Chaining links (a LinkIn's traffic
// leaving through another LinkOut) would be multi-hop; it is a later addition
// behind a capability of its own, and a binding here never names a LinkIn.
type EgressBinding struct {
	Listener ListenerKey `json:"listener"`
	Link     LinkKey     `json:"link"`
}

// LinkCounters is one link's cumulative traffic on this agent. Like the other
// counters it is a full-report enumeration. It is transit traffic: the user
// whose bytes these are is charged on the entry's listener, once.
type LinkCounters struct {
	Key          LinkKey `json:"key"`
	Present      bool    `json:"present"`
	UpBytes      int64   `json:"up_bytes"`
	DownBytes    int64   `json:"down_bytes"`
	CounterEpoch uint64  `json:"counter_epoch"`
}

// Accepted Shadowsocks-2022 methods and their key lengths.
var linkSSKeyBytes = map[string]int{
	"2022-blake3-aes-128-gcm": 16,
	"2022-blake3-aes-256-gcm": 32,
}

// Fingerprints both engines accept for a REALITY client.
var linkFingerprints = map[string]bool{
	"chrome": true, "firefox": true, "safari": true, "ios": true, "edge": true,
}

var canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validateLinks(transit *Transit) error {
	if len(transit.LinksIn) > MaxLinks || len(transit.LinksOut) > MaxLinks {
		return fmt.Errorf("transit has more than %d links on one side", MaxLinks)
	}
	seen := make(map[LinkKey]string, len(transit.LinksIn)+len(transit.LinksOut))
	for _, link := range transit.LinksIn {
		if err := ValidateLinkIn(link); err != nil {
			return err
		}
		if side, exists := seen[link.Key]; exists {
			return fmt.Errorf("link %s appears twice (%s and in)", link.Key, side)
		}
		seen[link.Key] = "in"
	}
	out := make(map[LinkKey]bool, len(transit.LinksOut))
	for _, link := range transit.LinksOut {
		if err := ValidateLinkOut(link); err != nil {
			return err
		}
		// One server cannot be both ends of one link: that is a loop.
		if side, exists := seen[link.Key]; exists {
			return fmt.Errorf("link %s appears twice (%s and out)", link.Key, side)
		}
		seen[link.Key] = "out"
		out[link.Key] = true
	}
	bound := make(map[ListenerKey]bool, len(transit.Egress))
	for _, binding := range transit.Egress {
		if _, err := binding.Listener.RowID(); err != nil {
			return fmt.Errorf("egress: %w", err)
		}
		if _, err := binding.Link.RowID(); err != nil {
			return fmt.Errorf("egress of %s: %w", binding.Listener, err)
		}
		if bound[binding.Listener] {
			return fmt.Errorf("listener %s has two egress bindings", binding.Listener)
		}
		bound[binding.Listener] = true
		if !out[binding.Link] {
			return fmt.Errorf("listener %s leaves through %s, which is not one of this agent's outgoing links", binding.Listener, binding.Link)
		}
	}
	return nil
}

// ValidateLinkIn checks the exit's half of one link.
func ValidateLinkIn(link LinkIn) error {
	if _, err := link.Key.RowID(); err != nil {
		return err
	}
	if err := validateBindAddress(link.Listen); err != nil {
		return fmt.Errorf("link %s listen: %w", link.Key, err)
	}
	if link.Port < 1 || link.Port > 65535 {
		return fmt.Errorf("link %s port %d is outside 1..65535", link.Key, link.Port)
	}
	switch link.Protocol {
	case LinkProtocolSS2022:
		if link.SS == nil || link.Reality != nil {
			return fmt.Errorf("link %s: an ss2022 link carries exactly its ss credential", link.Key)
		}
		return validateLinkSS(link.Key, *link.SS)
	case LinkProtocolVLESSReality:
		if link.Reality == nil || link.SS != nil {
			return fmt.Errorf("link %s: a vless_reality link carries exactly its reality credential", link.Key)
		}
		reality := link.Reality
		if !canonicalUUID.MatchString(reality.UUID) {
			return fmt.Errorf("link %s: uuid is not a canonical lowercase UUID", link.Key)
		}
		if err := validateX25519Key(reality.PrivateKey); err != nil {
			return fmt.Errorf("link %s private_key: %w", link.Key, err)
		}
		host, port, err := net.SplitHostPort(reality.Target)
		if err != nil {
			return fmt.Errorf("link %s target %q is not host:port", link.Key, reality.Target)
		}
		if err := validateForwardTarget(host); err != nil {
			return fmt.Errorf("link %s target host: %w", link.Key, err)
		}
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
			return fmt.Errorf("link %s target port %q is invalid", link.Key, port)
		}
		if len(reality.ServerNames) == 0 || len(reality.ServerNames) > MaxRealityServerNames {
			return fmt.Errorf("link %s needs 1..%d server names", link.Key, MaxRealityServerNames)
		}
		for _, name := range reality.ServerNames {
			if err := validateServerName(name); err != nil {
				return fmt.Errorf("link %s server name: %w", link.Key, err)
			}
		}
		if len(reality.ShortIDs) == 0 || len(reality.ShortIDs) > MaxRealityShortIDs {
			return fmt.Errorf("link %s needs 1..%d short ids", link.Key, MaxRealityShortIDs)
		}
		for _, id := range reality.ShortIDs {
			if err := validateShortID(id); err != nil {
				return fmt.Errorf("link %s short id: %w", link.Key, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("link %s protocol %q is not %q or %q", link.Key, link.Protocol, LinkProtocolSS2022, LinkProtocolVLESSReality)
	}
}

// ValidateLinkOut checks the entry's half of one link.
func ValidateLinkOut(link LinkOut) error {
	if _, err := link.Key.RowID(); err != nil {
		return err
	}
	if err := validateForwardTarget(link.Address); err != nil {
		return fmt.Errorf("link %s address: %w", link.Key, err)
	}
	if link.Port < 1 || link.Port > 65535 {
		return fmt.Errorf("link %s port %d is outside 1..65535", link.Key, link.Port)
	}
	switch link.Protocol {
	case LinkProtocolSS2022:
		if link.SS == nil || link.Reality != nil {
			return fmt.Errorf("link %s: an ss2022 link carries exactly its ss credential", link.Key)
		}
		return validateLinkSS(link.Key, *link.SS)
	case LinkProtocolVLESSReality:
		if link.Reality == nil || link.SS != nil {
			return fmt.Errorf("link %s: a vless_reality link carries exactly its reality credential", link.Key)
		}
		reality := link.Reality
		if !canonicalUUID.MatchString(reality.UUID) {
			return fmt.Errorf("link %s: uuid is not a canonical lowercase UUID", link.Key)
		}
		if err := validateX25519Key(reality.PublicKey); err != nil {
			return fmt.Errorf("link %s public_key: %w", link.Key, err)
		}
		if err := validateServerName(reality.ServerName); err != nil {
			return fmt.Errorf("link %s server name: %w", link.Key, err)
		}
		if err := validateShortID(reality.ShortID); err != nil {
			return fmt.Errorf("link %s short id: %w", link.Key, err)
		}
		if !linkFingerprints[reality.Fingerprint] {
			return fmt.Errorf("link %s fingerprint %q is not supported", link.Key, reality.Fingerprint)
		}
		return nil
	default:
		return fmt.Errorf("link %s protocol %q is not %q or %q", link.Key, link.Protocol, LinkProtocolSS2022, LinkProtocolVLESSReality)
	}
}

func validateLinkSS(key LinkKey, ss LinkSS) error {
	want, ok := linkSSKeyBytes[ss.Method]
	if !ok {
		return fmt.Errorf("link %s method %q is not a Shadowsocks-2022 AES method", key, ss.Method)
	}
	raw, err := base64.StdEncoding.DecodeString(ss.Password)
	if err != nil || len(raw) != want || base64.StdEncoding.EncodeToString(raw) != ss.Password {
		return fmt.Errorf("link %s password is not the standard base64 of %d bytes", key, want)
	}
	return nil
}

// validateX25519Key accepts the unpadded base64url form both engines print.
func validateX25519Key(key string) error {
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != key {
		return fmt.Errorf("not an unpadded base64url X25519 key")
	}
	return nil
}

func validateServerName(name string) error {
	if _, err := netip.ParseAddr(name); err == nil {
		return fmt.Errorf("%q is an address, not a server name", name)
	}
	if strings.Count(name, ".") == 0 {
		return fmt.Errorf("%q is not a fully qualified name", name)
	}
	return validateForwardTarget(name)
}

// validateShortID accepts an even-length lowercase hex string of at most 16
// characters, including the empty one REALITY allows.
func validateShortID(id string) error {
	if len(id) > 16 || len(id)%2 != 0 || strings.ToLower(id) != id {
		return fmt.Errorf("%q is not 0..16 lowercase hex characters of even length", id)
	}
	if _, err := hex.DecodeString(id); err != nil {
		return fmt.Errorf("%q is not hex", id)
	}
	return nil
}

func validateBindAddress(listen string) error {
	if listen == "" {
		return nil
	}
	addr, err := netip.ParseAddr(listen)
	if err != nil || addr.String() != listen || addr.Zone() != "" {
		return fmt.Errorf("%q is not a canonical IP address", listen)
	}
	return nil
}
