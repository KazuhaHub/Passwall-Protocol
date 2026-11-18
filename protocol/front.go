package protocol

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// CapabilityTransitSNI says the agent compiles Transit.Fronts: it binds a front's
// port itself, reads the SNI of each raw connection's ClientHello without
// decrypting anything, and hands the connection to the route's target. It
// reports each front's convergence as a config object keyed by its FrontKey.
//
// The capability is declared only where the engine can do it. In practice that
// is Xray (see the README for what a client must not do); an agent whose engine
// cannot front must not declare it.
//
// IT GATES SENDING, AND THE GATE IS MANDATORY. An agent that does not know the
// field ignores it, so the listeners that were moved to loopback ports would
// never be bound where users reach them: every REALITY node on a shared 443
// would go dark while the config reads as applied. PSP must send Transit.Fronts
// only to an agent that declared it. ValidateTransit cannot see capabilities.
//
// It is not an upgrade capability.
const CapabilityTransitSNI = "transit.sni.v1"

const frontKeyPrefix = "fnt_"

// FrontKey identifies one SNI front. Minted from PSP's transit_fronts row id.
//
// A type of its own, like ForwardKey and LinkKey: a front is not a listener, and
// sharing the type would let its convergence be booked as some node's.
type FrontKey string

// NewFrontKey mints a front key from a PSP transit_fronts row id.
func NewFrontKey(frontID int64) FrontKey {
	return FrontKey(frontKeyPrefix + strconv.FormatInt(frontID, 10))
}

// RowID recovers the PSP row id a key was minted from.
func (k FrontKey) RowID() (int64, error) { return rowID(string(k), frontKeyPrefix, "front") }

// Limits on fronts. A front is a hand-written port-sharing plan; a longer list
// is a PSP defect, and the route scan is paid once per connection.
const (
	MaxFronts          = 16
	MaxFrontRoutes     = 256
	MaxFrontRouteNames = 16
)

// Front shares one TCP port among several TLS or REALITY uses on a server by
// routing each raw connection on the SNI of its ClientHello, without decrypting
// it. Whatever the target is then sees the connection as if it had arrived on
// the port itself.
//
// A connection whose SNI is in no route, or which has none, goes to Default.
// The first route naming the SNI decides; names are exact, and a name appears in
// at most one route of a front, so order does not matter.
//
// THE PORT BELONGS TO THE FRONT. A fronted listener keeps its public port in
// its own config, where PSP and the user's links read it; the agent binds it to
// 127.0.0.1:LoopbackPort instead (see FrontedListener). A forward or link that
// is a route target is not bound on its own: the front owns its socket, and the
// forward or link must say the same Listen and Port the front does, so the two
// descriptions cannot disagree about where it lives.
type Front struct {
	Key FrontKey `json:"key"`
	// Listen is the local address to bind; empty binds every address.
	Listen string `json:"listen,omitempty"`
	Port   int    `json:"port"`
	// Listeners are the user listeners this front moves onto loopback ports.
	Listeners []FrontedListener `json:"listeners,omitempty"`
	Routes    []FrontRoute      `json:"routes"`
	// Default takes every connection no route names, SNI absent included.
	Default FrontTarget `json:"default"`
}

// FrontedListener moves one listener behind a front. The listener keeps its
// public port in its own config; the agent binds it to 127.0.0.1:LoopbackPort
// instead, and the front forwards to that address.
type FrontedListener struct {
	Listener     ListenerKey `json:"listener"`
	LoopbackPort int         `json:"loopback_port"`
}

// FrontRoute sends the connections whose SNI is one of ServerNames to Target.
// ServerNames are sorted ascending, lowercase and exact: there is no suffix or
// wildcard match, because a pattern is a second way to write a name and the
// router would have to pick between them.
type FrontRoute struct {
	ServerNames []string    `json:"server_names"`
	Target      FrontTarget `json:"target"`
}

// FrontTarget is where a connection goes. Exactly one field is set.
type FrontTarget struct {
	// Listener is one of the front's own Listeners.
	Listener ListenerKey `json:"listener,omitempty"`
	// Forward is a TCP forward bound where the front is: the connection is
	// relayed to the forward's target untouched.
	Forward ForwardKey `json:"forward,omitempty"`
	// Link is a vless_reality LinkIn bound where the front is.
	Link LinkKey `json:"link,omitempty"`
	// External is a site elsewhere. Only Front.Default may be one.
	External *FrontExternal `json:"external,omitempty"`
}

// FrontExternal is a real website that unknown or absent SNIs are relayed to,
// so a scanner that connects to the port sees an ordinary site. Host is a
// canonical IP address or a lowercase DNS name, resolved by the core.
type FrontExternal struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// unmapBind returns a bind address with an IPv4-mapped IPv6 address written as
// the IPv4 address it is, so that two spellings of one address compare equal.
// An address that does not parse is returned as it is.
func unmapBind(listen string) string {
	if addr, err := netip.ParseAddr(listen); err == nil {
		return addr.Unmap().String()
	}
	return listen
}

// bindsOverlap reports whether two bind addresses on the same port would
// conflict. Empty binds every address, so it overlaps everything. "0.0.0.0"
// overlaps every IPv4 address; "::" is taken as dual-stack, as it is on Linux
// by default, and overlaps every address. Two distinct specific addresses do
// not. An IPv4-mapped IPv6 address is the IPv4 address it maps.
func bindsOverlap(a, b string) bool {
	a, b = unmapBind(a), unmapBind(b)
	if a == b || a == "" || b == "" {
		return true
	}
	x, errX := netip.ParseAddr(a)
	y, errY := netip.ParseAddr(b)
	if errX != nil || errY != nil {
		return true
	}
	for _, pair := range [][2]netip.Addr{{x, y}, {y, x}} {
		if wild := pair[0]; wild.IsUnspecified() {
			return !wild.Is4() || pair[1].Is4() || pair[1].IsUnspecified()
		}
	}
	return false
}

// bindIncludesLoopback reports whether a socket bound to listen holds a port on
// 127.0.0.1's side of the host: every address (empty), the unspecified
// addresses, or any IPv4 loopback address (127.0.0.0/8). It is deliberately
// wider than "the same address": a loopback port of a fronted listener must not
// be one any other bind could reach. "::1" is a different socket and is not
// counted.
func bindIncludesLoopback(listen string) bool {
	listen = unmapBind(listen)
	if listen == "" {
		return true
	}
	addr, err := netip.ParseAddr(listen)
	if err != nil {
		return true
	}
	return addr.IsUnspecified() || (addr.Is4() && addr.IsLoopback())
}

func validateFronts(transit *Transit) error {
	if len(transit.Fronts) == 0 {
		return nil
	}
	if len(transit.Fronts) > MaxFronts {
		return fmt.Errorf("transit has %d fronts, maximum is %d", len(transit.Fronts), MaxFronts)
	}
	forwards := make(map[ForwardKey]Forward, len(transit.Forwards))
	for _, forward := range transit.Forwards {
		forwards[forward.Key] = forward
	}
	linksIn := make(map[LinkKey]LinkIn, len(transit.LinksIn))
	for _, link := range transit.LinksIn {
		linksIn[link.Key] = link
	}
	keys := make(map[FrontKey]struct{}, len(transit.Fronts))
	loopback := make(map[int]FrontKey)
	// fronted maps a listener, forward or link to the front that owns it, so
	// that nothing is behind two fronts.
	fronted := make(map[string]FrontKey)
	for i, front := range transit.Fronts {
		if err := validateFront(front, forwards, linksIn, loopback, fronted); err != nil {
			return err
		}
		if _, exists := keys[front.Key]; exists {
			return fmt.Errorf("duplicate front %q", front.Key)
		}
		keys[front.Key] = struct{}{}
		for _, earlier := range transit.Fronts[:i] {
			if earlier.Port == front.Port && bindsOverlap(earlier.Listen, front.Listen) {
				return fmt.Errorf("fronts %s and %s share a bind", earlier.Key, front.Key)
			}
		}
	}
	// A loopback port is a real socket on 127.0.0.1; it cannot also be a port a
	// front, a forward or a link holds on an address that includes loopback.
	for _, front := range transit.Fronts {
		if owner, taken := loopback[front.Port]; taken && bindIncludesLoopback(front.Listen) {
			return fmt.Errorf("front %s port %d is also a loopback port of front %s", front.Key, front.Port, owner)
		}
	}
	for _, forward := range transit.Forwards {
		if owner, taken := loopback[forward.Port]; taken && bindIncludesLoopback(forward.Listen) {
			return fmt.Errorf("forward %s port %d is also a loopback port of front %s", forward.Key, forward.Port, owner)
		}
	}
	for _, link := range transit.LinksIn {
		if owner, taken := loopback[link.Port]; taken && bindIncludesLoopback(link.Listen) {
			return fmt.Errorf("link %s port %d is also a loopback port of front %s", link.Key, link.Port, owner)
		}
	}
	// A forward or link on a front's port is the front's own socket or a
	// conflict with it: it is allowed only as that front's target.
	for _, forward := range transit.Forwards {
		if _, isTarget := fronted["forward "+string(forward.Key)]; isTarget {
			continue
		}
		for _, front := range transit.Fronts {
			if front.Port == forward.Port && bindsOverlap(front.Listen, forward.Listen) {
				return fmt.Errorf("forward %s is bound where front %s is and is not its target", forward.Key, front.Key)
			}
		}
	}
	for _, link := range transit.LinksIn {
		if _, isTarget := fronted["link "+string(link.Key)]; isTarget {
			continue
		}
		for _, front := range transit.Fronts {
			if front.Port == link.Port && bindsOverlap(front.Listen, link.Listen) {
				return fmt.Errorf("link %s is bound where front %s is and is not its target", link.Key, front.Key)
			}
		}
	}
	// An external default must not be a bind of this host, whatever holds it:
	// a front, a forward or an incoming link. A connection relayed there comes
	// straight back into this agent (a forward on 203.0.113.5:8443 to
	// 203.0.113.5:443 behind a front on 203.0.113.5:443 is a loop of two
	// sockets). A wildcard bind cannot be matched against a named host here, and
	// an unspecified external host is already refused.
	type bind struct {
		what, listen string
		port         int
	}
	var binds []bind
	for _, front := range transit.Fronts {
		binds = append(binds, bind{"front " + string(front.Key), front.Listen, front.Port})
	}
	for _, forward := range transit.Forwards {
		binds = append(binds, bind{"forward " + string(forward.Key), forward.Listen, forward.Port})
	}
	for _, link := range transit.LinksIn {
		binds = append(binds, bind{"link " + string(link.Key), link.Listen, link.Port})
	}
	for _, front := range transit.Fronts {
		external := front.Default.External
		if external == nil {
			continue
		}
		for _, other := range binds {
			if other.listen != "" && external.Port == other.port && unmapBind(external.Host) == unmapBind(other.listen) {
				return fmt.Errorf("front %s default %s:%d is the bind of %s", front.Key, external.Host, external.Port, other.what)
			}
		}
	}
	return nil
}

func validateFront(front Front, forwards map[ForwardKey]Forward, linksIn map[LinkKey]LinkIn,
	loopback map[int]FrontKey, fronted map[string]FrontKey) error {
	if _, err := front.Key.RowID(); err != nil {
		return err
	}
	if err := validateBindAddress(front.Listen); err != nil {
		return fmt.Errorf("front %s listen: %w", front.Key, err)
	}
	if front.Port < 1 || front.Port > 65535 {
		return fmt.Errorf("front %s port %d is outside 1..65535", front.Key, front.Port)
	}
	if len(front.Listeners) > MaxFrontRoutes+1 {
		return fmt.Errorf("front %s has %d listeners, maximum is %d", front.Key, len(front.Listeners), MaxFrontRoutes+1)
	}
	own := make(map[ListenerKey]bool, len(front.Listeners))
	for _, item := range front.Listeners {
		if _, err := item.Listener.RowID(); err != nil {
			return fmt.Errorf("front %s: %w", front.Key, err)
		}
		if own[item.Listener] {
			return fmt.Errorf("front %s fronts listener %s twice", front.Key, item.Listener)
		}
		own[item.Listener] = true
		if item.LoopbackPort < 1 || item.LoopbackPort > 65535 {
			return fmt.Errorf("front %s listener %s loopback_port %d is outside 1..65535", front.Key, item.Listener, item.LoopbackPort)
		}
		if owner, taken := loopback[item.LoopbackPort]; taken {
			return fmt.Errorf("front %s listener %s loopback_port %d is already used by front %s", front.Key, item.Listener, item.LoopbackPort, owner)
		}
		loopback[item.LoopbackPort] = front.Key
	}
	if len(front.Routes) == 0 {
		return fmt.Errorf("front %s has no routes; a front that sends everything to its default shares nothing", front.Key)
	}
	if len(front.Routes) > MaxFrontRoutes {
		return fmt.Errorf("front %s has %d routes, maximum is %d", front.Key, len(front.Routes), MaxFrontRoutes)
	}
	// referenced counts use by this front, so that a target that is both a
	// route's and the default's is one use, and an unused listener is visible.
	referenced := make(map[string]bool)
	claim := func(kind, key string) error {
		if owner, taken := fronted[kind+" "+key]; taken && owner != front.Key {
			return fmt.Errorf("%s %s is behind two fronts (%s and %s)", kind, key, owner, front.Key)
		}
		fronted[kind+" "+key] = front.Key
		referenced[kind+" "+key] = true
		return nil
	}
	names := make(map[string]bool)
	for index, route := range front.Routes {
		if len(route.ServerNames) == 0 || len(route.ServerNames) > MaxFrontRouteNames {
			return fmt.Errorf("front %s route %d needs 1..%d server names", front.Key, index, MaxFrontRouteNames)
		}
		if err := validateSortedUnique("server_names", route.ServerNames); err != nil {
			return fmt.Errorf("front %s route %d: %w", front.Key, index, err)
		}
		for _, name := range route.ServerNames {
			if err := validateServerName(name); err != nil {
				return fmt.Errorf("front %s route %d server name: %w", front.Key, index, err)
			}
			if names[name] {
				return fmt.Errorf("front %s names %q in two routes", front.Key, name)
			}
			names[name] = true
		}
		if err := validateFrontTarget(front, route.Target, false, own, forwards, linksIn, claim); err != nil {
			return fmt.Errorf("front %s route %d: %w", front.Key, index, err)
		}
	}
	if err := validateFrontTarget(front, front.Default, true, own, forwards, linksIn, claim); err != nil {
		return fmt.Errorf("front %s default: %w", front.Key, err)
	}
	if err := validateFrontLinkNames(front, linksIn); err != nil {
		return err
	}
	for _, item := range front.Listeners {
		if !referenced["listener "+string(item.Listener)] {
			return fmt.Errorf("front %s fronts listener %s, which no route or default sends traffic to", front.Key, item.Listener)
		}
	}
	return nil
}

func validateFrontTarget(front Front, target FrontTarget, isDefault bool, own map[ListenerKey]bool,
	forwards map[ForwardKey]Forward, linksIn map[LinkKey]LinkIn, claim func(kind, key string) error) error {
	set := 0
	for _, present := range []bool{target.Listener != "", target.Forward != "", target.Link != "", target.External != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return fmt.Errorf("a target names exactly one of listener, forward, link and external (found %d)", set)
	}
	switch {
	case target.Listener != "":
		if _, err := target.Listener.RowID(); err != nil {
			return err
		}
		if !own[target.Listener] {
			return fmt.Errorf("listener %s is not one of the front's listeners", target.Listener)
		}
		return claim("listener", string(target.Listener))
	case target.Forward != "":
		if _, err := target.Forward.RowID(); err != nil {
			return err
		}
		forward, ok := forwards[target.Forward]
		if !ok {
			return fmt.Errorf("forward %s is not in this transit", target.Forward)
		}
		if forward.Network != ForwardNetworkTCP {
			return fmt.Errorf("forward %s relays %q; a front hands over a TCP connection", forward.Key, forward.Network)
		}
		if forward.Listen != front.Listen || forward.Port != front.Port {
			return fmt.Errorf("forward %s is not bound where the front is", forward.Key)
		}
		return claim("forward", string(target.Forward))
	case target.Link != "":
		if _, err := target.Link.RowID(); err != nil {
			return err
		}
		link, ok := linksIn[target.Link]
		if !ok {
			return fmt.Errorf("link %s is not one of this agent's incoming links", target.Link)
		}
		if link.Protocol != LinkProtocolVLESSReality {
			return fmt.Errorf("link %s is %q; a front serves vless_reality links", link.Key, link.Protocol)
		}
		if link.Listen != front.Listen || link.Port != front.Port {
			return fmt.Errorf("link %s is not bound where the front is", link.Key)
		}
		return claim("link", string(target.Link))
	default:
		if !isDefault {
			return fmt.Errorf("an external target is allowed only as the default")
		}
		return validateFrontExternal(front, *target.External)
	}
}

func validateFrontExternal(front Front, external FrontExternal) error {
	if err := validateForwardTarget(external.Host); err != nil {
		return fmt.Errorf("external host: %w", err)
	}
	if external.Port < 1 || external.Port > 65535 {
		return fmt.Errorf("external port %d is outside 1..65535", external.Port)
	}
	// The default is a real website elsewhere. A host that means this machine
	// is never that, on any port: it is the server's own sockets, among them
	// the front and the loopback ports of the fronted listeners.
	if external.Host == "localhost" || strings.HasSuffix(external.Host, ".localhost") {
		return fmt.Errorf("external host %s is this machine", external.Host)
	}
	// 0.0.0.0/8 is "this host" to most stacks, not only the exact 0.0.0.0.
	if addr, err := netip.ParseAddr(external.Host); err == nil &&
		(addr.IsLoopback() || addr.IsUnspecified() || (addr.Is4() && addr.As4()[0] == 0)) {
		return fmt.Errorf("external host %s is this machine", external.Host)
	}
	// The host's own public address under an empty listen cannot be seen from
	// here; the agent and the panel check it.
	if front.Listen != "" && external.Port == front.Port && unmapBind(external.Host) == unmapBind(front.Listen) {
		return fmt.Errorf("external %s:%d is the front itself", external.Host, external.Port)
	}
	return nil
}

// validateFrontLinkNames holds a link target to the REALITY server names the
// link actually accepts. A route that names a host the link does not serve would
// hand the connection to a REALITY inbound that rejects it, and a link name the
// front routes elsewhere is a name its own clients can never reach it by.
//
// Every route to the link names only its server names, no route sends one of
// them elsewhere, and unless the link is also the default (which catches
// whatever no route names) every one of them is routed to it.
func validateFrontLinkNames(front Front, linksIn map[LinkKey]LinkIn) error {
	routed := make(map[LinkKey]map[string]bool)
	for index, route := range front.Routes {
		key := route.Target.Link
		if key == "" {
			continue
		}
		link := linksIn[key]
		accepted := make(map[string]bool, len(link.Reality.ServerNames))
		for _, name := range link.Reality.ServerNames {
			accepted[name] = true
		}
		if routed[key] == nil {
			routed[key] = make(map[string]bool)
		}
		for _, name := range route.ServerNames {
			if !accepted[name] {
				return fmt.Errorf("front %s route %d sends %q to link %s, which does not accept that server name", front.Key, index, name, key)
			}
			routed[key][name] = true
		}
	}
	// A name of a link that the front routes to something else is a name its
	// own clients reach another target by.
	targets := make(map[LinkKey]bool, len(routed)+1)
	for key := range routed {
		targets[key] = true
	}
	if front.Default.Link != "" {
		targets[front.Default.Link] = true
	}
	for index, route := range front.Routes {
		for key := range targets {
			if route.Target.Link == key {
				continue
			}
			for _, name := range linksIn[key].Reality.ServerNames {
				for _, routedName := range route.ServerNames {
					if routedName == name {
						return fmt.Errorf("front %s route %d sends %q elsewhere, but it is a server name of link %s", front.Key, index, name, key)
					}
				}
			}
		}
	}
	for key, names := range routed {
		if front.Default.Link == key {
			continue
		}
		for _, name := range linksIn[key].Reality.ServerNames {
			if !names[name] {
				return fmt.Errorf("front %s does not route %q to link %s, whose server name it is", front.Key, name, key)
			}
		}
	}
	return nil
}
