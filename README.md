# Passwall-Protocol

The shared communication contract between **Passwall-Sub-Panel** (PSP) and
**Passwall-Node** (PN): the wire types, the pure validation of what travels
between them, and the conformance vectors that pin both.

Both products depend on this module instead of one depending on the other, so a
change to a shared type no longer forces a product release:

```text
PSP ──→ Passwall-Protocol ←── PN
```

## What is here, and what is deliberately not

| In | Out |
| --- | --- |
| Report, envelope, segment and version types | Any HTTP client, scheduler, database or task executor |
| Capability names, task kinds, argument/result contracts | Which capabilities a given product implements |
| JSON validation, length bounds, normalization, input digests | GitHub release lookup, compatibility policy, core catalogs |
| Diagnostics and host-observation structures and their validation | Install templates and host update helpers (PN owns these) |
| Conformance vectors | Product version numbering and release identity |

The package is **pure data and pure functions over the standard library**. It
imports nothing else, and it must stay that way: a shared library that depends on
a product, a database or an HTTP framework reintroduces exactly the coupling it
exists to remove.

Which protocol generations and capabilities each product *supports* is a product
decision, not a property of this module. Updating this dependency can make a new
type visible; it must never, by itself, enable a capability.

## Versions

Three version identities are independent, and conflating them causes real
mistakes:

1. **Product versions** — PSP and PN release independently. Their product tags are
   not this module's tags.
2. **This module** — an ordinary Go module version (`v0.1.0`, later `v1.0.0`).
   The `v` is Go tooling convention; it is not a product release number.
3. **Wire generation** — the `v1` in `/v1/node/sync`. It has its own
   compatibility promise and moves on its own schedule.

A module version bump is not a wire change, and identical module versions in two
products are not evidence that the pair was ever tested together.

## Provenance

Extracted verbatim from `Passwall-Node`'s `protocol/` package at tag
`v0.0.1-beta11` (commit `0119a4ec`), which is the revision PSP pins and the two
sides have evidence for. The only change is the Go import path; the source diff
is three import lines, and the task-input domain separator
(`passwall-node/task-input/v1`) was deliberately left byte-identical because it
is hash input — changing it would change every task digest.

`harness/` is a **nested module, not part of this module.** It compiles both this
package and the original `passwall-node/protocol` side by side and asserts their
observable behaviour still matches, which is only possible while the original
exists. It is not a dependency of anything, and `go test ./...` from the root
does not reach it. CI runs it in a workflow of its own, `harness (equivalence
with beta11)`, on each PR that changes the package's sources, `go.mod` or
`harness/`. It is not a required check: a change meant to diverge from beta11
fails it by design, and that PR records the divergence in the harness or
retires it.

## Destination policy

`ConfigBody.Policy` carries a destination policy (block, allow and observe
rules over domains, destination and source CIDRs, ports, network and sniffed
protocols), and `NodeReport.PolicyStatus` is the node's answer. Both are gated
by the capability `policy.destination.v1`: PSP sends a policy only to an agent
that advertised it, so an agent that did not sees a config byte-identical to
v0.2.x. It is **not** an upgrade capability and is not in
`AgentUpgradeCapabilities`; lacking it never holds an agent back from upgrading.

Group rules (`g*`, the allowlist groups) are additionally gated by
`policy.destination.groups.v1`: an agent declaring it enforces them in the
specified order on every engine, in particular a protocol block (BitTorrent)
before a group member allow. PSP sends group rules, and makes an agent eligible
for an allowlist group's members, only when the agent declared it. It is not an
upgrade capability either.

`DestinationPolicy.Resolve` (v0.5.0) says how hostnames meet the IP rules
(`cidrs`, `private`): `""` (omitted, **AsIs**, the default) or `"on_demand"`.
Under `on_demand` the core resolves the hostname once per connection, the first
time a rule asks for its addresses, and the IP rules are tried on the resolved
addresses in rule order, so the answer is the reference matcher with those
addresses as input. Anything else is invalid, and `"if_non_match"` is refused on
purpose: running every rule without addresses first reorders rules, so a
report-only rule could change a verdict and a CIDR block could be skipped in
front of a group member's allow. AsIs is encoded as the absence of the field, so
existing policy digests do not change. A non-AsIs value may be sent only to an
agent that declared **`policy.destination.resolve.v1`**, meaning it compiles `Resolve` on
every engine it runs; an older agent ignores the unknown field and would
silently run AsIs. It is not an upgrade capability either. A policy that needs
`on_demand` also needs `SniffForResolvedIPs` from `CheckXraySniffing`: nothing is
injected, sniffing that is off or `metadataOnly` is fine, and an inbound with
`routeOnly: true` whose `destOverride` can accept a sniffed name (anything but
an empty list, `fakedns` or `fakedns+others`) is insufficient (`route_only_resolve`). Xray's
`domainStrategy` is router-wide, so one such inbound keeps the whole node AsIs.

What is shared beyond the types: `ValidateDestinationPolicy`,
`ValidatePolicyStatus`, `PolicyDigest`, `CheckXraySniffing` (can this inbound's
sniffing supply what the policy needs), `MatchDestination` (a pure trace of
which rule a connection would hit; under `on_demand` it takes the hostname's
addresses as `MatchInput.Resolved` and never resolves anything itself) and `PrivateDestinationCIDRs()` (the table
behind `private`, taken from xray-core). `XraySniffingInjection()`
is the sniffing object a node writes into an inbound whose sniffing is off.
Note that it sets `routeOnly` false, so Xray then connects to the sniffed host
rather than the address the client asked for. `conformance.SniffingVectors` and
`conformance.DestinationMatchVectors` pin the last two for every implementation.

### Limits of destination rules

- **Trailing dot.** xray-core hands matchers the host as written, so
  `example.com.` passes `domain:`, `full:` and an anchored `regexp:`. When a
  policy has a block rule over domains, the node adds a built-in rule
  (`psp-trailing-dot`) that blocks every hostname ending in a dot. It sits after
  the exempt list and the global allows and before the block rules, so it blocks
  the dotted form for every subject that is not exempt or allowed by a global
  allow that matches it as written, **and it defeats group allow exceptions for
  the dotted form**. It fails closed, and that is by design: the alternative is
  a hole in every matcher kind. `MatchDestination` shows it as a step with
  `Builtin: "trailing_dot"`.
- **Name resolution (AsIs).** By default hostnames are never matched against
  `cidrs` or `private`; `MatchDestination` says so with `NoteHostnameSkipsIPRules`.
  Xray's own fallback that blocks private addresses after resolution exists only
  in the freedom outbound, only for connections that arrived through a vless,
  vmess, trojan, hysteria, wireguard or shadowsocks inbound, and only after the
  operator's own final rules. In newer cores it checks after dialing (a client
  can still probe whether an internal port is open) and is skipped entirely for
  a handler with `sockopt.dialerProxy`. Do not rely on it. sing-box has no such
  fallback. Under AsIs, a connection that Xray rewrites to a sniffed Host or SNI
  is judged by domain rules only: whatever address that name resolves to is
  reached, private ranges included.
- **Name resolution (`on_demand`).** The IP rules judge the resolved addresses.
  What a caller must know:
  - *Failure mode differs.* If the lookup fails, Xray's IP rules simply miss and
    the connection goes on (fail open); sing-box fails the connection (fail
    closed). `MatchDestination` reports an empty `Resolved` as a miss plus
    `NoteResolutionFailedEngineDependent`.
  - *Matched is not always dialed.* Xray resolves again when it dials, so a
    rebinding or round-robin name can be matched on one address and dialed on
    another. sing-box dials the addresses it matched.
  - *`routeOnly: true` inbounds cannot run it.* There the sniffed name replaces
    the real target for the lookup while the connection still goes to the real
    address, so a fake SNI would choose the addresses that are judged
    (`SniffForResolvedIPs` is insufficient). Xray's `domainStrategy` is
    router-wide, so such an inbound keeps the whole node AsIs, not just itself.
  - *Any resolved address is a match.* A block is conservative; a CIDR **allow**
    is permissive, because the dial may use another address.
  - *Cost.* Xray: one uncached lookup at routing, for each hostname connection
    that reaches an IP rule, plus freedom's own lookup when it dials. sing-box:
    one cached lookup that the dial reuses (about nothing extra for an allowed
    connection).
  - *The trace needs the addresses.* PSP's resolver is not the node's, so
    `MatchDestination` resolves nothing and takes the addresses as
    `MatchInput.Resolved`: nil (not given) leaves the IP rules untestable and the
    result conditional (`NoteHostnameNeedsResolution`); non-nil and empty means
    the lookup failed (a miss, `NoteResolutionFailedEngineDependent`). Entries
    that are not IP literals are ignored, so validate what you pass.
- **Search-list expansion.** A dotless hostname can be expanded by the node's DNS
  search list (common under Docker and Kubernetes), so the connection can go to
  a name the domain rules never saw. Domain rules judge the name the client sent.

## Audit observation

`NodeReport.Audit` is the node's record of which destination rules fired: hits
per hour (rule, action, subject, destination, port) and, optionally, which
sites each person used. Hits need the capability `audit.hits.v1` and usage rows
also need `audit.usage.v1`; like the policy capability, neither is an upgrade
capability. A node with nothing to report sends no `audit` at all, and a report
without one is byte-identical to v0.3.0.

- **Report-only.** A hit with action `observe` on a policy (`p*`) or source rule
  (`s*`) means the connection was allowed and would have been blocked, and it
  carries subject, destination and port like a block. On a group (`g*`) it is a
  trial row, folded on the node: no subject, port 0, and the destination is the
  registrable domain or `(ip)`.
- **Spelling.** `Dest` and `Site` are lowercase ASCII hostnames with no leading
  or trailing dot, no empty label and labels of at most 63 bytes (253 in all),
  or, for `Dest` only, an address in canonical `netip` form: no zone, no port,
  no brackets, and an IPv4-mapped IPv6 address is refused (unmap it first).
  `Site` and a trial row's `Dest` are never an address (written `(ip)`) and their
  last label is never a number (`3.4`, `1.2.3`, `0x7f000001` are refused;
  `1.example.com` and `123.com` are fine). A single-label host or a public suffix
  (`localhost`, `github.io`) has no registrable domain, so the host itself is
  used.
- **Drops are counted per kind** (`dropped_hits`, `dropped_trial`,
  `dropped_usage`) so a lost block hit is distinguishable from trial or usage
  overflow. Validation errors never repeat the rejected value.
- **Rule IDs** follow the policy's: a source rule (`s*`) has no `x` suffix, a
  group's `x<k>` rules are allows and never hit, and `allow` is never an action.
- **Capabilities.** Usage rows are the second tier of recording and presuppose
  the first, so an observation with any usage needs both `audit.hits.v1` and
  `audit.usage.v1`.
- **No source address** is carried anywhere, for source rules too.
- **Validation is separate.** `ValidateAuditObservation` checks the subtree by
  itself (`ValidateAuditHit` and `ValidateAuditUsage` check one row, for the
  node's aggregator). It is not part of `ValidateNodeReportBase`, so the panel
  can drop a bad batch without losing the node's roster. The sender-side
  `ValidateNodeReport` does check it, and binds it to the capabilities.
- **Egress (v0.8.0).** With `audit.hits.egress.v1` (not an upgrade capability;
  it presupposes `audit.hits.v1`) a hit may carry `egress`, the link
  (`lnk_<id>`) the connection left through, or would have left through for a
  block. Empty or absent means it left from the server itself. PSP asks for it
  with `DestinationPolicy.AuditEgress` (`audit_egress`), set only for an agent
  that declared the capability, runs Xray and has egress bindings or routes
  through links (its hits can leave through a link). `egress` is
  part of the hit's aggregation key, so the same rule and destination through two
  links are two rows. Both fields are omitted when empty or false: a hit without
  egress and the digest of a policy without the flag are byte-identical to
  v0.7.0. A trial row may carry an egress: a link names two servers, not a
  person. The agent gives hits an egress only while the policy it holds has the
  flag, and `ValidateDestinationPolicy` refuses the flag without `collect`. A
  panel that validates an observation on its own checks the capability itself.
  A panel rolled back below v0.8.0 rejects a batch whose rows differ only in
  egress, so at most the batch in flight is lost.
- **Not durable.** A node restart loses the batch it had not yet sent.
- **Limits.** 4096 hit rows, 8192 usage rows and 1 MiB encoded. The row limits
  are separate caps: with ordinary values both full is over the byte limit, so a
  node trims rows to fit.

Registrable domains are computed on the node, which has the public suffix list;
this module only checks the shape of the result. `conformance.AuditVectors`
pins the accept and reject sets for every implementation.

## Transit forwards

`ConfigBody.Transit.Forwards` asks an agent to relay a port to another server
unchanged: every connection arriving on `port` goes to `target:target_port`, TCP
or TCP and UDP. The agent neither authenticates nor decrypts; the landing server
enforces everything, and it sees the relaying agent's address as the client's.
It is gated by `transit.forward.v1`, and the gate is mandatory: an agent that
does not know the field would accept the config, open no port and report it
applied. Without forwards the field is omitted, so the config of a server that
relays nothing is byte-identical to before.

- **Keys.** A forward is keyed by `ForwardKey` (`fwd_<id>`), a type of its own:
  it never parses as a `ListenerKey`, so its traffic cannot be booked against a
  node.
- **Convergence.** Each forward is a config-stream object with the usual four
  states, keyed by its `ForwardKey`. Forwards are not listeners: they are not
  in `Coverage` and no client attaches to them.
- **Counters.** `NodeReport.ForwardCounters` is a full-report enumeration like
  `ListenerCounters`, absent from partial reports. It is transit traffic and is
  never anyone's usage; the landing already counts the same bytes per user.
- **Target.** A canonical IP address or a lowercase DNS name, resolved by the
  core when it dials. A port, brackets, a trailing dot or a numeric last label
  is refused.

## Transit links

A link is the tunnel of a relay line whose entry terminates the user protocol:
the entry authenticates the user on its own listener and sends the traffic
through the link to the exit server, which connects to the destination. It is
gated by `transit.link.v1`, and the gate is mandatory: an agent that does not
know the fields would serve the bound listeners from its own address.

- **Halves.** The exit holds the link in `Transit.LinksIn` (a listener that
  accepts only the link's credential and sends traffic straight out); the entry
  holds it in `Transit.LinksOut` (an outbound that dials the exit). Both are
  keyed by the same `LinkKey` (`lnk_<id>`), a type of its own. One agent cannot
  hold both halves of one link.
- **Egress.** `Transit.Egress` binds an entry's listener to one of its outgoing
  links. A listener without a binding leaves from the agent itself. Only a
  listener can be bound; chaining links (multi-hop) is not part of v1.
- **Protocols.** `ss2022` (a single-user Shadowsocks-2022 key, AES-128 or
  AES-256) for links that do not cross a censored border; `vless_reality` for
  links that do. The REALITY private key exists only in `LinkIn`; `LinkOut`
  carries the public key and has no field for the private one.
- **Convergence and counters.** Each half is a config-stream object keyed by its
  `LinkKey`. `NodeReport.LinkCounters` is a full-report enumeration. Link
  traffic is never anyone's usage: the user is charged once, on the entry's
  listener.

Multi-hop chains are a later addition to `Transit`, behind a capability of their
own.

## Link probes (v0.9.0)

`Transit.Probe` asks an agent to self-test the lines it is the entry of, and
For an end-to-end probe, an agent can report its active internal TCP listener in
`loopback_port` (127.0.0.1, ports 31000–31999). An omitted port means that the
agent did not report a listener.

`NodeReport.Probes` carries what it measured. It is gated by
`transit.probe.v1` (not an upgrade capability), and the gate is mandatory: an
agent that does not know the field would leave the panel showing "never probed"
for a line nobody is measuring. An agent that did not declare it must not send
`Probes`; `ValidateNodeReport` refuses them.

- **What is probed.** The links probed are exactly `Transit.LinksOut`: the entry
  is the side that dials the exit, and there is no separate list to disagree
  with. Forwards are opt-in through `ProbeSettings.Forwards`, each with a method
  (`tcp` or `quic`) and each present in the same `Transit.Forwards`.
- **Settings.** `interval_seconds` 30..3600, `timeout_ms` 500..10000. `link_url`
  is an absolute `http` or `https` URL without credentials, at most 512 bytes;
  empty means links are probed transport-only and no `e2e` result exists.
  Settings with no `LinksOut` and no forward are refused, so the panel never
  sends a block that means nothing.
- **Results.** One `ProbeResult` per (key, kind): `e2e` and `transport` for a
  link (`lnk_`), `forward` for a forward (`fwd_`). `failures` is within
  `0..attempts`, `attempts` at most 1000, RTTs are ordered and all zero when no
  attempt succeeded, and `last_error` is one of `timeout`, `refused`, `tls`,
  `http_status`, `dns`, `probe_unavailable`, `other`.
- **Full reports only.** Like the counters, `Probes` is absent from a partial
  report, and a partial report that carries them is refused. Without `Probe` and
  `Probes` the encodings are byte-identical to v0.8.x.

## Routing by destination (v0.9.0)

`Transit.Routes` lets one listener leave through different exits depending on
where the connection is going: streaming through one link, mail from the server
itself, the rest through the listener's egress binding. It is gated by
`transit.route.v1` (not an upgrade capability), and the gate is mandatory: an
agent that does not know the field sends everything through the default exit,
so a user would be served from the wrong country with no error anywhere. The
same gate covers `DestinationRule.Exits`. Without `Routes` and `Exits` the
encodings are byte-identical to before.

- **Routes.** `ListenerRoutes{listener, rules}`, one entry per listener, at most
  64 rules per listener and 1024 in all. A `RouteRule` has an id `r<n>` (n >= 1,
  unique per listener), matchers (`domains`, `cidrs`, `ports`, `network`, with
  the meaning they have in a policy rule) and an `exit`. The first matching rule
  decides; a connection no rule matches leaves through the listener's default
  exit, which is its `EgressBinding` if it has one and the agent itself
  otherwise. A rule must match on something. `MatchRoute(transit, listener,
  input, resolve)` is the reference model and returns `(exit, known)`: input a
  rule depends on and leaves unknown (a port, a network, a target) makes that
  rule untestable, and then `known` is false and `exit` is only a guess.
  `MatchRouted` leaves the exit unknown in that case, so a policy rule with
  `Exits` comes back untestable and the result conditional, never a confident
  verdict on a guess. Under `resolve: on_demand` the router resolves a hostname
  for a rule's CIDRs, so a hostname meets them through `MatchInput.Resolved`
  (nil: untestable); under as-is a hostname never matches CIDRs. A trailing dot
  is not normalised.
- **Exits.** `exit` is `local` (`LocalExit`) or a key of the same
  `Transit.LinksOut`. `local` is a `LinkKey` in type only: `LinkKey.RowID`
  rejects it, so it is valid nowhere but `RouteRule.Exit` and
  `DestinationRule.Exits`, and a link, an egress binding, an audit hit or a
  probe result can never carry it.
- **Domains.** `domain:`, `full:` and `keyword:`. A `regexp:` is refused, so that
  every route rule can be intersected with a policy rule exactly.
- **Policy rules by exit.** `DestinationRule.Exits` is a sorted, duplicate-free
  list of `local` and `lnk_` keys (sorted as text, so `lnk_10` precedes `lnk_3`).
  Empty applies whatever the exit; otherwise the rule applies only to traffic
  whose chosen exit is in the set. It is a scope like `Inbounds`, not a matcher,
  and a source rule carries none. `MatchInput.Exit` carries the exit into
  `MatchDestination` (unknown makes such a rule untestable), and `MatchRouted`
  fills it from the transit. Whether a link is one of the agent's is the
  Transit's question; the policy validator checks the form only.
- **Compile contract.** The exit is the first matching route rule, else the
  default. A consumer applying the policy per exit must emit, for each routed
  listener and in route order, segment k = every policy rule whose `exits` allows
  exit k (empty allows all), each ANDed with route rule k, followed by a
  catch-all on route rule k to exit k; then the default segment. Earlier
  segments consume the traffic of earlier route rules, and the result is
  correct because of that ordering: the `exact` of `IntersectDestinations`
  applies to one (policy rule, route rule) pair only and does not exclude
  earlier route rules by itself.
- **Intersection.** `IntersectDestinations(a, b)` is the conjunction of two
  `DestinationMatcher`s, which is how the Xray compiler applies a policy rule to
  the traffic one route rule sends out one exit. When `exact` is true the
  result matches precisely what both match; it is fuzz-tested against the
  reference matcher. When it is false the result is an over-approximation: it
  matches everything both match and possibly more, never less. That is safe for
  a block and wrong for an allow, so a caller that cannot over-match must refuse
  an inexact result. Inexact pairs: a `regexp:` against a domain, keyword or
  regexp; two keywords neither of which contains the other; and, under
  `on_demand`, a hostname entry against an address matcher (a hostname that
  merely resolves into the CIDRs matches) or two address matchers. A `full:` is
  exact against everything, a keyword against a domain is exact (as a `regexp:`
  entry when the domain does not hold the keyword, which a caller bounding
  regexps must count) unless the domain or keyword is not ASCII or the
  generated regexp exceeds 1024 bytes, in which case it is inexact, and a
  result that matches nothing is `Never`, exact. An inexact result is a
  superset: safe for a block, and it must never be used for an allow or an
  observe rule.

## SNI fronts (v0.9.0)

`Transit.Fronts` lets several TLS or REALITY uses share one TCP port, normally
443: the agent binds the port itself and routes each raw connection by the SNI of
its ClientHello, without decrypting anything. It is gated by `transit.sni.v1`
(not an upgrade capability), and the gate is mandatory: an agent that does not
know the field would never bind the port where users reach the listeners that
were moved off it, so every node on a shared 443 would go dark while the config
reads as applied. Without `Fronts` the encoding is byte-identical to before.

- **Keys and states.** A front is keyed by `FrontKey` (`fnt_<id>`), a type of its
  own, and reports the usual four config-object states under that key. Fronts are
  not listeners: they are not in `Coverage` and no client attaches to them.
- **Shape.** `Front{key, listen, port, listeners, routes, default}`. At most 16
  fronts, 256 routes per front, 1..16 server names per route. Names are sorted,
  lowercase, exact (no wildcard or suffix match), pass the same server-name check
  a REALITY link does, and appear in at most one route of a front. A front needs
  at least one route and a `default`, which takes every connection no route names,
  SNI absent included.
- **Targets.** A `FrontTarget` names exactly one of `listener`, `forward`, `link`
  or `external`.
  - *Listener.* A listener keeps its public port in its own config; the front
    lists it in `listeners` with a `loopback_port`, and the agent binds it to
    `127.0.0.1:<loopback_port>` instead. Every fronted listener must be the
    target of a route or the default, and loopback ports are 1..65535 and unique
    across the whole transit. A loopback port must also not be the port of any
    front, forward or incoming link whose bind includes 127.0.0.1's side of the
    host: an empty `listen`, `0.0.0.0`, `::`, or any address in `127.0.0.0/8`
    (`::1` is another socket and is not counted). **Not checked here:** the
    listener's public port lives in its own config, which `ValidateTransit`
    cannot see. It must equal `Front.Port`, and the listener must be a TCP
    TLS or REALITY listener; the panel and the agent check this.
  - *Forward.* A `Transit.Forwards` entry with network `tcp` and the same `listen`
    and `port` as the front: the front owns the socket, and the forward says where
    it lives so the two descriptions cannot disagree.
  - *Link.* A `vless_reality` `Transit.LinksIn` entry with the same `listen` and
    `port`. Routes to a link name only server names the link accepts
    (`reality.server_names`), no route may send one of the link's names to another
    target, and unless the link is also the default every one of its names must be
    routed to it: a REALITY client reaches the link by its own server name.
  - *External.* `{host, port}` and only as `default`: a real website that unknown
    or absent SNIs are relayed to, so a scanner sees an ordinary site. The host is
    a canonical IP or a lowercase DNS name, as for a forward. A host that means
    this machine is refused whatever the port: loopback, the unspecified address,
    all of `0.0.0.0/8`, `localhost` and `*.localhost`. So is a host:port that is a
    bind of this transit: a front's, a forward's or an incoming link's `listen`
    address on its port, mapped spellings included (a forward on
    `203.0.113.5:8443` relaying to `203.0.113.5:443`, behind a front there, is a
    loop of two sockets). A wildcard bind cannot be matched against a named host.
    **Not detectable here:** with an empty `listen`, the host's own public
    address on a bound port would loop back; the agent and the panel must check
    it.
- **One front each.** A listener, forward or link is behind at most one front
  (it may be both a route target and the default of that front). Two fronts must
  not share a bind: the same address and port, or one with an empty `listen` (every
  address) over a specific one on the same port. A forward or incoming link whose
  bind overlaps a front's is refused unless it is that front's target. An
  IPv4-mapped IPv6 address is compared as the IPv4 address it maps. `0.0.0.0` overlaps every IPv4
  address and `::` is taken as dual-stack and overlaps all, as on Linux.
- **Probe.** `ProbeMethodTLS` (`"tls"`) sends a ClientHello and succeeds on a
  ServerHello. The server name is the first name (names are sorted) of the first
  route, in `Front.Routes` order and then `Transit.Fronts` order, that targets
  the forward. It is valid only for a forward that is a front *route* target, and
  such a forward must be probed with `tls`: `tcp` would only show that the front
  is up. A forward that is only a front's default has no name to send and may be
  probed with `tcp`, which reaches the default.
- **Caveats.** Xray-only in practice: the agent declares the capability only
  where its engine can do this, and PSP must not read the capability as available
  on other engines. A client must not split its ClientHello across TLS records;
  the front reads the SNI from the first record, so a split ClientHello does not
  reach its route. Sniffing waits for the first bytes, so a plain-HTTP probe
  (which sends nothing TLS-shaped) is not handed on until the sniff gives up.

## Compressed sync (v0.9.0)

`MaxSyncBodyBytes` bounds the raw JSON of one `/v1/node/sync` body, and the
roster is sent whole whenever it changes, so a server's client count had a ceiling
set by its roster's size. Roster JSON is highly repetitive, so the fix is to bound
what travels separately from what is held. `sync.gzip.v1` (not an upgrade
capability) lets either side send a body with `Content-Encoding: gzip`.

- **Negotiation.** Both ends must say so. The agent declares the capability in
  `NodeReport.Capabilities`; its first report is plain, because it cannot yet know
  the panel accepts anything else. PSP may then gzip its responses to that agent,
  and only to an agent that declared it. PSP says it accepts compressed requests
  with `Accept-Encoding: gzip` on its responses (`AcceptsSyncGzip` reads it; a
  `q` that is not a finite number in (0, 1] is not an offer); an agent compresses a request only after a response carried
  that and only if it declared the capability. A receiver refuses a coding it did
  not negotiate. The agent's state is a small machine (`SyncCompression`, with an
  injectable clock): it starts plain; **only a 2xx response changes it, and its
  `Accept-Encoding` replaces the state (absent means plain)**; a non-2xx response
  (a 5xx included) or a request that got no response leaves it as it was. On any
  non-2xx response to a compressed request other than the transients (408, 429,
  500, 502, 503, 504, 520-530) and 401/407, the agent resends the same request
  once in plain (`Rejected`). Only if that plain resend succeeds was the coding the
  problem: gzip then stays **off for one hour** (`SyncGzipCooldown`, started by
  `PlainRetried`). If it fails too, nothing changes, so an unrelated refusal
  never costs an hour without compression. During the cooldown an advertisement
  is ignored but a 2xx without one still switches gzip off (a panel rolled back
  to one without gzip); when the cooldown ends the agent tries gzip again on what
  it last learned. The state lives in the agent's memory and starts plain at
  every start. Nothing in
  the body changes, and segment ETags are taken over the
  canonical decoded bytes, so compression never moves a validator.
- **Two limits.** `MaxSyncWireBytes` (16 MiB, the old `MaxSyncBodyBytes`) bounds
  what crosses the wire, compressed or not; `MaxSyncDecodedBytes` (64 MiB) bounds
  the body after decompression. A body with no coding is held to the wire limit
  exactly as before, so a peer without the capability behaves byte-identically.
  64 MiB is four times the wire limit: roster JSON repeats its keys in every
  client and routinely shrinks by an order of magnitude, so this leaves headroom.
  **Memory:** a decoded body of N bytes is transiently held about twice (the
  chunks it was read into and the joined result), so a body at the ceiling costs
  about 128 MiB at the join, and parsing the JSON costs several times N on top.
  PSP, which may decode many reports at once, must bound concurrent decodes (a
  semaphore sized to its memory); this module does not. Both limits are ceilings:
  the decoder allocates what it reads, and a body that exceeds the decoded limit
  is refused after about limit+1 bytes of chunks, without being joined.
- **HTTP clients.** Go's default `http.Transport` adds `Accept-Encoding: gzip`
  itself and then inflates the response transparently with no size limit, which
  bypasses both limits. A caller must set `DisableCompression: true` (or set
  `Accept-Encoding` explicitly) and decode with `DecodeSyncBody`. A message may
  carry several `Content-Encoding` headers; read them all with
  `SyncEncodingFromHeaders(header.Values("Content-Encoding"))`, which refuses
  more than one.
- **Helpers.** `DecodeSyncBody(r, contentEncoding)` reads one body under both
  limits and returns the decoded bytes. The limit is enforced on the decompressed
  output as it streams: the decoder stops after limit+1 bytes of output and the
  rest of the stream is never inflated, so a bomb costs about the limit, not its
  size. A legitimate body is read in chunks of at most 1 MiB and joined once, so
  decoding holds up to twice the body at the join (at the ceiling, 128 MiB), not a
  growing buffer's old and new copies; the gzip stream must be complete and valid, trailing bytes count
  toward the wire limit, and any coding other than none, `identity` or `gzip`
  (a list, a parameter, `br`, `deflate`) is refused with `ErrSyncUnknownEncoding`
  before anything is read. `EncodeSyncBody(body)` gzips a body, refusing one over
  either limit. The output has no timestamp, so it is deterministic for a Go
  release. Failures are `ErrSyncWireTooLarge`, `ErrSyncDecodedTooLarge` and
  `ErrSyncUnknownEncoding`.

## Source guard (v0.10.0)

Direct, plain-forward and CDN lines end on the same landing listener, so the
listener cannot tell which line a connection came through, and a per-line client
identity could be used on the wrong line. The source guard makes the core refuse
the mismatch. It is gated by `transit.source_guard.v1` (not an upgrade
capability), and the gate is mandatory: an agent that does not know the fields
accepts every connection while the config reads as applied, which is the bypass
the guard exists to close. PSP must send `Transit.SourceSets` and
`Client.SourceGuard` only to an agent that declared it, and the agent declares it
only where its engine can enforce the guard.

- **Sets.** `Transit.SourceSets` is `[{key, cidrs}]`. A key is `src_<suffix>`
  with the suffix matching `[a-z0-9][a-z0-9_-]{0,47}`. Keys are unique, at most
  4096 sets; each set has 1..1024 CIDRs, each a canonical prefix (equal to its
  masked form, IPv4 or IPv6, no zone, no IPv4-mapped IPv6), unique within the set.
- **Guards.** `Client.SourceGuard` is `{allow_from, deny_from}`; exactly one of
  them is set (a guard with neither is invalid, so omit it). `deny_from` is at
  most 64 unique keys. The roster cannot see the config, so
  `ValidateClientSourceGuard` does not check that the sets exist.
- **Semantics.** The source is the address the core sees; behind a front it is the
  address from the PROXY protocol header. `allow_from`: the client's connections,
  on any of its listeners, are accepted only when the source is inside the set;
  if the set is missing from the config the client is refused entirely (fail
  closed). `deny_from`: refused when the source is inside any listed set; a
  missing set is ignored. Without guards the encoding is byte-identical to before.
- **Hits.** `NodeReport.SourceGuardHits` is `[{set, listener, source_ip, count,
  last_seen_ms}]`, at most 256, unique per (set, listener, source), count and
  time positive, `source_ip` canonical. For an allow guard `set` is the set the
  source was outside of; for a deny guard, a set that contains the source. How
  completely an engine can observe refusals is the agent's to document.
- **Interface addresses.** `NodeReport.InterfaceAddresses` lists the agent's own
  addresses that can be a public source: canonical global unicast, excluding
  private (RFC 1918, IPv6 ULA), CGNAT (100.64.0.0/10) and documentation ranges,
  sorted ascending, unique, at most 64 (`IsPublicSourceAddr` is the filter). The
  panel uses them as a relay line's source set when this agent is the entry.
- **Full reports only.** Both report fields are omitted from partial reports, and
  `ValidateNodeReportBase` refuses a partial report that carries them.
  `ValidateNodeReport` refuses them without the capability.

## Development

```bash
go test ./...          # unit and conformance
go test -race ./...
go vet ./...
```

Nothing here talks to the network, a database or a filesystem.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
