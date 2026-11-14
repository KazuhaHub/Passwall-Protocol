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

What is shared beyond the types: `ValidateDestinationPolicy`,
`ValidatePolicyStatus`, `PolicyDigest`, `CheckXraySniffing` (can this inbound's
sniffing supply what the policy needs), `MatchDestination` (a pure trace of
which rule a connection would hit) and `PrivateDestinationCIDRs()` (the table
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
- **No name resolution.** Hostnames are never matched against `cidrs` or
  `private`; `MatchDestination` says so with `NoteHostnameSkipsIPRules`. Xray's
  own fallback that blocks private addresses after resolution exists only in the
  freedom outbound, only for connections that arrived through a vless, vmess,
  trojan, hysteria, wireguard or shadowsocks inbound, and only after the
  operator's own final rules. In newer cores it checks after dialing (a client can
  still probe whether an internal port is open) and is skipped entirely for a
  handler with `sockopt.dialerProxy`. Do not rely on it. sing-box has no such
  fallback.
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
- **Not durable.** A node restart loses the batch it had not yet sent.
- **Limits.** 4096 hit rows, 8192 usage rows and 1 MiB encoded. The row limits
  are separate caps: with ordinary values both full is over the byte limit, so a
  node trims rows to fit.

Registrable domains are computed on the node, which has the public suffix list;
this module only checks the shape of the result. `conformance.AuditVectors`
pins the accept and reject sets for every implementation.

## Development

```bash
go test ./...          # unit and conformance
go test -race ./...
go vet ./...
```

Nothing here talks to the network, a database or a filesystem.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
