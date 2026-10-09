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

## Development

### Destination policies (additive v1 contract)

`ConfigBody.Policy` and `NodeReport.PolicyStatus` are optional and require
`policy.destination.v1`. Nil policy preserves the v0.2.0 configuration bytes;
full and partial reports both retain policy status. Producers validate before
sending; receivers validate status separately from `ValidateNodeReportBase` so
bad optional observations cannot block control synchronization.

`ValidateDestinationPolicy` enforces explicit scoped catch-all rules, canonical
sorted sets and bounded rules, domains, regular expressions, CIDRs, subjects and
encoded bytes. Rule order is preserved in validation, previews and digests.
`MatchDestination` is a pure destination preview with shadowed-rule evidence;
it never resolves DNS and cannot inspect BitTorrent traffic. An applicable
unknown protocol rule before a known outcome returns `untestable` rather than
promising that outcome. IDNA and registrable-domain computation belong to the
products, not this standard-library-only module. Shared destination and Xray
sniffing vectors live in `protocol/conformance`.

This intentionally extends the frozen beta11 API. The extraction harness still
checks the unchanged legacy shapes with the optional fields absent; it does not
prove destination-policy interoperability. The new conformance and consumer
tests cover that extension. It does not change the wire generation or agent
upgrade capability requirements.

### Audit observations (additive v1 contract)

`NodeReport.Audit` is optional and is retained on full and partial reports.
Sending any audit requires `audit.hits.v1`; `usage` also requires
`audit.usage.v1`, including batches carrying only loss counters. Neither is an
agent-upgrade requirement and installing this module enables neither capability.
Nil audit preserves the legacy report encodings.

`ValidateAuditObservation` validates one frozen batch for one UTC hour, collection
revision and kind: `block`, `observe`, `trial` or `usage`. It enforces kind/action
separation, positive counts, ordered timestamps inside that hour, unique aggregate
keys, at most 4,096 hit rows or 8,192 usage rows, and a 1 MiB encoded subtree.
Trial rows carry an exact group rule with an empty subject and zero port; the
node must collapse destinations to eTLD+1 or `(ip)` before aggregation. Usage
sites also exclude IP literals. IDNA, hostname normalization and public suffix
calculation belong to the node; this module validates the supplied result and
never recomputes the registrable domain.

Senders validate audit separately before constructing a report, dropping a bad
subtree rather than preventing control synchronization. Receivers isolate its
decoding as well as validation: `ValidateNodeReportBase` deliberately ignores
it. Products use injected clocks to enforce the shared 48-hour replay and
one-hour future-skew limits, and the receiver separately requires its current
collection revision. First-receipt batch deduplication lasts 72 hours.

The node's aggregates, pending batches and loss counters are all in memory.
Retries preserve the batch ID and frozen contents. Restart can lose the whole
unacknowledged 48-hour backlog; sync success does not prove database persistence.
This is best-effort telemetry, not a reliable audit trail. Counter-only batches
retain bounded loss evidence when no event row survives.

This is stage 2a, stacked on the destination-policy stage 1a while it is under
review. Stage 1a must merge, pass main checks and publish `v0.3.0` separately;
stage 2a then targets `v0.4.0` after its own main checks. These tags have not been
published by this change. The beta11 harness continues to verify unchanged
legacy reports with both optional extensions absent. It intentionally cannot
prove policy or audit interoperability; new unit/fuzz tests and subsequent
Node/PSP integration cover those extensions.

### Checks

```bash
go test ./...          # unit and conformance
go test -race ./...
go vet ./...
```

Nothing here talks to the network, a database or a filesystem.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
