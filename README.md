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
exists. It is excluded from this module's CI and is not a dependency of anything.

## Development

```bash
go test ./...          # unit and conformance
go test -race ./...
go vet ./...
```

Nothing here talks to the network, a database or a filesystem.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
