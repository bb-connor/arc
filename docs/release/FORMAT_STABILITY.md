# Format Stability

This note states what Chio promises about the stability of its own formats
before the first stable release. It covers every Chio-owned versioned family:
wire and signed artifacts (capabilities, receipts, passports, evidence and
co-sign bytes), schema ids under `spec/`, process and FFI ABIs, journal and
envelope formats, and SQLite store schemas.

## The rule today

1. **Every Chio-owned versioned family is v1.** A family has one live version.
   Older versions are deleted, not kept beside the current one. Format ids use
   `.v1`, integer schema versions start at 1, and each SQLite store has exactly
   one v1 schema with no migrations. Sibling shapes that are all still written
   carry distinct names, each at v1.
2. **An id reused from v0.1.0 does not mean the v0.1.0 shape.** Where the
   deprecated `v0.1.0` release used the same `.v1` id for a different shape, the
   current shape owns the id and rejects the old shape structurally (unknown
   fields denied, required fields enforced). Readers never dispatch on the id
   string. `v0.1.0` is not an upgrade or interoperability source.
3. **An older stamp is refused, not converted.** A store whose stamp is not its
   single v1 stamp is refused with an exact `StaleSchema` error before it serves.
   A populated database with no stamp is refused as foreign. There is no
   importer, schema ladder, fallback reader or alternate writer. Development
   databases with a retired layout are wiped and reprovisioned.
4. **Previews carry no cross-preview compatibility.** A `0.2.0-alpha.N` preview
   promises nothing about the formats of any other preview. Bytes written,
   signed or stored by one preview may be refused by the next, and a format
   change between previews keeps its v1 id. Treat preview state as disposable:
   reissue capabilities, re-sign artifacts and reprovision stores when you move
   to a new preview.
5. **Errors deny.** A payload, artifact or store that does not match the current
   v1 shape is refused. No version mismatch is silently accepted, upgraded or
   downgraded.

Version numbers above v1 that still appear in source on `main` are pending
collapse under this rule. They are not compatibility promises.

## External protocol revisions

The rule covers Chio-owned formats only. A named external protocol revision
keeps the version its owner publishes, and Chio may support more than one
revision of it at once. The exempt revisions are:

- MCP revisions `2025-11-25` and `2026-07-28`
- Sigstore
- TDX, SEV and TPM attestation formats
- Envoy v3
- PagerDuty and Opsgenie v2
- Cohere API v2
- A2A
- x402
- W3C Verifiable Credentials and DIDs

A revision that is not on this list is not exempt until the owner adds it.

## Open items

These questions are open. This note does not decide them.

- **D8, preview exception.** Whether tagged `0.2.0-alpha.N` previews may ship
  before the post-merge obligations of #1160 close
  ([UNIFIED_ROADMAP.md](../operations/UNIFIED_ROADMAP.md), decision table).
- **D10, crates.io.** Whether to yank the `chio-*` 0.1.x crates in favour of
  the preview channel, or keep the Rust library in the preview's supported
  surface.
- **D20, contract version number.** Whether `spec/schemas/VERSION` stays at
  1.0.0 with a preview label, or is renumbered to a 0.x preview version.
- **Post-stable commitments (backlog I-037).** Verification of the previous
  stable version, published migrations between stable versions, conformance
  vectors per stable version, a deprecation window for v1 tokens and receipts,
  and the treatment of the OCSF export version. None of these applies before
  the first stable release.

## Proposed: deprecation after the first stable release

> **Proposed, not adopted.** This section is a starting point for the I-037
> decision. Nothing in it is a commitment until the owner approves it and this
> banner is removed.

- A stable release names the formats it freezes, each with conformance vectors
  under `tests/bindings/vectors`.
- A breaking change to a frozen format takes a new version id. The release
  that introduces it still verifies the previous version, and the following
  stable release may remove it.
- A removal is announced in `CHANGELOG.md` at least one stable release ahead,
  with the replacement id and a migration note.
- Stored state crosses a stable boundary only through a published, tested
  migration. Preview state never does.

## Related documents

- [Install guide](../install/README.md)
- [Verifying release artifacts](../install/VERIFY.md)
- [Unified roadmap](../operations/UNIFIED_ROADMAP.md), lane REL
- [Changelog](../../CHANGELOG.md)
