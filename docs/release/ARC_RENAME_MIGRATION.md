# ARC Rename Migration Guide

**Status:** Phase 31 dual-stack update  
**Date:** 2026-03-25

## Goal

Rename the project from PACT to ARC in a way that is survivable for operators,
SDK consumers, and historical artifact verification.

## Compatibility Window

The rename uses an ARC-primary, ARC-compatible transition:

- ARC becomes the primary product name and documented entrypoint
- a small set of legacy Pact-era names remain as explicit deprecated
  compatibility shims where needed
- historical ARC artifacts remain verifiable
- the compatibility window lasts through the first ARC-branded release cycle

## Migration Matrix

| Surface | ARC-primary behavior | ARC compatibility behavior |
|---------|----------------------|-----------------------------|
| Rust crates | `arc-*` names are canonical | old `pact-*` names are migration-only history; no maintained crate keeps Pact branding |
| CLI binary | `arc` is the primary binary | any remaining Pact wrappers should be treated as deprecated transition shims only |
| CLI docs/examples | ARC examples first | Pact examples exist only when the migration itself is being explained |
| TypeScript SDK | ARC package name becomes canonical | old npm package kept only as a wrapper or documented replacement, depending on registry constraints |
| Python SDK | ARC distribution/docs become canonical | old package/import path documented and supported during transition window |
| Go SDK | ARC module/docs become canonical | old module path documented during transition window |
| Environment variables | `ARC_*` names are canonical where the runtime exposes branded envs | old Pact-era names remain only where a documented compatibility shim still exists |
| Signed artifacts | `arc.*` artifact families are canonical | historical artifacts remain verifiable; no blind rewrite of stored evidence |
| Portable-trust identity | `did:arc` is the shipped canonical DID method | legacy Rust symbol aliases can remain temporarily, but no Pact DID remains on the wire |
| Native service authoring API | `NativeArcServiceBuilder` / `NativeArcService` are canonical | `NativePactServiceBuilder` / `NativePactService` remain deprecated Rust aliases for one transition cycle |
| MCP streaming extension | `arcToolStreaming` / `arcToolStream` are canonical | `pactToolStreaming` / `pactToolStream` remain deprecated wire aliases for one transition cycle |

## Intentional Compatibility Decisions

The post-sweep contract is:

- frozen and canonical: `did:arc`, `arc.*` artifact schema IDs, and
  `notifications/arc/tool_call_chunk`
- temporary deprecated aliases: `DidPact`, `NativePactServiceBuilder`,
  `NativePactService`, `pactToolStreaming`, and `pactToolStream`
- not kept: broad Pact branding across maintained docs, examples, crate names,
  or primary CLI/package surfaces

## Rollout Order

1. **Inventory and contract**
   Finish Phase 29 before renaming code or packages.

2. **Workspace and packaging**
   Rename repo metadata, crates, CLI, and SDK package surfaces in Phase 30.

3. **Protocol and identity**
   Apply schema and DID transition work in Phase 31 after verifiers/importers
   are ready for dual-stack handling.

4. **Docs and qualification**
   Rewrite public/operator docs and run full ARC qualification in Phase 32.

## Operator Notes

- do not rewrite stored historical receipts or passports just to match the new
  name
- upgrade verifiers/importers before switching issuance defaults
- prefer `ARC_MCP_SESSION_*` env names; keep `ARC_MCP_SESSION_*` only during
  the documented compatibility window
- treat remaining Pact aliases as a temporary migration surface, not the
  long-term canonical name

## SDK Consumer Notes

- expect package rename guidance per ecosystem in Phase 30
- prefer ARC-branded imports/examples once they ship
- keep deprecated Pact-era imports only where the compatibility window
  explicitly says they remain supported
