# Chio Rename Migration Guide

**Status:** Phase 31 dual-stack update  
**Date:** 2026-03-25

## Goal

Rename the project from PACT to Chio in a way that is survivable for operators,
SDK consumers, and historical artifact verification.

## Compatibility Window

The rename uses an Chio-primary, Chio-compatible transition:

- Chio becomes the primary product name and documented entrypoint
- a small set of legacy Pact-era names remain as explicit deprecated
  compatibility shims where needed
- historical Chio artifacts remain verifiable
- the compatibility window lasts through the first Chio-branded release cycle

## Migration Matrix

| Surface | Chio-primary behavior | Chio compatibility behavior |
|---------|----------------------|-----------------------------|
| Rust crates | `chio-*` names are canonical | old `pact-*` / `arc-*` names are migration-only history; no maintained crate keeps Pact or ARC branding |
| CLI binary | `chio` is the primary binary | any remaining Pact/ARC wrappers should be treated as deprecated transition shims only |
| CLI docs/examples | Chio examples first | Pact/ARC examples exist only when the migration itself is being explained |
| TypeScript SDK | Chio package name becomes canonical | old npm package kept only as a wrapper or documented replacement, depending on registry constraints |
| Python SDK | Chio distribution/docs become canonical | old package/import path documented and supported during transition window |
| Go SDK | Chio module/docs become canonical | old module path documented during transition window |
| Environment variables | `CHIO_*` names are canonical where the runtime exposes branded envs | old Pact-era / ARC-era names are not supported |
| Signed artifacts | `chio.*` artifact families are canonical | historical artifacts remain verifiable; no blind rewrite of stored evidence |
| Portable-trust identity | `did:chio` is the shipped canonical DID method | legacy Rust symbol aliases have been removed; no Pact or ARC DID remains on the wire |
| Native service authoring API | `NativeChioServiceBuilder` / `NativeChioService` are canonical | `NativePactServiceBuilder` / `NativePactService` / `NativeArcServiceBuilder` / `NativeArcService` have been removed |
| MCP streaming extension | `chioToolStreaming` / `chioToolStream` are canonical | `pactToolStreaming` / `pactToolStream` have been removed |

## Intentional Compatibility Decisions

The post-sweep contract is:

- frozen and canonical: `did:chio`, `chio.*` artifact schema IDs, and
  `notifications/chio/tool_call_chunk`
- removed deprecated aliases: `DidPact`, `DidArc`, `NativePactServiceBuilder`,
  `NativePactService`, `NativeArcServiceBuilder`, `NativeArcService`,
  `pactToolStreaming`, `pactToolStream`, `arcToolStreaming`, and `arcToolStream`
- not kept: Pact or ARC branding across maintained docs, examples, crate names,
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
   Rewrite public/operator docs and run full Chio qualification in Phase 32.

## Operator Notes

- do not rewrite stored historical receipts or passports just to match the new
  name
- upgrade verifiers/importers before switching issuance defaults
- prefer `CHIO_MCP_SESSION_*` env names; keep `CHIO_MCP_SESSION_*` only during
  the documented compatibility window
- treat remaining Pact aliases as a temporary migration surface, not the
  long-term canonical name

## SDK Consumer Notes

- expect package rename guidance per ecosystem in Phase 30
- prefer Chio-branded imports/examples once they ship
- keep deprecated Pact-era imports only where the compatibility window
  explicitly says they remain supported
