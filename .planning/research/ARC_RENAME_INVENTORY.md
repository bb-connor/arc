# ARC Rename Inventory

**Date:** 2026-03-25  
**Status:** Phase 29 inventory baseline

## Classification Model

- `rename` — move the primary surface to ARC in a later execution phase
- `alias` — keep a narrow deprecated Pact-era shim temporarily while ARC
  becomes primary
- `freeze` — leave the legacy name in place for compatibility/history
- `convert` — support old PACT objects while issuing new ARC ones

## Inventory

| Surface | Examples | Classification | Notes |
|---------|----------|----------------|-------|
| Repo and workspace identity | root project name, GitHub repo URL, release names | rename | ARC becomes the primary repo/product identity |
| Rust crate names | `arc-core`, `arc-cli`, `arc-kernel`, `arc-*` workspace members | rename | ARC crates are canonical; Pact crate names are migration history only |
| CLI binary and commands | `arc check`, `arc trust`, `arc passport`, `arc certify` | rename + alias | ARC commands are canonical; any remaining Pact wrappers are deprecated shims only |
| SDK package names | `@arc-protocol/sdk`, `arc-ts`, `arc-py`, `arc-go` | rename + alias | ARC packages become primary; Pact wrappers survive only where registry constraints require them |
| Environment variables and config keys | `ARC_*`, config path text, release examples | alias | ARC names are canonical; old Pact-era aliases survive only where documented |
| Neutral HTTP routes | `/v1/...` endpoints without ARC branding | freeze | Keep neutral routes unchanged unless branding is embedded in payloads/examples |
| Docs and standards titles | README, VISION, roadmap, release docs, `ARC_*` doc names | rename | Phase 32 rewrites the public narrative to ARC |
| Signed schema identifiers | `arc.manifest.v1`, `arc.checkpoint_statement.v1`, `arc.dpop_proof.v1`, portable-trust schemas | convert | `arc.*` is canonical; historical PACT artifacts remain verifiable |
| Portable-trust identities | `did:arc`, `DidArc`, deprecated `DidPact` alias | rename + alias | `did:arc` is canonical on the wire; only the Rust alias remains temporarily |
| Signed artifact families | receipts, passports, verifier policies, certifications, evidence exports | convert | Old artifacts remain valid; new ARC artifacts may get new schema IDs |
| Native service API | `NativeArcServiceBuilder`, `NativeArcService`, deprecated Pact aliases | alias | ARC names are canonical; Pact aliases remain source-compatible for one cycle |
| MCP streaming extension | `arcToolStreaming`, `arcToolStream`, deprecated Pact aliases | alias | ARC keys are canonical; Pact keys remain wire-compatible for one cycle |
| Examples and snippets | CLI examples, package import examples, docs commands | rename + alias | Docs move to ARC-first examples with Pact notes only where migration is being explained |
| Tests and fixtures | assertions over `arc.*`, `did:arc`, package names | rename + convert | Fixtures need dual-stack handling only where legacy compatibility is intentional |

## Phase Dependencies

### Drives Phase 30

- repo/workspace/package rename
- CLI primary surface switch to `arc`
- SDK package rename strategy
- environment variable and example migration

### Drives Phase 31

- schema identifier dual-stack policy
- signed artifact compatibility
- `did:arc` / `did:arc` transition contract

### Drives Phase 32

- doc rewrite order
- migration guide structure
- qualification scope for ARC primary plus ARC compatibility
