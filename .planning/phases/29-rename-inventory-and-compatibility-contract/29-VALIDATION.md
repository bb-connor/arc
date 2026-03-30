---
phase: 29
slug: rename-inventory-and-compatibility-contract
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 29 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | documentation verification via `rg` and roadmap parser checks |
| **Quick run command** | `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze` |
| **Inventory command** | `rg -n "rename|alias|freeze|convert|did:arc|@arc-protocol|arc-cli|arc-" .planning/research/ARC_RENAME_INVENTORY.md` |
| **Identity contract command** | `rg -n "did:arc|did:arc|legacy compatibility|dual" docs/standards/ARC_IDENTITY_TRANSITION.md docs/DID_ARC_METHOD.md` |
| **Migration guide command** | `rg -n "rollout order|Rust crates|CLI|TypeScript SDK|Python SDK|Go SDK|environment variables|compatibility window" docs/release/ARC_RENAME_MIGRATION.md` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 29-01 | ARC-04 | `rg -n "rename|alias|freeze|convert|did:arc|@arc-protocol|arc-cli|arc-" .planning/research/ARC_RENAME_INVENTORY.md` |
| 29-02 | ARC-05, ARC-06 | `rg -n "did:arc|did:arc|legacy compatibility|dual" docs/standards/ARC_IDENTITY_TRANSITION.md docs/DID_ARC_METHOD.md` |
| 29-03 | ARC-07, ARC-08 | `rg -n "rollout order|Rust crates|CLI|TypeScript SDK|Python SDK|Go SDK|environment variables|compatibility window" docs/release/ARC_RENAME_MIGRATION.md` |

## Coverage Notes

- this phase is intentionally contract-heavy rather than implementation-heavy;
  it makes the rename survivable before Phase 30 starts moving packages and
  binaries
- the inventory and migration docs are treated as inputs to later execution,
  not marketing-only prose
- the phase closes only after the roadmap parser sees the phase artifacts and
  the docs exist on disk

## Sign-Off

- [x] the rename blast radius is inventoried and classified
- [x] `did:arc` compatibility policy is documented
- [x] migration order exists for operators and SDK consumers
- [x] Phase 30 can start from a written contract instead of rediscovery

**Approval:** completed
