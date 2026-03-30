# Phase 31 Context

## Phase

- **Number:** 31
- **Name:** Protocol, Artifact, and Identity Migration
- **Milestone:** v2.5 ARC Rename and Identity Realignment

## Goal

Resolve the rename surfaces where external semantics matter: schema families,
artifact version markers, env/config compatibility, and the `did:arc` to
`did:arc` transition boundary.

## Why This Phase Exists

Phase 30 made ARC the primary package, CLI, and SDK identity. That was the
safe package/tooling layer. The remaining rename debt is harder because it can
break verifiability or operator compatibility if handled as a blind
search/replace.

## Inputs

- `.planning/research/ARC_RENAME_INVENTORY.md`
- `docs/standards/ARC_IDENTITY_TRANSITION.md`
- `docs/release/ARC_RENAME_MIGRATION.md`
- `spec/PROTOCOL.md`
- current schema and identifier usage across `crates/`, `packages/`, and
  release/operator docs

## Locked Decisions

- `did:arc` remains valid indefinitely for historical artifacts
- ARC may introduce `arc.*` artifact identifiers, but validators/importers must
  keep accepting legacy `arc.*`
- neutral `/v1/...` HTTP routes stay frozen unless branding is embedded in
  payloads or examples
- environment/config names should move to ARC-first aliases without breaking
  one-cycle compatibility

## Risks

- signed artifact families are already used across receipts, checkpoints,
  passports, verifier policies, certifications, and evidence exports
- protocol markers are repeated across Rust, TS, Python, Go, dashboards, and
  docs, so partial migration creates drift quickly
- `did:arc` cannot be claimed as shipped until resolver and issuance flows are
  genuinely dual-stack or ARC-native
