---
phase: 29
slug: rename-inventory-and-compatibility-contract
status: in_progress
created: 2026-03-25
---

# Phase 29 Context

## Objective

Turn the ARC rename into an explicit compatibility program instead of an unsafe
repo-wide string replacement.

## Current Reality

- the project has adopted ARC as the planning identity, but the shipped repo
  still uses `ARC` and `arc-*` across crates, CLI, SDK packages, docs, and
  signed artifact names
- the rename blast radius includes repo metadata, package names, import paths,
  standards drafts, schema IDs, and the shipped `did:arc` portable-trust
  identity
- later phases depend on this phase to decide what renames, what aliases, what
  stays frozen, and what needs conversion support

## Constraints

- historical ARC artifacts must not become unverifiable
- the rename needs one migration matrix that operators and SDK consumers can
  actually follow
- this phase is documentation and contract first; broad code renames belong in
  later phases

## Strategy

- inventory the rename surfaces and classify each as rename, alias, freeze, or
  convert
- decide the identity and artifact compatibility model before Phase 30 touches
  repo/package names
- publish rollout order and migration guidance in operator-facing docs
