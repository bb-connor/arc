---
phase: 30
slug: workspace-sdk-cli-and-repo-surface-rename
status: in_progress
created: 2026-03-25
---

# Phase 30 Context

## Objective

Rename the visible developer and operator surfaces from PACT to ARC across the
workspace, SDK metadata, CLI binaries, and repo/package metadata while keeping
the repo mechanically stable.

## Current Reality

- Phase 29 decided the compatibility contract and rollout order
- Cargo package names still use `arc-*`, the primary CLI binary is still
  `arc`, and SDK package metadata still presents ARC as the product name
- internal Rust dependency keys can stay stable if package names change and
  Cargo `package = "arc-*"` aliasing is used where needed

## Constraints

- this phase should avoid protocol/schema identity churn; that belongs in Phase
  31
- qualification scripts and local developer flows cannot be left broken midway
- docs can stay partially ARC-branded until Phase 32, but package metadata and
  primary binary/package identity should move to ARC

## Strategy

- rename package metadata first, not directory layout
- keep internal Rust dependency keys stable with Cargo package aliasing where
  that lowers churn
- make `arc` the primary CLI binary while preserving `arc` as a compatibility
  alias for one cycle
- move SDK distribution/package metadata to ARC-first names before rewriting
  narrative docs
