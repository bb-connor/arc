# Phase 78: Public Operator Identity and Discovery Metadata - Context

## Goal

Publish operator identity and discovery metadata for the public certification
surface without turning discovery into a runtime trust oracle.

## Why This Phase Exists

Public discovery requires clear publisher identity, transport metadata, and
resolution rules. ARC already has operator-scoped discovery; this phase widens
that into a public-facing metadata model while preserving admission-policy
control.

## Scope

- public operator identity model for certification publishers
- discovery metadata and resolution artifacts
- provenance and rotation semantics for public publication
- fail-closed handling for stale or mismatched discovery metadata

## Out of Scope

- public search and transparency network
- governance or dispute flows
- automatic runtime trust from discovered listings
