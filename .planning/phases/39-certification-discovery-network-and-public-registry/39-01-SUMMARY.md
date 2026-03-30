---
phase: 39-certification-discovery-network-and-public-registry
plan: 01
subsystem: certification-discovery-contract
tags:
  - certification
  - discovery
  - protocol
requires: []
provides:
  - A typed certification discovery-network file format for explicit remote operators
  - Public read-only certification discovery semantics that preserve operator provenance
  - Protocol and standards text aligned with multi-operator certification discovery
key-files:
  modified:
    - crates/arc-cli/src/enterprise_federation.rs
    - spec/PROTOCOL.md
    - docs/standards/ARC_PORTABLE_TRUST_PROFILE.md
requirements-completed:
  - TRUST-03
completed: 2026-03-26
---

# Phase 39 Plan 01 Summary

Phase 39-01 defined the certification discovery contract instead of leaving
multi-operator lookup as an undocumented convention.

## Accomplishments

- added a file-backed `arc.certify.discovery-network.v1` contract for explicit
  remote certification operators
- validated operator records with normalized registry URLs, publish controls,
  and configuration-visible validation errors
- updated the protocol and portable-trust profile so certification discovery is
  modeled as operator-scoped truth rather than a global mutable registry
- documented public read-only certification resolution as the supported
  discovery primitive

## Verification

- `cargo test -p arc-cli certification_discovery_network`

