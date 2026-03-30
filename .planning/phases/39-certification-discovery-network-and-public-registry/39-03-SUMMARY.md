---
phase: 39-certification-discovery-network-and-public-registry
plan: 03
subsystem: certification-discovery-docs-and-regressions
tags:
  - certification
  - docs
  - tests
requires:
  - 39-01
  - 39-02
provides:
  - Operator docs for network publication and discovery
  - Federation guidance that places discovery on an explicit operator boundary
  - Regression coverage for multi-operator public discovery and remote fan-out
key-files:
  modified:
    - docs/ARC_CERTIFY_GUIDE.md
    - docs/IDENTITY_FEDERATION_GUIDE.md
    - crates/arc-cli/tests/certify.rs
requirements-completed:
  - TRUST-03
completed: 2026-03-26
---

# Phase 39 Plan 03 Summary

Phase 39-03 documented the discovery-network model and proved it with
multi-operator regressions.

## Accomplishments

- updated the certify guide with discovery-network configuration, public
  discovery endpoints, and publish-network usage
- updated the identity-federation guidance so certification discovery is
  presented as another explicit operator-owned portable-trust surface
- added integration coverage for per-operator public discovery state and
  trust-control-backed publish/discover fan-out flows

## Verification

- `cargo test -p arc-cli --test certify`

