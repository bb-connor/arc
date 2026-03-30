---
phase: 39-certification-discovery-network-and-public-registry
plan: 02
subsystem: certification-network-publication-and-query
tags:
  - certification
  - trust-control
  - discovery
requires:
  - 39-01
provides:
  - CLI discovery across multiple certification operators
  - Network fan-out publication to selected remote certification registries
  - Trust-control public and authenticated discovery endpoints
key-files:
  modified:
    - crates/arc-cli/src/certify.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/enterprise_federation.rs
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/tests/certify.rs
requirements-completed:
  - TRUST-03
completed: 2026-03-26
---

# Phase 39 Plan 02 Summary

Phase 39-02 implemented real multi-operator certification publication and
discovery without collapsing operator ownership.

## Accomplishments

- added `certify registry discover` for local or trust-control-backed
  per-operator certification discovery
- added `certify registry publish-network` to fan out one signed artifact to
  selected remote operators that explicitly allow publication
- added public trust-control resolve endpoints plus authenticated trust-control
  aggregation endpoints for discovery and publish fan-out
- exposed certification-discovery health metadata so operators can see whether
  a discovery network is configured and valid

## Verification

- `cargo test -p arc-cli --test certify`

