---
phase: 39
slug: certification-discovery-network-and-public-registry
status: passed
completed: 2026-03-26
---

# Phase 39 Verification

Phase 39 passed targeted verification for multi-operator certification
discovery and network-aware publication in `v2.7`.

## Automated Verification

- `cargo test -p arc-cli certification_discovery_network`
- `cargo test -p arc-cli --test certify`

## Result

Passed. Phase 39 now satisfies `TRUST-03`:

- certification state can be discovered across multiple explicit operators
  without merging them into one synthetic global registry
- trust-control exposes public read-only discovery and authenticated
  publish/discover aggregation endpoints
- CLI can fan out one signed artifact to multiple operators through the
  discovery network contract
- docs and protocol text now describe certification discovery as operator-scoped
  portable trust, not a marketplace or implicit trust root
