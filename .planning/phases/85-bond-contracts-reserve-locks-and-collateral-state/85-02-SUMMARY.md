# Summary 85-02

Implemented durable bond issuance and lifecycle projection.

## Delivered

- added signed bond evaluation, issuance, and list surfaces to trust-control
  and the CLI
- persisted bond artifacts in SQLite with supersession-aware lifecycle
  handling and queryable summaries
- linked bond truth back to exposure and the latest active granted facility so
  collateral posture preserves provenance to canonical ARC evidence
