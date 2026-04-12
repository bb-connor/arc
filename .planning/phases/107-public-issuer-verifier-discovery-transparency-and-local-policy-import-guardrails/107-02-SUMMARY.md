# Summary 107-02

Defined ARC's public discovery transparency and freshness semantics in
`crates/arc-credentials/src/discovery.rs` and
`crates/arc-cli/src/trust_control.rs`.

Implemented:

- `arc.public-discovery-transparency.v1` as one signed transparency snapshot
  over the current issuer and verifier discovery documents
- explicit `published_at` and `expires_at` freshness windows on every
  discovery object
- per-entry hashes and provenance so operators can detect stale or divergent
  public discovery views
- fail-closed handling for duplicate, contradictory, or stale discovery
  entries

This makes public discovery auditable without implying local trust activation.
