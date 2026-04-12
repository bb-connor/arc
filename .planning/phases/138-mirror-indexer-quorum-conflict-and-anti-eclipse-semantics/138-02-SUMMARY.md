# Summary 138-02

Defined conflict and anti-eclipse controls for federated registry state.

## Delivered

- added `FederationConflictEvidence` and `FederationAntiEclipsePolicy` in
  `crates/arc-core/src/federation.rs`
- enforced distinct-operator coverage, origin presence, optional indexer
  observation, and upstream-hop limits in quorum validation
- modeled explicit converged, stale, conflicting, and insufficient-quorum
  final states

## Result

Conflicting or eclipse-prone publisher state remains visible as evidence but
cannot silently rewrite trust.
