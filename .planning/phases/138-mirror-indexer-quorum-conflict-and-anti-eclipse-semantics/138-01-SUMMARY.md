# Summary 138-01

Defined mirror, indexer, and quorum observation artifacts for federation.

## Delivered

- added `FederationPublisherObservation` and `FederationQuorumReport` in
  `crates/arc-core/src/federation.rs`
- bound federated quorum state back to existing origin, mirror, and indexer
  publisher roles from the generic registry
- published `docs/standards/ARC_FEDERATION_QUORUM_REPORT_EXAMPLE.json`

## Result

Federated visibility is now machine-reviewable through one explicit quorum
artifact instead of ad hoc operator interpretation.
