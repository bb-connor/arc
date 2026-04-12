# Summary 137-01

Defined the federated trust-activation exchange contract.

## Delivered

- added `FederationArtifactReference`, `FederationTrustScope`, and
  `FederationActivationExchangeArtifact` plus validation in
  `crates/arc-core/src/federation.rs`
- exported the federation surface from `crates/arc-core/src/lib.rs`
- published `docs/standards/ARC_FEDERATION_ACTIVATION_EXCHANGE_EXAMPLE.json`

## Result

ARC can now express one cross-operator trust-activation exchange over explicit
listing, operator, and activation references instead of treating remote
visibility as local trust.
