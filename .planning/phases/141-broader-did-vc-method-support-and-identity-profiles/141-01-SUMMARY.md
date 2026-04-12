# Summary 141-01

Defined broader DID/VC method and credential-family support contracts.

## Delivered

- added `IdentityDidMethod`, `IdentityCredentialFamily`, and
  `IdentityProofFamily` in `crates/arc-core/src/identity_network.rs`
- required `did:arc` to remain present while any broader `did:web`, `did:key`,
  or `did:jwk` compatibility input stays explicit
- enforced native passport plus projected portable-family coverage instead of
  allowing arbitrary credential families

## Result

ARC can now name broader public identity compatibility inputs without erasing
ARC-owned provenance or trust semantics.
