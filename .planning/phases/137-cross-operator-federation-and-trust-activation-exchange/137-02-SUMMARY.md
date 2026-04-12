# Summary 137-02

Bounded federated trust with explicit attenuation and import controls.

## Delivered

- added `FederationDelegationControl` and `FederationImportControl` in
  `crates/arc-core/src/federation.rs`
- enforced explicit local activation, manual review, stale-input rejection,
  and no ambient runtime admission in federation validation
- added regression coverage for fail-closed local policy import requirements

## Result

Federated trust remains operator-controlled. Remote activation can be shared
for review and visibility, but it cannot bypass local activation policy.
