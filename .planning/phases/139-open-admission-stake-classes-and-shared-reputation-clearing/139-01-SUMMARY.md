# Summary 139-01

Defined federated open-admission policy and stake requirements.

## Delivered

- added `FederatedStakeRequirement` and
  `FederatedOpenAdmissionPolicyArtifact` in
  `crates/arc-core/src/federation.rs`
- required explicit bond class, bond amount, and slashable posture for
  `bond_backed` participation
- published `docs/standards/ARC_FEDERATION_OPEN_ADMISSION_POLICY_EXAMPLE.json`

## Result

Cross-operator admission is now machine-readable and bounded by explicit
review, governance, and slashable bond policy.
