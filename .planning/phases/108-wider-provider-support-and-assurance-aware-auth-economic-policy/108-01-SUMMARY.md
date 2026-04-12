# Summary 108-01

Extended ARC's shared appraisal substrate to one additional bounded verifier
family in `crates/arc-core/src/appraisal.rs` and
`crates/arc-control-plane/src/attestation.rs`.

Implemented:

- `enterprise_verifier` as one explicit verifier family over
  `arc.runtime-attestation.enterprise-verifier.json.v1`
- normalized assertion mapping for attestation type, runtime or workload
  identity, module id, digest, PCRs, hardware model, and secure-boot posture
- one signed-envelope enterprise verifier adapter with trusted signer keys,
  schema binding, freshness checks, and tier ceiling enforcement
- qualification-backed provider inventory widened from Azure/AWS Nitro/Google
  to Azure/AWS Nitro/Google plus the bounded enterprise verifier bridge

This widens provider coverage without creating a second policy-specific truth
model outside ARC's shared appraisal contract.
