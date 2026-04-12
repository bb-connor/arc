# Summary 106-01

Defined ARC's signed verifier-descriptor and trust-bundle artifacts in
`crates/arc-core/src/appraisal.rs`.

Implemented:

- `arc.runtime-attestation.verifier-descriptor.v1` as the portable verifier
  identity and signing-metadata contract
- `arc.runtime-attestation.trust-bundle.v1` as the signed versioned transport
  for verifier metadata
- explicit binding between portable verifier metadata and ARC's canonical
  appraisal artifact and result schemas

This keeps verifier identity portable without turning verifier publication into
local trust admission.
