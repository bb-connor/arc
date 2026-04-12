# Summary 101-01

Defined one outward-facing runtime-attestation appraisal artifact over the
existing ARC appraisal truth instead of leaving verifier outputs as adapter-
specific shapes.

Implemented:

- `RuntimeAttestationAppraisalArtifact` with explicit nested `evidence`,
  `verifier`, `claims`, and `policy` sections
- dedicated schema identifiers for the artifact itself and for the portable
  provider-inventory document
- compatibility-preserving attachment of the new artifact to
  `RuntimeAttestationAppraisal` without dropping the existing flat fields yet

This keeps raw evidence identity, verifier provenance, normalized claims, and
local policy conclusions visibly separate and auditable.
