# Summary 58-02

Implemented Azure Attestation JWT verification and normalization into ARC's
runtime-attestation evidence model.

## Delivered

- JWT parsing, RSA signing-key resolution, and signature verification over
  Azure MAA-style tokens
- fail-closed normalization into `RuntimeAttestationEvidence` with schema
  `arc.runtime-attestation.azure-maa.jwt.v1`
- optional SPIFFE workload-identity projection from configured
  `x-ms-runtime.claims.*` paths using the phase-57 mapping rules

## Notes

- unsupported algorithms, invalid time windows, untrusted signing keys, and
  disallowed attestation types are rejected explicitly
- verifier-specific Azure claims are preserved under `claims.azureMaa` instead
  of being misrepresented as generic cross-verifier semantics
