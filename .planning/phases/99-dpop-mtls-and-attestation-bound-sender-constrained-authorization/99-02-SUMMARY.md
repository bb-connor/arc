# Summary 99-02

Added mTLS thumbprint binding and one explicitly bounded attestation-bound
sender profile over the same hosted authorization flow.

Implemented:

- request-time mTLS thumbprint input through
  `arc_sender_mtls_thumbprint_sha256`
- request-time attestation digest input through
  `arc_sender_attestation_sha256`
- token `cnf["x5t#S256"]` and `cnf.arcAttestationSha256` projection
- runtime header validation over `x-arc-mtls-thumbprint-sha256` and
  `x-arc-runtime-attestation-sha256`

The attestation-bound profile stays narrow by construction: the attestation
digest must match `arc_transaction_context.runtimeAssuranceEvidenceSha256`,
and ARC only accepts it when paired with DPoP or mTLS. Attestation alone does
not authorize a sender.
