# Summary 103-01

Defined one signed external runtime-attestation appraisal-result contract over
the phase-101 artifact boundary instead of forcing foreign consumers to import
ARC-local appraisal reports directly.

Implemented:

- `RuntimeAttestationAppraisalResult` with explicit `resultId`, `exportedAt`,
  `issuer`, `subject`, nested appraisal artifact, and exporter-policy outcome
- deterministic content-derived result ids plus signer-verified signed export
  envelopes
- local and trust-control export surfaces for the signed result contract

This gives ARC one portable signed appraisal-result artifact with explicit
issuer, signer, subject, and verifier provenance.
