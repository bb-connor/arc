# Summary 72-01

Defined and implemented ARC's signed runtime-attestation appraisal export
surface.

## Delivered

- added one signed appraisal-report artifact over the canonical appraisal
  contract instead of inventing a second verifier-specific export shape
- exposed that artifact through both `arc trust appraisal export` and
  `POST /v1/reports/runtime-attestation-appraisal`
- carried one explicit policy-visible accept or reject outcome beside the
  appraisal body so exported trust posture stays auditable

## Notes

- the export surface is intentionally operator-facing and conservative; it
  does not claim generic attestation-result interoperability beyond ARC's
  documented appraisal contract
