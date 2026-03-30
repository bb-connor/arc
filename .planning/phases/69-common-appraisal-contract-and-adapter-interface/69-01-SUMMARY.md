# Summary 69-01

Defined ARC's canonical runtime-attestation appraisal contract.

## Delivered

- added typed appraisal artifacts in `arc-core` with explicit evidence
  identity, verifier family, verdict, reason codes, normalized assertions, and
  vendor claims
- kept normalized assertions intentionally narrow so cross-vendor comparison
  stays conservative
- made rejected appraisals explicit rather than overloading evidence-only
  fields

## Notes

- the appraisal contract is the adapter boundary; it does not claim vendor
  claim vocabularies are globally equivalent
