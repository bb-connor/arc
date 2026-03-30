# Summary 71-02

Implemented runtime-assurance policy v2 over canonical appraisals rather than
single-provider claim matching.

## Delivered

- evolved trusted-verifier rules to support explicit `verifier_family` and
  `required_assertions` matching over normalized appraisal output
- kept stale, mismatched, or unsupported evidence fail-closed while preserving
  explainable denial reasons through the existing trust-policy path
- completed the second additional verifier path beyond Azure, satisfying the
  multi-cloud requirement with AWS Nitro plus Google Confidential VM

## Notes

- raw verifier output remains conservative at `attested`; stronger effective
  tiers still require explicit operator policy
