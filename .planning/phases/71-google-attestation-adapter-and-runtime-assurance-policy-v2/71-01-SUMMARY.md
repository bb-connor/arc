# Summary 71-01

Defined ARC's first Google verifier-family boundary over the shared appraisal
contract.

## Delivered

- chose Google Confidential VM JWT evidence as ARC's first Google attestation
  family rather than inventing a vague generic `google` surface
- normalized only the small assertion set ARC can defend across families:
  `attestationType`, `hardwareModel`, `secureBoot`, and typed workload
  identity where present
- preserved the broader Google-specific claim surface under
  `claims.googleAttestation` instead of pretending vendor claims are globally
  equivalent

## Notes

- unsupported or weak Google evidence fails before ARC emits a trusted
  appraisal or widens effective runtime assurance
