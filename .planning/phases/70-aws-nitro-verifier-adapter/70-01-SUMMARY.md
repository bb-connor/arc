# Summary 70-01

Defined ARC's AWS Nitro evidence mapping into the canonical appraisal contract.

## Delivered

- treated AWS Nitro attestation documents as bounded `COSE_Sign1` evidence
  carrying `module_id`, timestamp, `SHA384` PCR measurements, signing
  certificate material, and optional `public_key`, `user_data`, and `nonce`
- normalized only the small cross-family assertion set ARC can defend for
  Nitro: `moduleId`, `digest`, and PCR measurements
- kept the full Nitro-specific surface vendor-scoped under `claims.awsNitro`
  instead of pretending Nitro and other verifier families expose equivalent
  claim vocabularies

## Notes

- unsupported digests, malformed COSE structures, and missing required Nitro
  fields fail closed before ARC emits an appraisal
