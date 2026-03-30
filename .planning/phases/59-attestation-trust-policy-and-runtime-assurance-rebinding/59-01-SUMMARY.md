# Summary 59-01

Defined one explicit attestation trust-policy surface for ARC runtime
assurance.

## Delivered

- HushSpec `extensions.runtime_assurance.trusted_verifiers`
- core `AttestationTrustPolicy` and `AttestationTrustRule` types
- fail-closed validation for empty verifier/schema fields, invalid evidence-age
  values, and duplicate schema or verifier bindings

## Notes

- verifier trust is now operator policy, not an implicit property of a
  normalized attestation payload
- when trusted verifier rules exist, unmatched verifier evidence is untrusted
  and denied
