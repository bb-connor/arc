# Summary 59-02

Bound trusted attestation evidence back into issuance and governed
runtime-assurance decisions.

## Delivered

- issuance resolves effective runtime-assurance tier through explicit
  trusted-verifier rules
- governed execution applies the same effective-tier resolver before approval
  and budget enforcement continue
- governed receipt metadata now records the accepted runtime-assurance tier
  after rebinding rather than only the raw upstream tier

## Notes

- Azure MAA evidence still normalizes to raw `attested`; it only becomes
  `verified` through explicit trusted-verifier policy
- stale, mismatched, or unsupported verifier evidence now fails closed
