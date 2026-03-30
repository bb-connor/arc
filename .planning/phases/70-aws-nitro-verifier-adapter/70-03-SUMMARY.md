# Summary 70-03

Added regression coverage and operator guidance for the AWS Nitro adapter.

## Delivered

- covered Nitro happy-path verification plus PCR mismatch, stale document,
  debug-mode, nonce mismatch, and malformed-COSE failures under test
- updated the workload-identity runbook with Nitro-specific trust and
  fail-closed behavior
- extended the protocol contract so AWS Nitro is now a documented concrete
  verifier family beside Azure MAA

## Notes

- the new tests prove Nitro trust failures are explicit and reproducible
  without widening ARC's normalization boundary
