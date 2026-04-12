# Summary 104-01

Qualified ARC's signed appraisal-result boundary across the shipped verifier
families instead of relying on one single-provider export/import proof.

Implemented:

- mixed-provider appraisal-result qualification over Azure MAA, AWS Nitro, and
  Google Confidential VM in `crates/arc-cli/tests/receipt_query.rs`
- explicit fail-closed import coverage for stale results, stale evidence,
  unsupported verifier-family policy, and contradictory portable claims
- direct core regression coverage for stale result/evidence and schema/family
  mismatch in `crates/arc-core/src/appraisal.rs`

This gives ARC one reproducible qualification matrix for the current portable
appraisal-result contract.
