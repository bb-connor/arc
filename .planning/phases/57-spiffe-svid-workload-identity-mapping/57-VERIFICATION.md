# Phase 57 Verification

status: passed

## Result

Phase 57 is complete. ARC now standardizes one explicit SPIFFE/SVID-style
workload-identity mapping contract, binds that contract into issuance,
governed execution, receipt metadata, and policy-visible attestation context,
and fails closed when explicit and raw runtime identity facts conflict.

## Commands

- `cargo test -p arc-core workload_identity -- --nocapture`
- `cargo test -p arc-policy tool_access_workload_identity -- --nocapture`
- `cargo test -p arc-control-plane workload_identity_validation_denies_conflicting_attestation_without_policy -- --nocapture`
- `cargo test -p arc-kernel governed_request_denies_conflicting_workload_identity_binding -- --nocapture`
- `cargo test -p arc-kernel governed_monetary_allow_records_runtime_assurance_metadata -- --nocapture`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs init phase-op 57`
- `git diff --check`

## Notes

- ARC currently standardizes typed workload identity only for SPIFFE-derived
  inputs; non-SPIFFE `runtimeIdentity` remains opaque compatibility metadata
- explicit `workloadIdentity` must reconcile with raw `runtimeIdentity` when
  both are present, otherwise issuance and governed execution fail closed
