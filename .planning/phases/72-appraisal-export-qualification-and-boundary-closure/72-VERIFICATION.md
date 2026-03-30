# Phase 72 Verification

status: passed

## Result

Phase 72 is complete. ARC now emits one signed runtime-attestation appraisal
report over the canonical appraisal contract, qualifies the Azure/AWS/Google
verifier boundary, and closes `v2.15` with truthful protocol, runbook,
release, and partner-facing documentation.

## Commands

- `cargo fmt --all`
- `cargo test -p arc-core appraisal -- --nocapture`
- `cargo test -p arc-core runtime_attestation_trust_policy -- --nocapture`
- `cargo test -p arc-policy runtime_assurance_validation -- --nocapture`
- `cargo test -p arc-control-plane azure_maa -- --nocapture`
- `cargo test -p arc-control-plane aws_nitro -- --nocapture`
- `cargo test -p arc-control-plane google_confidential_vm -- --nocapture`
- `cargo test -p arc-control-plane runtime_assurance_policy -- --nocapture`
- `cargo test -p arc-kernel governed_request_denies_untrusted_attestation_when_trust_policy_is_configured -- --nocapture`
- `cargo test -p arc-kernel governed_monetary_allow_rebinds_trusted_attestation_to_verified -- --nocapture`
- `cargo test -p arc-kernel governed_monetary_allow_rebinds_google_attestation_to_verified -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_runtime_attestation_appraisal_export_surfaces -- --exact --nocapture`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs init phase-op 72`
- `git diff --check`

## Notes

- the signed appraisal report is an operator-facing export artifact over ARC's
  canonical appraisal contract, not a claim of generic attestation-results
  federation
- milestone closeout advances planning into `v2.16`; enterprise IAM work is
  the next executable ladder
