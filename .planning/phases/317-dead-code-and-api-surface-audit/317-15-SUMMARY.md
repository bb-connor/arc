# Summary 317-15

Phase `317` then took the credit issuance helper cleanup wave across the
trust-control facility/bond issuance path.

The implemented refactor updated:

- `crates/arc-cli/src/trust_control/capital_and_liability.rs`
- `crates/arc-cli/src/trust_control/credit_and_loss.rs`
- `crates/arc-cli/src/trust_control/http_handlers_b.rs`
- `crates/arc-cli/src/cli/runtime.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave15 cargo check -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave15 cargo test -p arc-cli --test receipt_query test_credit_facility_report_issue_and_list_surfaces -- --exact`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave15 cargo test -p arc-cli --test receipt_query test_credit_bond_issue_and_list_surfaces -- --exact`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**' | wc -l`
- `git diff --check -- crates/arc-cli/src/trust_control/capital_and_liability.rs crates/arc-cli/src/trust_control/credit_and_loss.rs crates/arc-cli/src/trust_control/http_handlers_b.rs crates/arc-cli/src/cli/runtime.rs`

This wave removed three non-test `#[allow(clippy::too_many_arguments)]` sites:

- `issue_signed_credit_bond`
- `issue_signed_credit_bond_detailed`
- `issue_signed_credit_facility_detailed`

Those facility/bond issuance helpers now share one typed `CreditIssuanceArgs`
input struct across the public wrapper layer, the HTTP handlers, and the local
CLI fallback path.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `10`
- no remaining multi-site hotspot remains; every live suppression is now a
  singleton
