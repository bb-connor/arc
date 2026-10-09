---
id: "SHARE-2.1"
title: "Model calls through the broker provider adapter with worst-case-then-reconcile holds"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-1.1"]
paths: ["crates/security/chio-secret-broker/src/kernel_admission.rs", "crates/security/chio-secret-broker/src/generic_https.rs", "crates/security/chio-secret-broker/src/model_spend.rs", "crates/security/chio-secret-broker/tests/model_spend.rs", "crates/protocol/chio-provider-adapter-core/src/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-2 ("model calls route through the broker's provider adapter, using the worst-case-then-reconcile lifecycle"); KERNEL unowned primitive "the model-relay spend dimension" (this item owns it). Before provider dispatch, reserve a hold for the worst case (input tokens plus a supported hard output ceiling times price, plus cache and fees where applicable), then reconcile to the actual usage reported by the provider; a missing bound refuses before credential release (see #1177 Omarchy plan item on model-provider resource boundaries). Use the existing hold API in `crates/kernel/chio-kernel/src/budget_store.rs`. Lost replies keep the reservation (no release, no redispatch). Boundary: `prevent` for kernel-mediated model calls.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `crates/security/chio-secret-broker/tests/model_spend.rs`: `model_call_reserves_worst_case_before_dispatch`, `model_call_reconciles_down_to_actual_usage`, `model_call_without_output_ceiling_refuses`, `lost_model_reply_keeps_reservation`.
- `cargo test -p chio-secret-broker model_spend` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
