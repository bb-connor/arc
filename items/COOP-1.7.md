---
id: "COOP-1.7"
title: "`chio evidence verify|import --trust-anchor <partner card>`"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-COOP.3", "COOP-1.6"]
paths: ["crates/products/chio-cli/src/cli/types/receipt.rs", "crates/platform/chio-control-plane/src/evidence_export.rs", "crates/platform/chio-control-plane/src/evidence_export/verification.rs", "crates/products/chio-cli/tests/evidence_export/package_trust.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-1 ("HOST-M1, re-cut server-first"), G2 steps (passport, challenge, inbox, holder pickup, allow and deny at the door, offline verification against a pinned partner card). Plan source: #1177 `docs/superpowers/plans/2026-10-08-m1-cooperate-0.md` as re-cut by COOP-1.0. HOST-M1 never depends on #1179. Roadmap COOP-1 (`evidence verify --trust-anchor <partner card>`); the roadmap's "pins no trust anchor" is true on main but stale after #1160, which requires `--trusted-kernel-pubkey` and accepts `--trusted-anchor-file` (`types/receipt.rs:239-262`). The missing piece is anchoring to a partner card: resolve authority key history plus receipt-signer windows plus optional anchor binding; reject receipts signed outside a key's window. Output carries the claim label from COOP-4.3. Boundary: `detect_only` (G2 claim: A verifies B's receipts offline against operator-pinned partner keys, no external witness).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `package_cli_trust_anchor_accepts_rotated_history` and `package_cli_trust_anchor_rejects_out_of_window_signer` pass alongside the existing `package_cli_pins_signer_and_rejects_omission_with_rewritten_manifest`.

## Log
- 2026-10-09T04:51:58Z connor: created
