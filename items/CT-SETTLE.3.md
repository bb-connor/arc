---
id: "CT-SETTLE.3"
title: "One signer-rotation rule for finalization, release and waiver (D2)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-SETTLE.2", "CT-COOP.1"]
paths: ["spec/vectors/settle/v1/signer-rotation.json", "spec/SETTLEMENT_COMPOSITION.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: CT-SETTLE ("one signer-rotation rule applies to finalization, release completion and waiver completion"), D2 (recommended: sign with the current key and bind the original identity; parked UR-D2). Today: #1160 quarantines (`crates/kernel/chio-kernel/src/kernel/signing_authority.rs:59-77`, defers until the original signer returns), #1179 re-signs and binds `original_signing_identity` in `PrivateRecoverySettlementReceiptV1` but only with disposition `permanently_withheld` (`terminal/historical_signing.rs:10-90`), #1173 refuses (`payment/unknown_release.rs:499,562`). Freeze the recommended rule in the rotation section of `spec/SETTLEMENT_COMPOSITION.md` (small edit after CT-SETTLE.1 has merged) and decide in the contract whether a rotated finalization may deliver output or only withhold (a new question surfaced by #1179; list it for the owner with D2). Key history comes from the CT-COOP partner card format. Declare harness case `rotated_signer_finalizes_with_original_identity_bound` pending until REC-P0P1.8 implements it.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Vectors validate; the pending harness case is declared and counted by CT-SETTLE.2's harness.

## Log
- 2026-10-09T04:51:58Z connor: created
