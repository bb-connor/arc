---
id: "COOP-1.0"
title: "Re-cut the HOST-M1 plan and NORTH-STAR-FLOWS server-first against #1160"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["DOCS-1177.2"]
paths: ["docs/superpowers/plans/2026-10-08-m1-cooperate-0.md", "docs/superpowers/specs/2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-1 ("HOST-M1, re-cut server-first"), G2 steps (passport, challenge, inbox, holder pickup, allow and deny at the door, offline verification against a pinned partner card). Plan source: #1177 `docs/superpowers/plans/2026-10-08-m1-cooperate-0.md` as re-cut by COOP-1.0. HOST-M1 never depends on #1179. Section 13 re-cut: remove "needs nothing from #1160" (plan Global Constraints line 23); point custody at `crates/platform/chio-control-plane/src/signing_custody.rs` (plan Task 2 would replace `load_existing_keypair` with `fs::read` and drop its file checks); handle the fallible `unix_timestamp_now() -> Result<u64, ClockError>` (`trust_control/underwriting_and_support/policy_support.rs:950`; Tasks 3 and 5 treat it as `u64`); fix drifted line refs (`handle_federated_issue` is now 1056-1501; `unix_from_rfc3339` is `passport_verifier.rs:1443`). Flow fixes: B owns the delegation ceiling (an A-signed ceiling is rejected today because the signer must be in B's `authority.trusted_public_keys()`); steps 3-4 go through the inbox without consuming the challenge on submit (today both `handle_public_verify_passport_challenge` and federated issue consume it); step 6 exports the door's receipt store; step 7 verifies with `--trust-anchor`; Task 6 reuses `deploy/reference-runtime/` instead of a new `packaging/` tree; Task 7 commands use #1160 flags (`--authority-seed-file`, `--kernel-seed-file`, `--trusted-kernel-pubkey`); the revoked-passport case moves to COOP-2.2/2.3 (cross-org revocation); desktop review moments become optional (COOP-1.12). Map each plan task to its COOP-1.x ID.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/check-native-host-docs.py --rule links --rule em-dash` passes; no stale line refs remain (grep for the old ranges returns nothing); every plan task names a COOP-1.x item.

## Log
- 2026-10-09T04:51:58Z connor: created
