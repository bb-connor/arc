---
id: "UR-U5"
title: "x402 authorize response fails closed when `settled` is absent"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/kernel/chio-kernel/src/payment.rs", "crates/kernel/chio-kernel/src/payment/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 3.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: U5 ("x402 fails open"). On #1160 head, `crates/kernel/chio-kernel/src/payment.rs` declares `struct X402AuthorizeResponse` (line 489) with `#[serde(default = "default_true")] settled: bool` (lines 496-497; `fn default_true` at line 958), so a rail response that omits `settled` is treated as settled and the payment journal moves to `Settled` (`let state = if response.settled` at line 273). Change the default to not settled (remove `default_true` if nothing else uses it), so an absent field leaves the journal in the pending/authorized state and settlement must be observed explicitly. Check the ACP path (`AcpAuthorizeResponse`, line 541) for the same pattern. Boundary: rail settlement outcomes are `detect_only`; this fix keeps the kernel from claiming settlement it did not observe.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- New tests in `crates/kernel/chio-kernel/src/payment.rs` tests module (or `payment/` tests): `x402_authorize_response_without_settled_is_not_settled`, `x402_authorize_response_settled_true_still_settles`, and an ACP counterpart if the pattern exists there.
- `cargo test -p chio-kernel payment` passes; `cargo clippy -p chio-kernel -- -D warnings` clean.
- `git grep -n default_true crates/kernel/chio-kernel/src/payment.rs` returns nothing (or only non-settlement uses, justified in the commit body).

## Log
- 2026-10-09T04:51:58Z connor: created
