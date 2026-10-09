---
id: "SHARE-4.4"
title: "Move the x402 and ACP clients out of the kernel (KSPEC-01 R13)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-U5", "SHARE-4.2", "CT-ABI.1"]
paths: ["crates/kernel/chio-kernel/src/payment.rs", "crates/kernel/chio-kernel/src/payment/**", "crates/economy/chio-payment-rails/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-4 ("move the x402 and ACP clients out of the kernel (KSPEC-01 R13)"). `crates/kernel/chio-kernel/src/payment.rs` holds `X402PaymentAdapter` and `AcpPaymentAdapter` (HTTP clients) next to the `PaymentAdapter` trait and the payment journal. Keep the trait and journal in the kernel; move both rail clients into a new optional crate `crates/economy/chio-payment-rails` behind features, wired in by the control plane. Preserve the U5 fail-closed default.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `git grep -n "X402PaymentAdapter\|AcpPaymentAdapter" crates/kernel/chio-kernel/src` returns only re-export shims or nothing.
- Moved tests pass in the new crate (`cargo test -p chio-payment-rails`), including the U5 regression tests.
- `cargo tree -p chio-kernel` no longer pulls the rail HTTP client dependencies.

## Log
- 2026-10-09T04:51:58Z connor: created
