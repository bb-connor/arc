---
id: "SHARE-2.2"
title: "Token quota dimension for subscription harnesses"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-2.1"]
paths: ["crates/core/chio-core-types/src/capability/token_quota.rs", "crates/security/chio-secret-broker/src/token_quota.rs", "crates/security/chio-secret-broker/tests/token_quota.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-2 ("add a token quota for subscription harnesses"). Subscription harnesses have no per-call price, so money holds cannot bound them. Add a token-count quota dimension to grants that the broker reserves and reconciles exactly like spend (SHARE-2.1), held in the kernel hold ledger. Wire-visible additions must be listed against CT-WIRE (append-only fields; do not change frozen bytes).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Tests: quota exhaustion denies the next model call; reconcile releases unused tokens; restart does not replenish.
- `cargo test -p chio-core-types token_quota` and `cargo test -p chio-secret-broker token_quota` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
