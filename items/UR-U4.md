---
id: "UR-U4"
title: "Constant-time emergency admin token compare and AC6 stop-scope document"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/platform/chio-http-core/src/emergency.rs", "crates/platform/chio-http-core/Cargo.toml", "crates/platform/chio-http-core/tests/emergency_endpoints.rs", "crates/kernel/chio-kernel/tests/loom_concurrency.rs", "docs/security/emergency-stop-scope.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: U4 (KDEF-N23 plus the AC6 stop-scope document), KSPEC-08 phase 0. Correction: the roadmap cites `crates/kernel/chio-kernel/src/kernel/emergency.rs`, which does not exist on main or #1160. The comparison is `Some(token) if token == self.expected_admin_token` at `crates/platform/chio-http-core/src/emergency.rs:193` on #1160 (line 189 on main), and the doc comment at 170-172 says it uses `==`. Replace it with `subtle::ConstantTimeEq` (workspace already has `subtle = "2"`, `Cargo.toml:413`), following `crates/products/chio-api-protect/src/proxy/control.rs:173` and its test `sidecar_control_bearer_token_compare_is_constant_time_safe`. Write `docs/security/emergency-stop-scope.md` (AC6): the stop is in-process, a restart resumes, the host latch is separate, and the claim limit is "no restart-durable or operator-reachable stop" until KSPEC-08 phase 1 lands. The AC6 clock test `clock_failure_during_emergency_stop_cannot_resume_execution` and Loom harness `loom_emergency_stop_arcswap` already exist; extend the Loom harness to cover "publish latch, then read time" (KSPEC-08 section 16 step 0). Do not edit `docs/security/landing-ledger.json` (the AC6 and EV11 rows are updated by the ledger owner).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- New test `emergency_admin_token_compare_is_constant_time_safe` (equal, prefix, one-byte-off tokens) in `crates/platform/chio-http-core/tests/emergency_endpoints.rs`; `cargo test -p chio-http-core --test emergency_endpoints` passes.
- Loom harness passes under `RUSTFLAGS="--cfg loom"`; `cargo clippy -p chio-http-core -- -D warnings` clean.

## Log
- 2026-10-09T04:51:58Z connor: created
