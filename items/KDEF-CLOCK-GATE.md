---
id: "KDEF-CLOCK-GATE"
title: "Clock rebase gates for KDEF-N1 (#1173) and KDEF-N15 (#1179)"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["scripts/check-security-clocks.py", "scripts/tests/check-security-clocks.test.py", "scripts/security-clock-inventory.json"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-6 ("KDEF-N1 and N15 become rebase gates, at the #1173 and #1179 merges respectively"). #1160's `scripts/check-security-clocks.py` already runs in CI job `check` (`.github/workflows/ci.yml:200`) over `crates/kernel/` and `crates/platform/chio-control-plane/`. Add a frozen-zero list: `crates/kernel/chio-process/src/worker.rs` (N1; #1173 carries a stale copy calling `SystemTime::now()` at line 330 where #1160 uses `authority_clock` at 185) and the nine #1179 control-plane sites (`confinement.rs`, `knowledge.rs`, `semantic.rs`, `recovery/maintenance.rs`, `recovery/materialize.rs`, `recovery/runtime/native_work.rs`, `recovery/setup.rs`, `recovery/transport/authentication.rs`) may never gain inventory entries. Any WORK slice carrying the stale `worker.rs` or any REC slice keeping those sites then fails a required check.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Fixtures that revert `worker.rs:185` to `SystemTime::now()` or add a wall-clock read in `chio-control-plane/src/confinement.rs` both fail `python3 scripts/check-security-clocks.py`; `python3 scripts/tests/check-security-clocks.test.py` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
