---
id: "SHARE-3.1"
title: "One root grant across Claude Code and Codex on one Linux host"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["SHARE-1.2", "REL-3.2", "REL-3.3"]
paths: ["crates/products/chio-cli/src/cli/process_host/serving.rs", "crates/products/chio-cli/src/cli/process_host/state.rs", "crates/products/chio-cli/tests/process_host/root_grant_shared.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-3 ("one root grant across the harnesses outside teams run: Claude Code and Codex first"), G3 ("one root grant across Claude Code and Codex on one Linux host"), D12 recommendation. The process host (`crates/products/chio-cli/src/cli/process_host/`, serving path in `serving.rs`) must admit sessions from both launchers (REL-3.2, REL-3.3) under one root grant whose family hold (SHARE-1.2) bounds both. Boundary: `prevent` for kernel-mediated calls; native effects outside the kernel path are `cannot_see` unless a qualified KSPEC-07 backend confines them.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `crates/products/chio-cli/tests/process_host/root_grant_shared.rs` (Linux, `real-linux-enforcement` feature): both harness launchers draw from one family hold; exhausting it from one denies the other.
- `cargo test -p chio-cli --features real-linux-enforcement root_grant_shared` passes on a Linux runner.

## Log
- 2026-10-09T04:51:58Z connor: created
