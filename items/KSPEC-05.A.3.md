---
id: "KSPEC-05.A.3"
title: "Generation-seeded session event ids (KDEF-D4)"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-05.A.2"]
paths: ["crates/protocol/chio-mcp-remote/src/remote_mcp/session_core/factory.rs", "fuzz/fuzz_targets/parse_session_event_id.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-4 (KSPEC-05 Part A: KDEF-D3, D4, N26; N30 is already fixed on #1160), because doors serve over `chio mcp serve-http`. Spec: `docs/superpowers/specs/2026-10-04-unified-event-queue-design.md` (KSPEC-05). Note REL-2.2 added a stateless path in the same files; keep it working. `AtomicU64::new(0)` at `session_core/factory.rs:469,687`; ids are `{session_id}-{n}`. Seed from a generation so a restored session never reuses ids; add a fuzz target for `parse_session_event_id`. A small edit in `session_core/session.rs` is expected after A.2.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Restore twice then a stale cursor gets 409; seed-0 negative control fails as expected; fuzz target builds.

## Log
- 2026-10-09T04:51:58Z connor: created
