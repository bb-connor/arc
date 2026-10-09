---
id: "REL-1.SALVAGE-1046"
title: "Salvage #1046: MCP last-page cursor, workspace dependency versions, path_allowlist roots"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-LEDGER-CARRY"]
paths: ["crates/protocol/chio-mcp-edge/src/runtime/requests.rs", "crates/protocol/chio-mcp-edge/src/runtime/tasks.rs", "crates/protocol/chio-mcp-edge/src/runtime/protocol/serialization.rs", "crates/protocol/chio-mcp-edge/src/runtime/runtime_tests.rs", "Cargo.toml", "crates/guards/chio-guards/src/path_allowlist.rs", "crates/guards/chio-guards/tests/integration.rs", "scripts/check-workspace-dependency-versions.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7 (#1046: salvage into REL-1; its workspace dependency versions make `cargo package` work). Source: PR #1046 (ref `origin/fix/docs-release-gate`). Re-reproduce each defect on post-#1160 main and port only what still reproduces:
(a) `nextCursor: null` is still emitted on the last page (`protocol/serialization.rs:65` `unwrap_or(Value::Null)`, `requests.rs:327`, `tasks.rs:297`; `runtime_tests.rs:1990,2014` assert null). SDK clients reject it on the README quickstart path, so this blocks G1. Omit the field on the last page.
(b) Only 50 of 140 `chio-*` workspace path dependencies carry `version`; add it to the other 90 and a CI check that each equals `workspace.package.version`.
(c) path_allowlist: carry P1 ledger row `inherited-thread:r3695800374` ("Preserve an explicitly empty root boundary"). Do NOT adopt #1046's empty-means-unconstrained filter (fails open against #1160's `session_roots_fail_closed_when_root_set_is_empty`). Distinguish never negotiated (`None`) from negotiated empty and withdrawn-pending-refresh (`Some(&[])`, which keeps denying).
The version-negotiation half (`runtime.rs`, `jsonrpc.rs`) and P2 row `r3695800375` (`spec/versions/chio-protocol-negotiation.v1.json`, `spec/WIRE_PROTOCOL.md:271-285`) go to REL-2.1.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-mcp-edge tools_list_last_page_omits_next_cursor`.
- `cargo test -p chio-guards path_allowlist` keeps the fail-closed test and adds `negotiated_empty_roots_deny` and `unnegotiated_session_reaches_allowlist`.
- `cargo package --list -p chio-cli` succeeds; `python3 scripts/check-workspace-dependency-versions.py` passes; the CLAUDE.md one-liner passes.

## Log
- 2026-10-09T04:51:58Z connor: created
