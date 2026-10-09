---
id: "REL-1.SALVAGE-1155"
title: "Salvage #1155: process preview install path and portable projects"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-U10", "UR-LEDGER-CARRY"]
paths: ["crates/products/chio-cli/src/cli/mcp/provision.rs", "crates/products/chio-cli/src/cli/process_host/diagnostics.rs", "crates/products/chio-cli/src/cli/process_host/output.rs", "crates/products/chio-cli/src/cli/process_host/paths.rs", "crates/products/chio-cli/src/cli/process_host/provision.rs", "crates/products/chio-cli/src/cli/process_host/runner/portable.rs", "crates/products/chio-cli/src/cli/process_host/runner/mod.rs", "sdks/python/chio-mini-swe/src/chio_mini_swe/**", "sdks/python/chio-mini-swe/tests/test_runtime_profile.py", "sdks/python/chio-mini-swe/tests/test_session.py", "sdks/python/chio-process/src/chio_process/invocation.py", "sdks/typescript/packages/process/package.json", "docs/install/PROCESS_PREVIEW.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7 (#1155: salvage into REL-1 as the preview install path). Source: PR #1155 (ref `origin/codex/process-preview-entrypoint-20260908`, draft, base #1160). Its docs commit already landed in #1160 as `docs/install/PROCESS_PREVIEW.md`; the unique remainder is commit `bef5a98e6` ("support portable projects and installed coding sessions (#1169)"): portable projects, an installed-session `process_json_output` with no TTY, and `mcp/provision.rs` hardening. `paths.rs`, `output.rs` and `runner/portable.rs` are absent on #1160. Rebase that commit onto post-#1160 main (small wiring edits in `cli/dispatch/mod.rs`, `cli/mcp.rs`, `cli/process_host.rs`, `cli/process_host/state.rs` and `cli/types.rs` are allowed; list them) and rewrite `PROCESS_PREVIEW.md` to install from the tagged preview archive instead of commit `d99e03027c` and PR #1154. Sequence after SEC-POSTMERGE.4 if both touch `chio-mini-swe`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli process_host`; `cargo test -p chio-cli mcp::provision`; `python3 -m pytest sdks/python/chio-mini-swe/tests/test_runtime_profile.py sdks/python/chio-mini-swe/tests/test_session.py` pass.
- `python3 scripts/qualify-process-packages.py --chio target/debug/chio --output <tmpdir>` succeeds.

## Log
- 2026-10-09T04:51:58Z connor: created
