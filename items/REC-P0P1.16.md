---
id: "REC-P0P1.16"
title: "Recovery CLI and hand-written SDK protocol (Codex P2 fixes)"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.14"]
paths: ["crates/products/chio-cli/src/recovery*", "crates/products/chio-cli/src/recovery/**", "sdks/python/chio-sdk-python/src/chio_sdk/recovery_host.py", "sdks/typescript/packages/node-http/src/recovery*", "sdks/go/chio-go-http/recovery_wire_validation*.go"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. Fix the Codex P2s: `chio-cli/src/recovery.rs:381` accepts unvalidated 2xx responses; `recovery_host.py:72-74` sends a `pending` release down the `complete` path. Wiring edits in `cli/process_host/native_broker.rs` and `main.rs` are allowed; list them.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- CLI `tests/recovery*`, `python3 -m pytest sdks/python/chio-sdk-python/tests` and `go test ./sdks/go/chio-go-http/...` pass, including new tests for both P2s.

## Log
- 2026-10-09T04:51:58Z connor: created
