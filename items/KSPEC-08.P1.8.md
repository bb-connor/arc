---
id: "KSPEC-08.P1.8"
title: "Process-host control socket and `chio stop|restrict|relax|resume|status --scope kernel`"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-08.P1.7", "CT-ABI.3"]
paths: ["crates/products/chio-cli/src/cli/process_host/control_socket.rs", "crates/products/chio-cli/src/cli/stop.rs", "crates/products/chio-cli/src/cli/dispatch/stop.rs", "crates/products/chio-cli/src/cli/types.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-1 (KSPEC-08 phase 1: KDEF-D2, N22, N23; durable restart-safe stop with an allocated schema slot; reachable from the process-host socket and the CLI). Spec: `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md` (rule numbers S1 to S38 below refer to it). 
Rule S30. There is no control socket today (`chio.process.v1` workers have six ops and no administrative op; `process_host/runner/socket.rs` is the runner endpoint). Add a Unix socket in the runtime directory with an `SO_PEERCRED` owning-uid check (precedent `crates/security/chio-cage-init/src/descriptors.rs:117`) plus the control credential; the CLI drives either the routes or the socket. Additive control DTOs (and `withheld` on `invoke`) must already be in process ABI v4 (CT-ABI). Wire the socket into `process_host/serving.rs` with minimal lines (that file is leased by SHARE items later; list the edit). `cli/types.rs` (`Commands` enum, line 535) is a shared serialization point with other CLI items.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Conformance case "operator stop through the process-host socket" passes; wrong uid and wrong token are both refused.
- `cargo test -p chio-cli stop` passes on Linux.

## Log
- 2026-10-09T04:51:58Z connor: created
