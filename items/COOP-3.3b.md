---
id: "COOP-3.3b"
title: "mTLS server option pinned to partner-card SPKIs"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-CROSS.2", "COOP-2.1"]
paths: ["crates/protocol/chio-http-serve/src/transport.rs", "crates/protocol/chio-http-serve/tests/mtls.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-3 ("the HOST-M3 door"), G4/G5 claim "the receiver admits a co-signed work commitment at its own door" (`prevent`, `ready_after_adr` CT-WORK, CT-CROSS); success-test criterion (b). Today `chio-http-serve` uses `.with_no_client_auth()` (`transport.rs:83`). Add a client-cert verifier pinned to partner-card SPKIs (CT-CROSS mTLS profile).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-http-serve mtls` passes: pinned client accepted, unpinned and expired client refused.

## Log
- 2026-10-09T04:51:58Z connor: created
