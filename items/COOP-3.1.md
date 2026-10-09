---
id: "COOP-3.1"
title: "Receiver-owned admission at the api protect door with treaty predicates"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-G.2", "CT-WORK.3", "COOP-2.6a", "COOP-2.7"]
paths: ["crates/products/chio-api-protect/src/proxy/mediated.rs", "crates/products/chio-api-protect/src/proxy/admission_profile.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-3 ("the HOST-M3 door"), G4/G5 claim "the receiver admits a co-signed work commitment at its own door" (`prevent`, `ready_after_adr` CT-WORK, CT-CROSS); success-test criterion (b). Install `ChioRuntimeAdmissionHook` (`crates/kernel/chio-runtime-core/src/admission_hook.rs:185`; set via `ChioKernel::set_runtime_admission_hook`, `kernel/construction.rs:1867`) with treaty predicates from a receiver-signed profile, following `chio-cli/src/cli/process_host/swarm.rs:352`. Neither api protect nor serve-http installs it today. The proxy path evaluates on a separate `HttpAuthority` kernel: route federated calls through the hooked kernel or bind both kernels to the hook. Wiring lines in `chio-cli/src/cli/runtime.rs` follow COOP-2.7.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `federated_call_without_treaty_denied` and `treaty_predicate_mismatch_denied` pass; an admitted call carries the treaty reference in its receipt.

## Log
- 2026-10-09T04:51:58Z connor: created
