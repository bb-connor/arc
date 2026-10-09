---
id: "KSPEC-08.P1.4"
title: "Shared StopHeads, tier-1 checks at the eleven sites, typed KernelStopped, separate host latch"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KSPEC-08.P1.2"]
paths: ["crates/kernel/chio-kernel/src/kernel/construction.rs", "crates/kernel/chio-kernel/src/kernel/kernel_struct.rs", "crates/kernel/chio-kernel/src/kernel/dispatch.rs", "crates/kernel/chio-kernel/src/finding_pool.rs", "crates/kernel/chio-kernel/src/kernel/evaluation/evaluation_entry.rs", "crates/kernel/chio-kernel/src/kernel/credential_reservation/native_dispatch.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/lifecycle.rs", "crates/kernel/chio-kernel/src/kernel/admission_coordinator/collection_context.rs", "crates/platform/chio-control-plane/src/durable_admission.rs", "crates/products/chio-api-protect/src/proxy/state.rs", "crates/platform/chio-http-core/src/authority.rs"]
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
Today the stop is two process-local atomics (`crates/kernel/chio-kernel/src/kernel/construction.rs:369-370`) read at eleven tier-1 sites (`evaluation_entry.rs:54,343`, `async_evaluation_core.rs:39`, `nested_flow_evaluation.rs:121`, `dispatch.rs:721`, `credential_reservation/native_dispatch.rs:207`, `native_egress/lifecycle.rs:83`, `terminal.rs:159`, `native_output.rs:396`, `collection_context.rs:74`, `finding_pool.rs:720`). Put an `ArcSwap` of stop heads on the store or runtime handle, shared by every kernel in the process including api-protect's proxy authority kernel (S11, S20, S24, S35). `emergency_stop()` stays a process latch and is never rewired to the chain. The one-line stop checks inside `async_evaluation_core.rs`, `nested_flow_evaluation.rs`, `terminal.rs` and `native_output.rs` are leased by KSPEC-03 items; make those edits after KSPEC-03.P1.4 lands or coordinate a single-line patch (record which in the PR).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- A stop through one hosted session's kernel denies tool calls in another session's kernel; host-latch independence and the containment implication are tested.
- Loom: `StopHeads` swap against tier-1 readers passes under `--cfg loom`; `cargo test -p chio-kernel stop_heads` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
