---
id: "CT-ABI.2"
title: "Process ABI v4 union contract"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-ABI.1"]
paths: ["spec/CHIO_PROCESS_ABI.md", "spec/versions/chio-protocol-negotiation.v1.json", "crates/kernel/chio-process/tests/abi_contract.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-ABI ("Process ABI v4"), G0.2 ("there are two incompatible v3s (#1160 and #1179), so their union is v4"), KDEF-N13. #1160's v3 (`crates/kernel/chio-process/src/lib.rs:65`, commit 2a4c2fbe4) adds worker op `prepare_invocation` (`worker.rs:84`, documented in `crates/products/chio-cli/PROCESS_HOST.md:379` but missing from `WORKER_PROTOCOL.md`'s op table), the `process_prepared_invocations` table, supplemental routes and `output_withheld: "too_large"`. #1179 at its live head f217de1fb (the roadmap's pin 491bd01b5 is stale; the local ref `origin/feat/recoverable-agent-runtime-20261002` may lag)'s v3 (`lib.rs:57`) adds durable-knowledge refusals, original snapshot and call binding (`binding.rs`), tables `process_recovery_calls`, `process_artifact_objects`, `process_confined_return_slots` with no-delete triggers, and drops `PrepareInvocation` (6 ops vs 7). v4 = #1160 v3 union #1179 v3 union KSPEC-08's reserved `withheld` invoke status and control-socket DTOs (S14, S30) union the `exited` `ProcessState` (KERN-3.EXIT-SPEC) union redacted `inspect` (KDEF-N14) union `chio.work.v1` negotiation on the same socket (no second listener). Include a closed op table with retired names and the v3 refusal rule from `PROCESS_HOST.md:200-213`. Do NOT flip `PROCESS_ABI` on main: it flips at the REC-P0/P1 merge (flipping earlier forces a v5).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-process --test abi_contract` (`worker_ops_are_documented_in_v4_table`) passes; `bash scripts/check-chio-owned-v1-only.sh` and `cargo test -p chio-core-types --test protocol_error_registry` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
