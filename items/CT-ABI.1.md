---
id: "CT-ABI.1"
title: "KSPEC-01 phase 0 census and KERNEL_ABI_VERSION"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-G0-LEDGER.1", "DOCS-1174.1"]
paths: ["crates/kernel/chio-kernel-core/src/abi.rs", "crates/kernel/chio-kernel-core/src/lib.rs", "docs/security/kernel-abi-inventory.json", "scripts/check-kernel-abi.py", "scripts/tests/check-kernel-abi.test.py", "spec/PROTOCOL.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-ABI ("`KERNEL_ABI_VERSION`, published from the KSPEC-01 phase 0 census. Operation IDs are never reused"). Spec: `docs/superpowers/specs/2026-10-04-closed-kernel-abi-design.md` (KSPEC-01): L1 row at line 143, R3 "ids are dense and never reused" at 158, `crates/kernel/chio-kernel-core/src/abi.rs` with `KernelOp` and `KERNEL_ABI_VERSION {1,0}` at 185-210, census `scripts/check-kernel-abi.py` plus `docs/security/kernel-abi-inventory.json` at 328-345, phase 0 at 386-391, PROTOCOL section 8.6 at 374. `chio-kernel-core` is `#![no_std]` and has no `abi.rs` today. Generate the census from the post-#1160 tree: `KERNEL_ABI_VERSION` 1.0 = ops 1 to 26; ops 27 (WORK alpha `ExportExecutionEvidence`) and 28-29 (REC) stay `planned` in the slot ledger, not in `abi.rs`. Retired ids stay listed. The L1 row records `chio.process.abi.v3` as on the tree; dispositions are observed behaviour marked "pending owner review". KSPEC-01's "six worker ops" is stale: #1160 serves seven. Edit only section 8.6 of `spec/PROTOCOL.md`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/check-kernel-abi.py` passes; its test has failing fixtures for an unclassified symbol, a row with no symbol, a reused retired id, and enum drift.
- `cargo test -p chio-kernel-core abi::` (`kernel_op_ids_dense_and_unique`, `kernel_abi_version_is_1_0`) and `cargo build -p chio-kernel-core --no-default-features` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
