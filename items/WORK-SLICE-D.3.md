---
id: "WORK-SLICE-D.3"
title: "Slice d: research code (labs, benches, composition tests)"
severity: "P3"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-G.2"]
paths: ["labs/kernel-work-composition/**", "labs/kernel-work-families/**", "examples/composed-baseline/**", "crates/kernel/chio-runtime-core/benches/**", "crates/kernel/chio-kernel/benches/paper_security_components.rs", "crates/kernel/chio-kernel/tests/three_owner_composition*", "crates/kernel/chio-process/tests/cross_owner_recovery.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Exclude anything that needs #1162's outcome-continuation code (`examples/outcome-ledger-comparison`, runtime-core outcome examples), which is parked (UR-PK-1162-OUTCOME).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Each landed lab and bench builds (`cargo build --manifest-path <lab>/Cargo.toml`, `cargo bench --no-run -p chio-kernel`); composition tests pass.

## Log
- 2026-10-09T04:51:58Z connor: created
