---
id: "WORK-SLICE-B.2"
title: "Beta: D1 native enforcement in the kernel"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-B.1"]
paths: ["crates/kernel/chio-kernel/Cargo.toml", "crates/kernel/chio-kernel/src/delegated_work.rs", "crates/kernel/chio-kernel/tests/dynamic_delegation.rs", "crates/kernel/chio-kernel/tests/dynamic_delegation/**", "crates/kernel/chio-kernel/examples/dynamic_delegation.rs", "crates/kernel/chio-kernel/examples/dynamic_delegation_support/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice beta (D1 dynamic delegation, S1 swarm evolution, A2A v1 edge; lands right after Gate 0; 2 conflicts). None of the beta paths reference alpha or delta symbols. chio-kernel gains a chio-workflow dependency (acyclic: chio-workflow depends only on chio-core). One `mod` line in `chio-kernel/src/lib.rs`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-kernel --features admission-test-support --test dynamic_delegation` (12 tests, including `changed_native_identity_payload_and_ceiling_never_dispatch`) passes.

## Log
- 2026-10-09T04:51:58Z connor: created
