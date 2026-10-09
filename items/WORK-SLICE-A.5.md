---
id: "WORK-SLICE-A.5"
title: "Alpha: finding-verifier execution profile"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-A.1"]
paths: ["crates/trust/chio-finding-verifier/src/verify.rs", "crates/trust/chio-finding-verifier/src/verify/receipt_semantics.rs", "crates/trust/chio-finding-verifier/tests/verifier.rs", "crates/trust/chio-finding-verifier/tests/verifier/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 5.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice alpha (execution evidence and checked output; lands right after Gate 0; drops #1173's own sweep edit in favour of #1160's classifier). Port the verifier's execution-profile receipt semantics.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-finding-verifier --test verifier execution_profile` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
