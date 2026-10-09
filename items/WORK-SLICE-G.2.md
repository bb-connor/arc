---
id: "WORK-SLICE-G.2"
title: "Gamma: treaty runtime-core"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-B.4", "WORK-SLICE-G.1"]
paths: ["crates/kernel/chio-runtime-core/src/admission_hook/dsse.rs", "crates/kernel/chio-runtime-core/src/admission_hook/dsse/**", "crates/kernel/chio-runtime-core/src/admission_hook/treaty_ref.rs", "crates/kernel/chio-runtime-core/src/admission_hook/treaty_evidence.rs", "crates/kernel/chio-runtime-core/src/admission_hook/swarm_ref.rs", "crates/kernel/chio-runtime-core/src/treaty.rs", "crates/kernel/chio-runtime-core/src/types.rs", "crates/kernel/chio-runtime-core/src/schema.rs", "crates/kernel/chio-runtime-core/tests/runtime_treaty*.rs", "crates/kernel/chio-runtime-core/tests/runtime_treaty_predicate_substitution/**", "crates/kernel/chio-runtime-core/tests/runtime_agreement_context_scan.rs", "crates/kernel/chio-runtime-core/tests/runtime_buyer_review.rs", "crates/kernel/chio-runtime-core/tests/support/treaty_presentation.rs", "crates/kernel/chio-runtime-harness/src/treaty.rs", "spec/CHIO_LADDER.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice gamma (federation, bilateral DSSE, iroh lanes, treaty runtime-core; roadmap: after alpha and beta, needed for the remote co-signer). No crate-level conflicts with #1160. Needed by COOP-3.1 (treaty predicates carried by the process host's admission hook).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-runtime-core --test runtime_treaty --test runtime_treaty_binding_substitution --test runtime_treaty_predicate_substitution` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
