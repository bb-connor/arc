---
id: "WORK-SLICE-C.1"
title: "Land the WORK specs, plans and work-abstraction docs with the roadmap corrections"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-0.1"]
paths: ["docs/superpowers/specs/2026-10-03-*.md", "docs/superpowers/plans/2026-10-03-*.md", "docs/research/work-abstraction/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice c (roadmap: "WORK specs and plans, with the corrections below"; landing it with gamma is too late because WORK-W1.0 writes into `docs/research/work-abstraction/`). Carry the four 2026-10-03 specs, the five plans (work-runtime, work-owner-services, work-developer-surface, work-beta-convergence, verifiable-work-finalization) and `docs/research/work-abstraction/{README,CURRENT-STATE,ARCHITECTURE-REVIEW,REVIEW,SESSION-INTENT-REVIEW}.md` plus `SOURCES.json`. Apply corrections: split W1.5, W1.6 (and W1.3, which also needs recovery) into a (no recovery) and b (after REC) halves; add `POST /v1/work/cosign` to W2.1's route list; make W2.5 mandatory; replace doc-only port names with the real #1179 names (CT-WORK.1 table); fix the router path (`crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs`), MSRV (1.95, not 1.94), the `chio.work.v1` schema directory, and the funded-example dependencies (examples/federated-work is slice delta and will not be on main); prefix every cross-program ID with WORK- or PAPER- (roadmap section 12). Do not import the other 31 history plans (slice d).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Link and anchor check over the moved docs passes; `grep -rn "ProcessRecoveryPort\|KernelRecoveryPort\|ExplainIntent" docs/superpowers docs/research/work-abstraction` matches only inside a "superseded names" table; no U+2014.

## Log
- 2026-10-09T04:51:58Z connor: created
