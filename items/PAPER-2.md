---
id: "PAPER-2"
title: "PAPER-2: abstract, introduction and programming model"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["PAPER-1", "CT-WORK.3", "WORK-SLICE-C.1"]
paths: ["docs/papers/verifiable-work/paper.tex", "docs/papers/verifiable-work/sections/01-problem.tex", "docs/papers/verifiable-work/sections/02-model.tex", "docs/papers/verifiable-work/sections/03-programming.tex"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: "PAPER-1 to PAPER-4 are now scheduled. PAPER-5 follows W4". PAPER-n = P.n in `docs/superpowers/plans/2026-10-03-verifiable-work-finalization.md` (landed by WORK-SLICE-C.1). `docs/papers/verifiable-work/PUBLICATION.json` (`chio.paper.publication-gates.v1`) has `publish_ready=false`; gates independent-operation, useful-work-economics, integration-advantage and foundational-claim are open and must stay open until evidence exists. Describe the programming model with the frozen CT-WORK names, including the real recovery command names. Adding `03-programming.tex` beside `03-contract.tex` requires renumbering later sections (coordinate with PAPER-3).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `make -C docs/papers/verifiable-work build` succeeds; claims map to ARCHITECTURE-CLAIMS rows.

## Log
- 2026-10-09T04:51:58Z connor: created
