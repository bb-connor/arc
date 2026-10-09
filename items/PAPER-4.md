---
id: "PAPER-4"
title: "PAPER-4: complete and review the manuscript"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["PAPER-3"]
paths: ["docs/papers/verifiable-work/sections/06-evaluation.tex", "docs/papers/verifiable-work/README.md", "docs/papers/verifiable-work/ARTIFACT.md", "docs/papers/verifiable-work/paper.pdf", "docs/papers/verifiable-work/artifact-manifest.json", "docs/papers/verifiable-work/FINALIZATION-REVIEW.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: "PAPER-1 to PAPER-4 are now scheduled. PAPER-5 follows W4". PAPER-n = P.n in `docs/superpowers/plans/2026-10-03-verifiable-work-finalization.md` (landed by WORK-SLICE-C.1). `docs/papers/verifiable-work/PUBLICATION.json` (`chio.paper.publication-gates.v1`) has `publish_ready=false`; gates independent-operation, useful-work-economics, integration-advantage and foundational-claim are open and must stay open until evidence exists. Page-by-page review with the actual reviewer recorded. The independent-operation gate stays open until an outside team and an independently written provider exist (section 1 stretch).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `make -C docs/papers/verifiable-work test build` passes; FINALIZATION-REVIEW.md records the review; open gates remain false.

## Log
- 2026-10-09T04:51:58Z connor: created
