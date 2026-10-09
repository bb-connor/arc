---
id: "PAPER-3"
title: "PAPER-3: technical construction sections"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["PAPER-2"]
paths: ["docs/papers/verifiable-work/sections/03-contract.tex", "docs/papers/verifiable-work/sections/04-execution.tex", "docs/papers/verifiable-work/sections/05-composition.tex", "docs/papers/verifiable-work/sections/07-related.tex", "docs/papers/verifiable-work/sections/08-limits.tex", "docs/papers/verifiable-work/sections/09-conclusion.tex", "docs/papers/verifiable-work/sections/10-profile-details.tex", "docs/papers/verifiable-work/sections/11-evidence.tex"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: "PAPER-1 to PAPER-4 are now scheduled. PAPER-5 follows W4". PAPER-n = P.n in `docs/superpowers/plans/2026-10-03-verifiable-work-finalization.md` (landed by WORK-SLICE-C.1). `docs/papers/verifiable-work/PUBLICATION.json` (`chio.paper.publication-gates.v1`) has `publish_ready=false`; gates independent-operation, useful-work-economics, integration-advantage and foundational-claim are open and must stay open until evidence exists. Keep the preservation-proof premises unchanged.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `make -C docs/papers/verifiable-work test build` passes; the proof premises diff is empty.

## Log
- 2026-10-09T04:51:58Z connor: created
