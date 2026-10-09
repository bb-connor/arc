---
id: "PAPER-1"
title: "PAPER-1: thesis freeze and architecture publication profile"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-D.1"]
paths: ["docs/papers/verifiable-work/ARCHITECTURE-PUBLICATION.json", "docs/papers/verifiable-work/ARCHITECTURE-CLAIMS.json", "docs/papers/verifiable-work/FINALIZATION-REVIEW.md", "docs/papers/verifiable-work/tools/check.py", "docs/papers/verifiable-work/tools/test_evidence.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: "PAPER-1 to PAPER-4 are now scheduled. PAPER-5 follows W4". PAPER-n = P.n in `docs/superpowers/plans/2026-10-03-verifiable-work-finalization.md` (landed by WORK-SLICE-C.1). `docs/papers/verifiable-work/PUBLICATION.json` (`chio.paper.publication-gates.v1`) has `publish_ready=false`; gates independent-operation, useful-work-economics, integration-advantage and foundational-claim are open and must stay open until evidence exists. Schema `chio.paper.architecture-publication.v1` with flags from design_complete to publish_ready; preserve the legacy PUBLICATION.json gates.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `architecture_profile_with_unverified_implementation_is_rejected`, `missing_claim_evidence_is_rejected`, `legacy_open_gates_still_fail`, `unknown_profile_is_rejected` pass; `make -C docs/papers/verifiable-work test` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
