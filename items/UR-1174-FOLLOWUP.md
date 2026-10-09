---
id: "UR-1174-FOLLOWUP"
title: "KSPEC follow-up: 2 review-bot P2 findings deferred from PR #1174 (quorum roster binding, submission-table bound)"
severity: "P2"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md", "docs/superpowers/specs/2026-10-04-opaque-adapter-context-design.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 3.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Deferred under decision docs-pr-p2-followup-rule (2026-10-09): review-bot P2 findings on PR #1174 head 7419d56e98, on lines the final push did not change. Both are spec contract gaps that must close before the matching implementation phase ships. Verify each against the landed spec on main, then fix the spec (and the implementation plan it feeds) or answer on the thread with a concrete reason.

- https://github.com/bb-connor/arc/pull/1174#discussion_r4230630372 (docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md:264, P2: Bind quorum records to the roster generation they used). `StopAuthorizer::Quorum` stores only an artifact digest and principals, so after an operator roster or threshold rotation, a later boot or offline verifier cannot revalidate a historical quorum-authorized `Resume` or `Relax`. Carry `roster_digest` and the deployment generation in the signed authorizer (the S29 artifact already signs `roster_digest`), and retain the authenticated roster configuration for verification.
- https://github.com/bb-connor/arc/pull/1174#discussion_r4230630381 (docs/superpowers/specs/2026-10-04-opaque-adapter-context-design.md:511, P2: Bound retained submission records before sealing requests). `SubmissionTable` has no capacity, namespace quota, expiry or reclamation rule, so a long-lived provider bridge grows it without bound. Define a bounded per-namespace admission quota that fails before evaluation when full, plus a replay-safe retention and reclamation policy. `Retained` records are never reclaimed before their terminal receipt binds.

## Acceptance

- Each finding is fixed in the landed spec, with a disposition row and a conformance test line in the spec's test section, or answered with a concrete reason on its thread.
- No em dashes; the KSPEC numbering is unchanged.

## Log
- 2026-10-09T21:12:51Z connor: created
