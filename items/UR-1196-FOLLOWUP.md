---
id: "UR-1196-FOLLOWUP"
title: "Roadmap follow-up: 13 review-bot P2 findings deferred from PR #1196"
severity: "P2"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/operations/UNIFIED_ROADMAP.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Deferred under decision docs-pr-p2-followup-rule (2026-10-09): review-bot P2 findings raised on PR #1196 heads 6eeffd9d and c32c460f, on text the final push did not change. Verify each against the merged roadmap (docs/operations/UNIFIED_ROADMAP.md on main) and the code, fix it or record why it is wrong, in one follow-up PR.

- https://github.com/bb-connor/arc/pull/1196#discussion_r4228540581 (line 188 Decide rotated-signer delivery before freezing CT-SETTLE)
- https://github.com/bb-connor/arc/pull/1196#discussion_r4228540594 (line 260 Scope COOP-4 to what unwitnessed checkpoints prove)
- https://github.com/bb-connor/arc/pull/1196#discussion_r4228540607 (line 532 Use separate operators for G4's section 1 rehearsal)
- https://github.com/bb-connor/arc/pull/1196#discussion_r4228540619 (line 545 Add a post-G4 release step before G5)
- https://github.com/bb-connor/arc/pull/1196#discussion_r4228540630 (line 345 Qualify the undefined M20 dependency)
- https://github.com/bb-connor/arc/pull/1196#discussion_r4228676483 (line 483 Wire OUT-4 reviews into the gate dependencies)
- https://github.com/bb-connor/arc/pull/1196#discussion_r4228676491 (line 569 Remove the blanket kernel-mediated scope from native claims)
- https://github.com/bb-connor/arc/pull/1196#discussion_r4228676498 (line 656 Schedule the licensing decision before G1)
- https://github.com/bb-connor/arc/pull/1196#discussion_r4228676504 (line 445 Add the required v prefix to preview tags)
- https://github.com/bb-connor/arc/pull/1196#discussion_r4228676511 (line 445 Configure the preview release as a prerelease)
- https://github.com/bb-connor/arc/pull/1196#discussion_r4228676517 (line 667 Resolve D20 consistently with Gate 0's version promise)
- https://github.com/bb-connor/arc/pull/1196#discussion_r4228676522 (line 439 Make the automated release trigger release-tagged)
- https://github.com/bb-connor/arc/pull/1196#discussion_r4228676527 (line 439 Publish the replay bundle before release-tagged runs)

## Acceptance

- Each listed finding is fixed in the roadmap or answered with a concrete reason on its thread.
- The docs checks CI runs on docs/operations pass.

## Log
- 2026-10-09T13:48:41Z connor: created
