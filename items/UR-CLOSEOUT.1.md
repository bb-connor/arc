---
id: "UR-CLOSEOUT.1"
title: "Close contained and superseded PRs after carry-forward (#1161, #1159, #1158, #1136, #1162, #1163 prep)"
severity: "P2"
wave: 2
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-LEDGER-CARRY"]
paths: ["docs/operations/PR-CARRY-FORWARD.md", "docs/archive/pr-1162/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 3.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7. #1161, #1159 and #1158 close as contained in #1173 (note: #1161's peer transport is example-only and does not satisfy STRAT-F15). #1136 closes after #1160 (patch contained). #1162: archive its evidence and `examples/repair-machine-proof` (create annotated tag `archive/pr-1162` at its head `origin/wip/outcome-continuation-review-2026-09-14` and a `docs/archive/pr-1162/README.md` listing archived paths with sha256), then close. #1163 is parked on an owner decision (UR-PK-1163); do not close it. Each closing comment links the PR's rows in PR-CARRY-FORWARD.md. Also archive the unmerged branches the roadmap lists (`research/genesis-program`, `project/roadmap-04-25-2026`, `docs/native-application-adoption`, `research/funded-work-baseline`) as `archive/<branch>` tags without deleting them.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `gh pr view <n> --json state` is CLOSED for 1161, 1159, 1158, 1136, 1162, each with a comment linking PR-CARRY-FORWARD.md.
- `git ls-remote --tags origin 'archive/*'` lists the five archive tags; no branch was deleted.

## Log
- 2026-10-09T04:51:58Z connor: created
