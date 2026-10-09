---
id: "REL-1.SALVAGE-1073"
title: "Salvage #1073: split the release qualification budget and bind exact-head CI"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-LEDGER-CARRY"]
paths: [".github/workflows/release-qualification.yml", ".github/workflows/README.md", "scripts/qualify-release.sh", "scripts/wait-for-exact-ci.sh", "scripts/tests/release-qualification-exact-ci.test.sh", "scripts/tests/release-qualification-formal-tools.test.sh", "scripts/check-release-source-gates.py", "scripts/tests/check-release-source-gates.test.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7 (#1073: salvage into REL-1, release qualification budget). Source: PR #1073 (ref `origin/fix/release-qualification-budget`, head cae222b08); none of it is on #1160. #1160's `release-qualification.yml` is one job: `scripts/qualify-release.sh` re-runs `ci-workspace.sh` (line 45), then web3 qualification, then MSRV, and it hits the 6-hour ceiling. Port the split: stop re-running `ci-workspace.sh` once exact-head CI is proven green by a new fail-closed `scripts/wait-for-exact-ci.sh`; move MSRV and web3 lanes into separate jobs with their own budgets. Carry ledger row `inherited-thread:r3880815557` (P2, "Reject dispatched aliases of main candidates"): decide main membership by ancestry, not by ref name. Leave out #1073's `.github/CODEOWNERS` edit (owner decision).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `bash scripts/tests/release-qualification-exact-ci.test.sh` with new case `dispatched_alias_of_main_commit_is_rejected`; `bash scripts/tests/release-qualification-formal-tools.test.sh`; `python3 scripts/tests/check-release-source-gates.test.py` pass.
- `actionlint` clean on the changed workflows.

## Log
- 2026-10-09T04:51:58Z connor: created
