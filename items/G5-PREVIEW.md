---
id: "G5-PREVIEW"
title: "G5: preview release that contains HOST-M3"
severity: "P2"
wave: 4
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["G4-DRILLS", "REL-1.9", "WORK-W2.5b"]
paths: ["CHANGELOG.md", "docs/install/README.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G5 ("a preview release that contains HOST-M3"), section 1 criterion (f) ("the run uses a tagged preview release"). Prepare the next `0.2.0-alpha.N` with HOST-M3: changelog, install docs, release notes with the G4/G5 claim rows and preview label, CT-WIRE freeze list unchanged or bumped by new identifiers only. Tag push and publish are owner operations (same path as REL-1.9). Re-run G1-REHEARSAL in published mode and the G4-RUN script against the tag.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The tag's G1-REHEARSAL and G4-RUN pass in published mode; `python3 scripts/check-preview-freeze.py --publish` passes; release is prerelease, not Latest.

## Log
- 2026-10-09T04:51:58Z connor: created
