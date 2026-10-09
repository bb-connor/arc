---
id: "REL-1.9"
title: "Cut v0.2.0-alpha.1: changelog, notes, checksum review, mirror sync, published-mode rehearsal"
severity: "P1"
wave: 2
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-1.2", "CT-REL.2", "REL-1.1", "REL-1.3", "REL-1.4", "REL-1.5", "CT-WIRE.5", "REL-1.8", "REL-1.SALVAGE-1056", "REL-1.SALVAGE-1155", "G1-REHEARSAL", "SEC-POSTMERGE.1", "SEC-POSTMERGE.4", "UR-U10"]
paths: ["CHANGELOG.md", "docs/install/README.md", "docs/install/VERIFY.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-1, G1, U10 ("replace them at G1"). Prepare the first preview: CHANGELOG entry, install docs pointing at the tag (replacing U10's notices), the checksum review PR per `docs/install/PUBLISHING.md:363-399`. The tag push and `gh release edit --draft=false --prerelease --latest=false --verify-tag` are owner operations. The CT-REL.2 gate refuses the tag unless either a D8 preview-exception record exists (parked UR-D8) or the obligations are evidenced (SEC-POSTMERGE.1 and .4 here, plus parked UR-PK-SEC-CAPTURE and UR-PK-SEC-APP). After publication, confirm the mirror sync and run G1-REHEARSAL in published mode.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- G1-REHEARSAL passes in published mode against the tag; `cosign verify-blob` succeeds on downloaded assets; the mirror carries the tag.
- The GitHub release is prerelease and not Latest.

## Log
- 2026-10-09T04:51:58Z connor: created
