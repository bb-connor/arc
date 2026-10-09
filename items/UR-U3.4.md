---
id: "UR-U3.4"
title: "spec/PROTOCOL.md header: pre-release preview label and CT-WIRE pointer"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-WIRE.1"]
paths: ["spec/PROTOCOL.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 2.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: U3, section 9 ("The spec/PROTOCOL.md header"). The post-#1160 header says "Version: 1.0", "Date: 2026-04-14", "Status: Current bounded Chio release profile". Replace it with a header that states the document is a pre-release profile, carries the preview label until the qualification in roadmap section 11, and points to the CT-WIRE freeze list (`spec/` location chosen by CT-WIRE.1) for which byte formats are frozen during the `0.2.0-alpha.N` preview window. Header only: do not change normative sections (CLAUDE.md: wire-level changes must agree with PROTOCOL.md, so a body edit is out of scope here).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `git diff` touches only the header block (first 15 lines) of spec/PROTOCOL.md.
- The header contains "pre-release", "preview" and a link to the CT-WIRE freeze list path.

## Log
- 2026-10-09T04:51:58Z connor: created
