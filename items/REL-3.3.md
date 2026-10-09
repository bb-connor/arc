---
id: "REL-3.3"
title: "Linux restricted launcher for Codex (bubblewrap) with KSPEC-07 evidence"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-3.1", "KSPEC-07.BK"]
paths: ["integrations/linux/launchers/codex/**", "tests/integration/linux/test_host_launcher_codex.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-3, KERN-5, G3. Same contract as REL-3.2 for Codex. Share helper code only through a small module under `integrations/linux/launchers/common/` created by whichever of REL-3.2 or REL-3.3 lands first (the second rebases onto it).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 -m unittest tests/integration/linux/test_host_launcher_codex.py` passes on Linux with the same negative checks as REL-3.2.

## Log
- 2026-10-09T04:51:58Z connor: created
