---
id: "REL-SALVAGE-1164.2"
title: "Salvage #1164 agent preview packaging and install scripts into the preview train"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-LEDGER-CARRY", "CT-REL.1"]
paths: ["scripts/package-agent-preview.py", "scripts/check-agent-install.sh", "scripts/check-agent-preview-runtime.py", "scripts/agent-preview-readme.md", "scripts/tests/package-agent-preview.test.py", "scripts/tests/agent-preview-runtime.test.py", ".github/workflows/agent-preview-package.yml", ".github/workflows/agent-preview-acceptance.yml"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7 (#1164 preview-distribution machinery into Lane REL). Source: PR #1164 (ref `origin/feat/workbench-git-tasks`, head 5bdf08fc3). Port the agent-preview packaging and install checks and adapt them to CT-REL (versions `0.2.0-alpha.N`, signed artifacts, tested host ranges). Reconcile with REL-1's packaging so there is one preview build path, not two: if REL-1 already provides an equivalent script, port only the missing checks and delete the duplicate. `scripts/install-chio.sh` from #1164 is handled by REL-1's install path (salvaged from #1155); do not port it here. Address the inherited findings on native packaging portability and artifact/test provenance.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/tests/package-agent-preview.test.py` and `scripts/tests/agent-preview-runtime.test.py` pass.
- Workflows are non-required, run on tag and manual dispatch, and produce artifacts consumed by REL-1's signing step.

## Log
- 2026-10-09T04:51:58Z connor: created
