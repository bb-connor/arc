---
id: "G1-REHEARSAL"
title: "G1 rehearsal: scripted clean-host install to first allow and deny receipt"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-1.3", "REL-1.4", "REL-1.8", "REL-1.SALVAGE-1046", "REL-2.1", "REL-2.3", "REL-2.4", "KSPEC-08.P1.10", "KSPEC-08.P1.11", "KSPEC-03.P1.5", "KDEF-N4", "KDEF-GT1", "KDEF-CLOCK-GATE", "CT-WIRE.5", "UR-U3.6"]
paths: [".github/workflows/preview-install-rehearsal.yml", "scripts/preview-install-rehearsal.sh", "scripts/tests/preview-install-rehearsal.test.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G1 ("a tagged 0.2.0-alpha.N; a timed install by someone outside the core team, on Linux and on macOS, through to a first receipt; current Claude Code and Codex connect over MCP and produce allow and deny receipts; the CT-WIRE freeze list is published"). This rehearses everything except the outsider (parked UR-PK-G1-OUTSIDER). Matrix: `ubuntu-24.04` container, `ubuntu-24.04-arm`, `macos-14`. Candidate mode uses a draft run's artifacts; published mode uses the tag. Steps: install with REL-1.8 into an empty `HOME`; `chio --version`; serve `examples/docker/mock_mcp_server.py` under `chio mcp serve`; drive it with a stock MCP SDK client (list tools, one allowed and one denied call); `chio receipt verify`; emit JSON with elapsed time per step. Real Claude Code and Codex legs reuse REL-2.4 when secrets exist. #1164's `scripts/check-agent-install.sh` may be reused if REL-SALVAGE-1164.2 landed.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- All three matrix legs pass in candidate mode; receipts show one allow and one deny; timing JSON retained as a workflow artifact.
- The run also checks that the KERN-1 stop works from the CLI on the installed binary.

## Log
- 2026-10-09T04:51:58Z connor: created
