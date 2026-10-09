---
id: "REL-3.2"
title: "Linux restricted launcher for Claude Code (bubblewrap) with KSPEC-07 evidence"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-3.1", "KSPEC-07.BK"]
paths: ["integrations/linux/launchers/claude-code/**", "tests/integration/linux/test_host_launcher_claude_code.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-3 ("Linux restricted launchers for the HOST-M2 harnesses. Today Pi has bubblewrap; Claude Code, Codex, Cursor and Hermes are Seatbelt-only; OpenClaw is a container"), KERN-5 (`AgentHostBwrap` backend kind), G3 isolation evidence. Paths follow the #1177 Omarchy plan's guidance (`integrations/linux`, `tests/integration/linux`). Build a bubblewrap launcher that runs Claude Code with only the MCP door, the model relay and the declared workspace reachable, records its effective protection as KSPEC-07 `AgentHostBwrap` evidence, and refuses (never falls back to unrestricted) when namespaces or cgroups are unavailable. "Isolation denies, Chio grants" (ADR-0038).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 -m unittest tests/integration/linux/test_host_launcher_claude_code.py` passes on Linux: kernel port unreachable, arbitrary egress denied, missing userns refuses, evidence record emitted with backend kind.

## Log
- 2026-10-09T04:51:58Z connor: created
