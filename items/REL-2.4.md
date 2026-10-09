---
id: "REL-2.4"
title: "Claude Code and Codex connect over ordinary remote MCP with allow and deny receipts"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-2.2", "REL-3.5"]
paths: ["tests/integration/mcp-remote/**", ".github/workflows/mcp-remote-harness.yml"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-2 exit ("current Claude Code and Codex connect through ordinary remote MCP, with no plugin"), G1 ("current Claude Code and Codex connect over MCP and produce allow and deny receipts"). Write a scripted acceptance that starts `chio mcp serve-http` with a policy allowing one tool and denying another, configures each harness's standard remote-MCP client (no Chio plugin), drives one allowed and one denied call, and verifies both receipts offline with `chio evidence verify`. Harness versions come from the tested ranges (REL-3.5). Harness credentials are a hosted-CI secret: make the workflow skip with a clear message when absent and runnable locally; the owner wires the secret (serialization point).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `tests/integration/mcp-remote/run.sh claude-code` and `... codex` each produce one allow and one deny receipt that verify offline.
- The workflow runs the matrix over the min and max tested versions of each harness when credentials are present.

## Log
- 2026-10-09T04:51:58Z connor: created
