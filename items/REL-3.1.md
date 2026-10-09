---
id: "REL-3.1"
title: "Claude Code and Codex MCP-mode harness profiles with hooks labelled as coverage"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-2.0"]
paths: ["integrations/harnesses/claude-code/**", "integrations/harnesses/codex/**", "integrations/harnesses/README.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-3 ("Claude Code and Codex are co-first, in MCP mode. Hooks count as coverage, never enforcement, because hook failure does not block either host"), D12 recommendation, G1 claim "Harness hooks observe native tool use" (`detect_only`). The harness plugins live in external repos (`backbay-labs/chio-claude-code-plugin`, `backbay-labs/chio-codex-plugin`); this item creates the in-repo source of truth: per-harness MCP configuration snippets for serve-http, the policy profile, and a statement of what hooks observe versus what the MCP door enforces, with `boundary_class` for each. No hook is described as enforcement anywhere.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Each harness directory has a README with the remote-MCP config, the boundary table (`prevent` for MCP-door calls, `detect_only` for hook observations, `cannot_see` for native tools outside both), and a smoke script used by REL-2.4.
- `python3 scripts/check-native-host-docs.py --rule retired-phrases --rule em-dash` passes on `integrations/harnesses/`.

## Log
- 2026-10-09T04:51:58Z connor: created
