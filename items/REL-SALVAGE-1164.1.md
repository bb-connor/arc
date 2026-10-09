---
id: "REL-SALVAGE-1164.1"
title: "Salvage #1164 MCP adoption, activation and status commands"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-LEDGER-CARRY", "REL-2.1"]
paths: ["crates/products/chio-cli/src/cli/mcp/adopt.rs", "crates/products/chio-cli/src/cli/mcp/activate.rs", "crates/products/chio-cli/src/cli/mcp/activate/**", "crates/products/chio-cli/src/cli/mcp/adoption_bundle.rs", "crates/products/chio-cli/src/cli/mcp/status.rs", "crates/products/chio-cli/src/cli/mcp/status/**", "crates/products/chio-cli/tests/mcp_adopt.rs", "crates/products/chio-cli/tests/mcp_activate.rs", "crates/products/chio-cli/tests/mcp_status.rs", "examples/mcp-adoption/**", "docs/guides/ADOPT-EXISTING-MCP.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7 (#1164: close; salvage its MCP adoption, activation and preview-distribution machinery into Lane REL). Source: PR #1164 (ref `origin/feat/workbench-git-tasks`, head 5bdf08fc3); never built or tested since written; none of these files exist on main or #1160. Port `chio mcp adopt`, `activate`, `status` and the adoption bundle (wire them in `crates/products/chio-cli/src/cli/mcp.rs` and dispatch with minimal lines), plus `examples/mcp-adoption/**` and `docs/guides/ADOPT-EXISTING-MCP.md`. Do not port `chio-workbench`. Address the inherited review findings that touch these files (12 `inherited-thread:*` requirement IDs listed in the PR body and in `docs/operations/pr-carry-forward.json`), especially the P1 "imported server environment reaching the kernel": imported server env must be filtered by an allowlist before reaching the kernel.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-cli --test mcp_adopt --test mcp_activate --test mcp_status` passes, including a new test that a non-allowlisted environment variable from an adopted server never reaches the kernel process.
- `examples/mcp-adoption/check.py` passes against a locally built binary.
- Every #1164 ledger row touching these files is dispositioned in PR-CARRY-FORWARD.

## Log
- 2026-10-09T04:51:58Z connor: created
