---
id: "REL-3.5"
title: "Host compatibility: tested harness version ranges replace exact pins"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-REL.1"]
paths: ["integrations/harnesses/compat.toml", "scripts/check-harness-compat.py", "scripts/tests/check-harness-compat.test.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: CT-REL ("Host compatibility: tested version ranges for harness hosts, instead of exact pinned hashes"), REL-3. Create a machine-readable compatibility manifest (harness, min tested version, max tested version, last qualification run, boundary notes) for Claude Code, Codex, Pi and Hermes, and a checker that REL-2.4 and REL-3.x tests read to pick versions. Remove or redirect any exact-hash pin of a harness found in this repo (search `integrations/`, `scripts/`, `.github/`); hashes of vendored test fixtures (for example `integrations/mcp-adapter/tests/conformance_suite.rs` `PINNED_HASH`) are not harness pins and stay.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/check-harness-compat.py` validates the manifest; tests cover malformed ranges and min greater than max.
- The CT-REL contract links the manifest as the normative compatibility source.

## Log
- 2026-10-09T04:51:58Z connor: created
