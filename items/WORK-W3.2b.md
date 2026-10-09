---
id: "WORK-W3.2b"
title: "W3: Python WorkClient wrapper in chio-process"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W3.2a"]
paths: ["sdks/python/chio-process/src/chio_process/work.py", "sdks/python/chio-process/src/chio_process/__init__.py", "sdks/python/chio-process/tests/test_work.py", "scripts/qualify-process-packages.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Roadmap: WORK-W3 ("`WorkClient` wrappers for Python `chio-process` and `@chio-protocol/process`. Outside teams' agents need these").

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 -m pytest sdks/python/chio-process/tests/test_work.py` passes against CT-WORK vectors; `python3 scripts/qualify-process-packages.py` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
