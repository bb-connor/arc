---
id: "UR-U3.2"
title: "AGENTS.md overview and VISION.md historical banner"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["DOCS-1177.1"]
paths: ["AGENTS.md", "docs/start-here/VISION.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 3.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: U3, section 9 (AGENTS.md lines 5 and 11; VISION.md needs a historical banner). On post-#1160 main, AGENTS.md line 5 still describes Chio as "a protocol for secure, attested tool access", and the five-component list says tool servers are "isolated from each other", which contradicts ADR-0038 ("isolation denies, Chio grants": isolation always comes from the host). Rewrite line 5 around the north star and rule 6 (userspace authority and work-state kernel), and scope the isolation sentence to host-provided isolation. Add a dated historical banner to `docs/start-here/VISION.md` pointing at the unified roadmap. North-star sentence, verbatim: "Chio is a Rust kernel for agentic operating systems that coordinate work, share resources, and cooperate across organizational boundaries." Supporting line, verbatim: "Authority that only narrows. Work that survives. Evidence that travels." Retired phrases: "The kernel your agents answer to", "Agents that pay each other", "only protocol", "kernel for building agentic operating systems".

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/check-native-host-docs.py --rule retired-phrases` passes for both files.
- AGENTS.md no longer claims Chio itself isolates tool servers; VISION.md begins with a historical banner naming the roadmap.

## Log
- 2026-10-09T04:51:58Z connor: created
