---
id: "SHARE-4.2"
title: "Write ADR-0035: web3-free distribution at full scope"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-U3.5"]
paths: ["docs/adr/ADR-0035-web3-free-distribution.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 5.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: SHARE-4 ("write ADR-0035 (web3-free distribution) at its real scope: the kernel, core, control plane and CLI"); section 8 recorded decision "ADR-0035 at full scope". The number is reserved by #1170's candidate list (`docs/research/nvidia/06-strategy-and-roadmap.md` section 12). State the boundary: the preview distribution (kernel, core, control plane, CLI) builds and runs without web3 settlement, anchoring or contract crates; rails plug in as optional modules; no on-chain or escrow claims. List the crates and features SHARE-4.3 and SHARE-4.4 change. Do not include commercial rationale.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- ADR-0035 exists, is indexed in `docs/adr/README.md` (coordinate a one-line index edit with UR-U3.5's owner if still open), and names the exact crates and features.

## Log
- 2026-10-09T04:51:58Z connor: created
