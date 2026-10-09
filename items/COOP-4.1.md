---
id: "COOP-4.1"
title: "C2SP checkpoint compatibility (north-star bet 6)"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-WIRE.5"]
paths: ["crates/kernel/chio-kernel/src/checkpoint/c2sp.rs", "crates/core/chio-core-types/src/receipt/checkpoint.rs", "tests/bindings/vectors/c2sp-checkpoint/**", "docs/architecture/transparency/README.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: COOP-4 ("evidence a counterparty can trust without trusting the operator"; claims stay labelled "signatures verified against pinned keys; no external witness" until witnessing exists). #1174's `docs/research/2026-10-04-chio-kernel-north-star.md` bet 6 (lines 215-230); `docs/architecture/transparency/README.md` stage 4 (lines 316-328) proposes C2SP but has no code. Emit and verify C2SP-format checkpoints for the receipt log without changing frozen receipt bytes.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-kernel checkpoint::c2sp` passes against published C2SP vectors (sources cited in the vector file).

## Log
- 2026-10-09T04:51:58Z connor: created
