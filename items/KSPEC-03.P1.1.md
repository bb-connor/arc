---
id: "KSPEC-03.P1.1"
title: "PostEffectObligation and Discharged types (Mechanism A)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["KERN-REGROUND"]
paths: ["crates/kernel/chio-kernel/src/kernel/evaluation/effect_obligation.rs", "crates/kernel/chio-kernel/src/kernel/evaluation/mod.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-2 (KSPEC-03 phase 1: KDEF-D1, N2, N28, N29, together with the M20 identity-disposition delta; one train batch because KSPEC-08 rule S15 ties `retryable_after_resume` to M20). Spec: `docs/superpowers/specs/2026-10-04-typed-reservations-design.md` (KSPEC-03). Add the affine obligation type that every post-effect path must discharge exactly once; construction outside the module, `Clone`, and discharge for the wrong request must not compile.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `compile_fail` doctests (return without `Discharged`; construct outside the module; `Clone`; wrong-request discharge) pass: `cargo test -p chio-kernel --doc effect_obligation`.

## Log
- 2026-10-09T04:51:58Z connor: created
