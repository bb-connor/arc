---
id: "ECON-SALVAGE-959"
title: "Salvage #959 conformance tests and record the FV-D3 netting dependency"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-LEDGER-CARRY"]
paths: ["crates/tooling/chio-conformance/tests/x402_payment_does_not_authorize_tool_call.rs", "crates/tooling/chio-conformance/tests/eas_verax_display_only_projection.rs", "docs/formal/plan/FV-D3-*.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7 (from #959: the conformance tests `x402_payment_does_not_authorize_tool_call` and `eas_verax_display_only_projection`; drop #959's closed-enum wire break; the FV-D3 dependency on #959's netting code). Source: PR #959 (ref `origin/chio/m2-build`). Port the two tests to main's `chio-conformance` and adapt them to main's types without the closed-enum wire change. Record in the FV-D3 plan document (find it under `docs/formal/plan/`; create `FV-D3-netting-dependency.md` if none exists) that the netting code was not salvaged and what FV-D3 must target instead. Address the 54 rows with `landing_pr` 959.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-conformance x402_payment_does_not_authorize_tool_call eas_verax_display_only_projection` passes.
- No wire enum is closed by this item (CT-WIRE frozen bytes unchanged; `spec/schemas` untouched).

## Log
- 2026-10-09T04:51:58Z connor: created
