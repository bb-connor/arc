---
id: "WORK-W3.2c"
title: "W3: TypeScript WorkClient wrapper in @chio-protocol/process"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W3.2a"]
paths: ["sdks/typescript/packages/process/work.mjs", "sdks/typescript/packages/process/work.d.ts", "sdks/typescript/packages/process/test/work.test.mjs", "sdks/typescript/packages/process/package.json"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Plans and specs (landed by WORK-SLICE-C.1): `docs/superpowers/plans/2026-10-03-work-runtime.md`, `2026-10-03-work-owner-services.md`, `2026-10-03-work-developer-surface.md`; specs `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `work-owner-services-design.md`, `work-developer-surface-design.md`, `agentic-work-kernel-design.md`; real constructor inventory in `docs/research/work-abstraction/INTEGRATION.md` (WORK-W1.0). Lossless wide integers; never a JavaScript Number for signed values.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `npm test` in `sdks/typescript/packages/process` passes against CT-WORK vectors.

## Log
- 2026-10-09T04:51:58Z connor: created
