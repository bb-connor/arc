---
id: "REC-P0P1.17"
title: "Regenerate SDKs from the recovery schemas (no hand merges)"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.3", "REC-P0P1.16"]
paths: ["xtask/src/codegen/**", "crates/tooling/chio-spec-codegen/src/**", "sdks/python/chio-sdk-python/src/chio_sdk/_generated/**", "sdks/typescript/packages/conformance/src/_generated/**", "sdks/typescript/packages/node-http/src/_generated/**", "sdks/go/chio-go-http/types.go", "crates/core/chio-errors/src/_generated/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. Roadmap: "regenerate the SDKs rather than merging 161 generated files by hand". #1179 touches 255 generated files and changes the generators (`xtask/src/codegen/python_{api_stability,publish,recovery_models,utf8_models}.rs`, `schema_catalog.rs`). Port the generator changes, then run `cargo xtask codegen --lang <rust|ts|go|python>`. `crates/core/chio-errors/src/_generated` is also a generator output.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `make codegen-check` and `scripts/spec-drift-check.sh` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
