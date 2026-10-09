---
id: "REC-P0P1.3"
title: "Recovery wire schemas, vectors and Rust codegen"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["REC-P0P1.1", "UR-G0-SPECTOOL.1"]
paths: ["spec/schemas/chio-wire/v1/recovery/**", "spec/vectors/recovery/v1/**", "spec/scripts/generate-recovery-authority-corpus*.py", "crates/core/chio-core-types/src/_generated/**", "crates/tooling/chio-spec-codegen/src/schema_catalog.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method (applies to every REC-P0P1 slice): do not run `git rebase`. Re-land from the frozen #1179 source `f217de1fb` (PR head; the roadmap pin 491bd01b5 is stale) onto `integration/beta-next` by path: `git checkout f217de1fb -- <slice globs>`, then repair against #1160's code, and record the slice's source-manifest digest in `docs/architecture/recoverable-agent-runtime/implementation/REBASE-MANIFEST.json` (created by REC-P0P1.0). Keep each slice compiling: new kernel trait methods land with fail-closed default bodies (#1160 precedent `store.rs:874`); `recovery_authority()` returns `None` until the store slices land. Never hand-merge `_generated` files (REC-P0P1.17 regenerates). Roadmap Lane REC requirements this lane must meet: rebase onto #1160's paged sweep rather than porting the old loop; adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24); adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16); fix KDEF-N15 (wall-clock time in authority evidence); fix every open P1; take schema slots through the ledger lock; regenerate the SDKs. The #1179 rebase is one of the two riskiest pieces in the roadmap and gets the earliest prototype. 84 recovery schemas and 18 vectors. Schemas under `chio-wire/v1` feed codegen into four language outputs; this slice regenerates the Rust output only (REC-P0P1.17 does the rest). Regenerate `spec/schemas/MANIFEST.sha256` with `--write`; never hand-merge registry or manifest files.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo xtask codegen --lang rust --check`, `bash scripts/check-chio-schema-registry.sh` and `cargo test -p chio-core-types --test recovery_digest_inventory` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
