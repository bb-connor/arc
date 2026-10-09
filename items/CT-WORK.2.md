---
id: "CT-WORK.2"
title: "`chio.work.v1` schemas and vectors (Agreement excluded)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-WORK.1", "UR-G0-SPECTOOL.1"]
paths: ["spec/schemas/chio-work/v1/**", "tests/bindings/vectors/work/v1.json", "crates/tooling/chio-spec-validate/tests/work_v1.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-WORK. Schemas for the closed envelope, preparation, submit, query, `WorkHandleV1` and `WorkViewV1` (manifest-only root, see UR-G0-SPECTOOL.1). Note: #1173 placed experimental `chio.experimental.native-funded-*` schemas in `spec/schemas/chio-work/{v1,v2}`; those are slice delta (after the test) and must move to an experimental directory when they land. The SDK generators read only `chio-wire/v1`, so WORK-W3 wrappers consume these vectors directly. Shared spec files: `spec/schemas/MANIFEST.sha256`, `spec/schemas/registry.json` and `spec/wire-schemas.lock` are touched by every schema-adding item. Do not hand-merge them: regenerate the manifest with `scripts/check-chio-schema-registry.sh --write` (UR-G0-SPECTOOL.1) at rebase and append registry and lock entries; the check train lands schema items one at a time.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-spec-validate --test work_v1` with negative cases: unknown variant, unknown or duplicate field, catalog page over 64 entries, handle without `receiver_kernel_id`, contradictory `Applied` results; `cargo xtask freeze-vectors --check` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
