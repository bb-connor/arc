---
id: "UR-G0-LEDGER.1"
title: "Schema-slot ledger and checker (the ledger lock)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/security/schema-slot-ledger.json", "scripts/check-schema-slot-ledger.py", "scripts/tests/check-schema-slot-ledger.test.py", "docs/security/landing-ledger.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.2 ("admission-store versions are assigned in landing order, at merge time, under a lock recorded in the #1160 landing ledger; branches use symbolic version names until they rebase"; no static reservations), decision D3 (recommended option; parked UR-D3 records it). Facts: versions live per store key in `chio_store_schema_versions` (`crates/platform/chio-store-sqlite/src/schema_version.rs:73`); #1160 has 22 store keys; admission is `ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION = 36` (`admission_operation_store.rs:229-230`); tool_outcome is v4. #1160 used admission v35/v36 for deferrals and participant checkpoint; #1173 claims v35/v36 for unknown release and capture waiver and tool_outcome v4 for execution evidence; #1179 claims admission v35 to v40 and hard-codes 41. The roadmap's "#1179 takes v39 to v45" is itself a static reservation and is not used.

Create `docs/security/schema-slot-ledger.json` (schema `chio.schema-slot-ledger.v1`) with sections `stores` (store_key, source constant, `landed[{slot,name,pr,merge_commit}]`, `pending[{name,pr}]`), ordered `global_projection_kinds`, `kernel_ops`, `process_abi`, and `lock {holder_pr, base_main, acquired_utc}` (at most one holder). Baseline: all 22 store keys at post-#1160 values as pre-lock history bound to the #1160 merge commit. Do NOT edit the 10 MB `docs/security/landing-ledger.json`; append a "Schema slot lock" section to `landing-ledger.md` that references the new file. Checker rules: dense unique slots; landed `merge_commit` is an ancestor of `origin/main`; each store's SUPPORTED constant equals max(landed) plus pending count; no integer literal above the landed max compared against a schema version or stamp anywhere in code (catches #1179's `!= 41`); `--landing` mode refuses pending entries.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/check-schema-slot-ledger.py` passes on post-#1160 main.
- `python3 scripts/tests/check-schema-slot-ledger.test.py` has failing fixtures for: duplicate slot, gap, future literal (`!= 41`), SUPPORTED mismatch, pending under `--landing`, non-ancestor merge commit, two lock holders.

## Log
- 2026-10-09T04:51:58Z connor: created
