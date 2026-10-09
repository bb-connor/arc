---
id: "REL-1.SALVAGE-1056"
title: "Salvage #1056: mirror sync to backbay-labs/chio on every tag"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-REL.1", "UR-LEDGER-CARRY"]
paths: ["scripts/mirror-to-chio.sh", "scripts/tests/mirror-to-chio.test.sh", ".github/workflows/mirror-to-chio.yml"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 7 (#1056: salvage into REL-1 as the distribution mirror sync), D7. Source: PR #1056 (ref `origin/chore/mirror-to-chio`, one file). The script pushes `main` only, reconciles LFS by object ID, refuses non-ancestor pushes and verifies commit and tree. Extend it to push channel tags as exact tag objects, keep the ancestor guard, and report but never delete mirror-only refs (`agentic-os-2026-09-10-9ffca8d6`, `archive/pre-mirror`). The workflow triggers on channel tag and main pushes. The mirror push credential is an owner-provisioned secret (serialization point). Today the mirror's main is 52 commits behind and fast-forwardable.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `bash scripts/tests/mirror-to-chio.test.sh` with local bare repos covers: behind pushes, current no-ops, forked exits 1, new tag pushed and verified, off-channel tag refused, mirror-only tag left intact.
- `shellcheck` and `actionlint` clean.

## Log
- 2026-10-09T04:51:58Z connor: created
