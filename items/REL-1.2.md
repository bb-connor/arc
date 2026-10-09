---
id: "REL-1.2"
title: "Green Release Qualification on post-#1160 main (fix Aeneas snapshot drift)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-1.SALVAGE-1073"]
paths: ["formal/lean4/Chio/FormalAeneas/**", "scripts/check-aeneas-production.sh", "scripts/snapshot-aeneas-generated.sh"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-1 (preview train), KERN-6 (KDEF-GT1: one whole hosted CI run passes). Release Qualification has failed on every main push since 2026-10-04; the latest failure on `002b4d14e` is `aeneas-equivalence: GENERATED SNAPSHOT DRIFT` against `formal/lean4/Chio/FormalAeneas/Funs.lean` after about 70 minutes. `scripts/check-release-source-gates.py` requires a green Release Qualification at the exact tag SHA, so no tag can be staged until this is fixed. Reproduce on the first post-merge main push, review the generated semantics, regenerate with `scripts/snapshot-aeneas-generated.sh`, and fix any further `qualify-release.sh` failures (narrow `paths` to the failing lane scripts at claim time and say so in the PR). Hosted CI is a serialization point: coordinate runs with KDEF-GT1.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- A `release-qualification.yml` push run on main concludes `success`, with `ci.yml`, `cargo-vet` and `cve-monitor` successes at the same SHA; run IDs recorded in the PR.

## Log
- 2026-10-09T04:51:58Z connor: created
