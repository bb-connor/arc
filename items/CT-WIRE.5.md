---
id: "CT-WIRE.5"
title: "Publish the CT-WIRE freeze list and the format-stability note (G1)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-WIRE.2", "CT-WIRE.3", "CT-WIRE.4", "CT-ABI.4", "CT-WORK.3", "CT-REL.1", "CT-COOP.3", "CT-CTRL.3"]
paths: ["spec/versions/chio-preview-freeze.v0.json", "spec/FORMAT-STABILITY.md", "spec/schemas/COVERAGE.md", "spec/README.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G1 ("The CT-WIRE freeze list is published"), REL-1 ("Publish the format-stability note"), section 11 semver promise (covers wire and contract formats, `KERNEL_ABI_VERSION` and migrations; not the Rust API of `chio-kernel`, the hint channel or performance). Flip every inventory row to `frozen`, write `spec/FORMAT-STABILITY.md` (RFC 8785 canonicalization per `spec/PROTOCOL.md` section 4.1, signature domains, preview rule: frozen bytes change only through a new identifier with dual-read), refresh the stale `COVERAGE.md` (says 55 chio-wire schemas; 146 exist), and link from `spec/README.md`. Wire the publish check into CI via a one-line follow-up to UR-G0-CI.1's gate (`--publish` mode).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/check-preview-freeze.py --publish`, `bash scripts/check-chio-schema-registry.sh` and `python3 scripts/check-wire-schemas.py` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
