---
id: "REL-1.1"
title: "Release workflows conform to the preview channel"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-REL.1"]
paths: [".github/workflows/release-binaries.yml", ".github/workflows/release-tagged.yml", ".github/workflows/sbom.yml", "scripts/tests/ci-release-assurance.test.sh"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-1 (signed binaries for Linux x86_64 and arm64 and macOS arm64 already exist in `release-binaries.yml`: cargo-auditable builds, SBOMs, cosign keyless signatures, SLSA, drafts with `make_latest: false`). Refuse tags outside the CT-REL regex; render preview release notes with the preview label, the ADR-0011 claim table and a link to the format-stability note (CT-WIRE.5); repoint `release-tagged.yml:34,125` from the to-be-archived `project/roadmap-04-25-2026` branch to `main`; make scheduled `sbom.yml` pick the latest published release instead of the highest `v*.*.*` tag (today the stray `v3.20.0-trj4`).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `bash scripts/tests/ci-release-assurance.test.sh` with new cases for stray-tag refusal and the preview-notes label; `bash scripts/tests/check-sidecar-image-workflow.test.sh` and `actionlint` pass.
- `git grep -n roadmap-04-25-2026 .github/workflows` returns nothing.

## Log
- 2026-10-09T04:51:58Z connor: created
