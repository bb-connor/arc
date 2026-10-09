---
id: "KDEF-GT1"
title: "One whole hosted CI run passes on post-#1160 main"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["scripts/check-stub-surfaces.py", "scripts/ci-workspace.sh", "sdks/python/**/pyproject.toml", "docs/security/ci-gt1-*.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-6 (KDEF-GT1 / N5: "one whole hosted CI run passes"). On #1160 head these jobs failed: "Build, lint, test" (step "Stub surface hygiene"), "MSRV build and test" (step "MSRV workspace lane"), "Security contract", "Native host and protocol tests" (step "Python integration style"), "MCP process host and enforced native recovery", "Installed native consumer recovery", "attest exact pull request merge binding", "dispatch isolated enterprise Linux capture"; cargo-vet and cargo-deny passed. Fix or properly scope every failing job so one hosted run of `ci.yml` and its called workflows concludes success or a documented, reviewed skip. `.github/workflows/ci.yml` gates may not be weakened. The enterprise-capture and merge-binding jobs may need #1160's trusted-capture infrastructure (owner operations, parked UR-PK-SEC-CAPTURE); if so, document them and record the scoping decision for the owner rather than disabling them. Narrow `paths` at claim time to the actual failing scripts. Hosted CI is a serialization point; coordinate with REL-1.2.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- A hosted run URL and SHA where every required job passes is recorded in the KDEF register (N5 closed) and in `docs/security/ci-gt1-<date>.md`.
- No required check was removed or marked `continue-on-error`.

## Log
- 2026-10-09T04:51:58Z connor: created
