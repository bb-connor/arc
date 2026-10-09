---
id: "UR-U10"
title: "In-repo deprecation notices for stale v0.1.x artifacts"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/install/README.md", "docs/install/BINARY_DISTRIBUTION.md", "docs/install/VERIFY.md", "docs/install/homebrew.md", "CHANGELOG.md", "releases.toml"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: U10 ("add deprecation notices to the stale installer and registry artifacts now, and replace them at G1"), REL-1 ("Fix CHANGELOG.md and the install docs"), section 2 "Distribution today". State that v0.1.0 (in both `bb-connor/arc` and `backbay-labs/chio`), crates.io `chio-*` 0.1.0/0.1.2, npm `@chio-protocol/*` 0.1.0 and PyPI `chio-sdk` 0.1.0 are superseded and unsupported, and that PyPI `chio` is an unrelated project. Fix `docs/install/README.md:20-27` ("mirror had no GitHub Releases", stale since the mirror's v0.1.0), `CHANGELOG.md:8-16` and `releases.toml:383-391` ("unreleased"). Do not edit `README.md` (UR-U3.1 owns it and fixes the `README.md:260` clone target) or `docs/install/PROCESS_PREVIEW.md` (REL-1.SALVAGE-1155 owns it). External notices (website installer, release flags, registry yanks) are parked (UR-PK-STALE-EXTERNAL, UR-D10).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/tests/release-identity.test.py` passes and the `release-identity-check.yml` workflow is green.
- `git grep -n "not yet been tagged" CHANGELOG.md` and `git grep -n "had no GitHub Releases" docs/install` return nothing.

## Log
- 2026-10-09T04:51:58Z connor: created
