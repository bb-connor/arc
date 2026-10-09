---
id: "REL-1.3"
title: "Version tooling and the 0.2.0-alpha.N bump"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-1.SALVAGE-1046", "CT-REL.1"]
paths: ["xtask/src/release_version.rs", "xtask/src/main.rs", "xtask/src/dispatch.rs", "Cargo.toml", "Cargo.lock"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-1, CT-REL. The workspace is `version = "0.1.0"` (`Cargo.toml:257-262`) and no tooling bumps versions or picks an alpha number. Add `cargo xtask release set-version <ver>` that rewrites `workspace.package.version` and every exact `=` pin, refuses off-channel versions, and regenerates the lock. Apply `0.2.0-alpha.1`. SDK package versions are out of scope.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p xtask release_version`; `cargo build --workspace --locked`; `cargo xtask release rust-preview --out <tmpdir>` succeeds at the new version.

## Log
- 2026-10-09T04:51:58Z connor: created
