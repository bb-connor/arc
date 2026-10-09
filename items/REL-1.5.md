---
id: "REL-1.5"
title: "AWS-LC fork audit closeout for release lanes"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["docs/security/launch-status.md", "docs/security/rust-preview-packages.md", "scripts/check-aws-lc-fork.py", "scripts/tests/check-aws-lc-fork.test.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 5.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-1 ("The AWS-LC fork audit"). The audit has landed on #1160 (`docs/security/audits/aws-lc-rs-1.18.1-fork.md`, `aws-lc-rs-1.18.1-independent-review.md`, `supply-chain/aws-lc-rs-fork.json` status approved, `Cargo.toml:252-253` `[patch.crates-io]`); the M10 row in `docs/security/launch-status.md:66-67` is stale. Correct it, add a check that every release lane (`release-binaries.yml`, `sidecar-image.yml`, the rust-preview registry) resolves the fork, and record that crates.io publication would bypass the patch (input to D10). Whether agent-only reviews suffice for preview claims is an owner call: state it as an open question in the doc, do not decide it.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/tests/check-aws-lc-fork.test.py` with a new case refusing a registry-resolved `aws-lc-rs` in a release manifest; `bash scripts/check-supply-chain.sh` passes.

## Log
- 2026-10-09T04:51:58Z connor: created
