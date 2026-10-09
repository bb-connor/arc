---
id: "REL-1.8"
title: "Verifying installer for the preview channel"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-REL.1", "REL-1.1"]
paths: ["scripts/install.sh", "scripts/tests/install.test.sh", "docs/install/INSTALLER.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-1, U10 ("replace them at G1"), G1 (timed install through to a first receipt). No installer exists in this repo; the public `install.sh` is served from the docs site and resolves `latest` to v0.1.0, checking only a same-origin `.sha256`. Write `scripts/install.sh`: resolve the preview channel (never `Latest`), verify the `SHA256SUMS` cosign signature against the pinned `bb-connor/arc` identity (reuse `scripts/verify-release-identity.py` logic), verify the archive hash, refuse 0.1.x, install into a user prefix. Serving it from the website is an owner operation (parked UR-PK-STALE-EXTERNAL).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `bash scripts/tests/install.test.sh` with local signed fixtures covers a tampered archive, a wrong signing identity, a 0.1.0 refusal and a happy path into an empty prefix.

## Log
- 2026-10-09T04:51:58Z connor: created
