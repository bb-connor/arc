---
id: "SEC-POSTMERGE.1"
title: "Prepare the 35-campaign trusted capture: shard cost rehearsal and qualification PR"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["scripts/run-security-execution-container.py", "scripts/aggregate-security-evidence-shards.py", "scripts/tests/security-evidence-shards.test.py", "docs/security/audits/postmerge-capture-prep-*.json"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.1 (#1160's post-merge, pre-release obligations scheduled in Lane REL), REL-1. Obligation `trusted-35-campaign-capture` (`docs/security/audits/foundation-landing-boundary-20261008.json`): run all 35 campaigns as the seven-shard trusted capture against frozen exact source, through `enterprise-evidence-controller.yml` (pull_request_target, owner-authored PR), `enterprise-linux-capture.yml` (shards 0-6, 360-minute timeout, `--timeout-seconds 21000`) and `enterprise-evidence-finalizer.yml` (environment `enterprise-evidence-signing`). Earlier, 6 of 35 campaigns took 16,644 seconds, so cost is a real risk. Run each `refresh-evidence-shard-N` locally on a Linux x86_64 host with `Dockerfile.security-evidence-runner`, measure against the cap, remove repeated cold compilation without weakening isolation, and prepare the owner's variable values (`CHIO_AUTHORIZED_SECURITY_SOURCE_SHA` and the others) and the minimal qualification PR text. The capture run itself is an owner operation (parked UR-PK-SEC-CAPTURE).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `python3 scripts/tests/security-evidence-shards.test.py` passes; measured per-shard wall time is under 21,000 s and recorded in the audit JSON with host details.

## Log
- 2026-10-09T04:51:58Z connor: created
