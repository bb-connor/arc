---
id: "CT-REL.2"
title: "Encode the preview channel and preview exception in the release gate (fail closed)"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-REL.1", "REL-1.SALVAGE-1073"]
paths: ["scripts/check-release-source-gates.py", "scripts/tests/check-release-source-gates.test.py"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: CT-REL, D8. #1160's landing boundary (`docs/security/audits/foundation-landing-boundary-20261008.json`, `post_merge_pre_release_requirements`, `"release_permitted": false`) forbids any tag before three obligations pass: `trusted-35-campaign-capture`, `per-pr-security-app-enforcement`, `native-mini-swe-and-cold-platform-acceptance`. Teach the release gate: preview-channel tags require either a valid preview-exception record bound to the source SHA (created only if the owner records D8, which must also be appended to the landing ledger because it overrides the 2026-10-08 ruling) or evidence for all three obligations; non-preview tags always require the obligations; off-channel tags are refused. Without an exception record the gate behaves exactly like today (fail closed).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- New tests: `test_preview_tag_requires_exception_record_or_obligations`, `test_stable_tag_requires_postmerge_evidence`, `test_offchannel_tag_refused`, `test_exception_record_bound_to_other_sha_refused`.
- `python3 scripts/check-security-landing-ledger.py` still passes.

## Log
- 2026-10-09T04:51:58Z connor: created
