---
id: "CT-WORK.3"
title: "Agreement variant including unpaid work (D5)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-WORK.2"]
paths: ["spec/schemas/chio-work/v1/agreement.schema.json", "tests/bindings/vectors/work/agreement-v1.json", "spec/CHIO_WORK.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 6.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-WORK, D5 ("add an unpaid `Agreement` variant to `chio.work.v1`"; parked UR-D5 records it). #1173's spec has a funded-only `Agreement { commitment, funding_profile_id, terms_reference }`. Define `Agreement { commitment, terms_reference, funding: Unpaid | Funded { funding_profile_id, WorkFundingRefV1 } }`: unpaid work uses D1 `Acceptance::check` through kernel-receipted evaluation, has no reserve, and reports settlement `NotApplicable`. This keeps CT-SETTLE off the success-test path. Append the Agreement section to `spec/CHIO_WORK.md` with a small edit after CT-WORK.1 has merged.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Vectors `unpaid_agreement_has_no_reserve_reference` and `funded_agreement_requires_funding_ref` pass in `cargo test -p chio-spec-validate --test work_v1`.

## Log
- 2026-10-09T04:51:58Z connor: created
