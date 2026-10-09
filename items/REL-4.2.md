---
id: "REL-4.2"
title: "Approval routes and dashboard approval panel"
severity: "P1"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-4.1"]
paths: ["crates/platform/chio-control-plane/src/trust_control/approval_handlers.rs", "crates/platform/chio-control-plane/src/trust_control/service_runtime/router/approvals.rs", "crates/products/chio-cli/dashboard/src/components/Approvals*.tsx"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-4 ("approval routes"). Expose pending approvals (the kernel already has approval channels: `crates/kernel/chio-kernel/src/approval_channels.rs`, threshold approval) through CT-CTRL-specified routes with the approver principal, and add an approvals panel to the dashboard that shows the exact request and capability being approved and records a signed decision bound to the approval ID (the defect class of `backbay-labs/chio-bridge#3`: a decision must check the recorded decision and approval ID). Register routes in the `approvals` router fragment created by COOP-1.1. This item also addresses KDEF-D7 (`ApprovalGuard`, `crates/kernel/chio-kernel/src/approval.rs:765`, has no production constructor) and KDEF-N6 (threshold collector lacks a production request-context source) as far as the approval routes need them.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Handler tests: approve and deny bind the approval ID and decision; replay and mismatched ID are rejected; viewer principal denied.
- Dashboard component tests for list, approve, deny states pass (`npm test`).

## Log
- 2026-10-09T04:51:58Z connor: created
