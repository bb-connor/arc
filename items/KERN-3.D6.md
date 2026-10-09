---
id: "KERN-3.D6"
title: "Overlay guards revalidate at dispatch (KDEF-D6)"
severity: "P2"
wave: 3
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["KERN-REGROUND"]
paths: ["crates/security/chio-security-kernel/src/containment.rs", "crates/security/chio-security-kernel/src/capability_set_suspension.rs", "crates/security/chio-security-kernel/src/egress_restriction.rs", "crates/security/chio-security-kernel/src/session_throttle.rs", "crates/security/chio-security-kernel/tests/overlay_revalidation.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 5.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: KERN-3 (KDEF-D6). `ContainmentGuard`, `CapabilitySetSuspensionGuard`, `EgressRestrictionGuard` and `SessionThrottleGuard` do not override `requires_dispatch_revalidation` (trait default at `crates/kernel/chio-kernel/src/kernel/mod.rs:889`, revalidation at `dispatch.rs:817`), so a suspension after admission does not deny at dispatch. Override it for each; the throttle guard must not consume a second token on revalidation.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Test "overlay revalidation denies after a late suspension"; chio-conformance active-defense case "suspend after admission" passes; throttle token count unchanged by revalidation.

## Log
- 2026-10-09T04:51:58Z connor: created
