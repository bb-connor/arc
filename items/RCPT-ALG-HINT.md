---
id: "RCPT-ALG-HINT"
title: "Receipt verification must reject a present algorithm hint that does not match the signature (PROTOCOL.md 983-985)"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/core/chio-core-types/src/receipt/body.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 3
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Found by Codex's cross-vendor review of PR #1171 (2026-10-09). `spec/PROTOCOL.md` lines 983-985 require every present receipt `algorithm` hint to match the signature prefix. The hint is unsigned, and the ordinary verification helper (`crates/core/chio-core-types/src/receipt/body.rs` around lines 479-494 on main) accepts a valid Ed25519 receipt with `algorithm: "p256"` added; only the floor-aware helper (lines 521-528) checks it. Make every verification path reject a present hint that does not match the signature algorithm, fail closed.

## Acceptance

- A regression test with a valid Ed25519 receipt carrying a mismatched `algorithm` hint fails before the fix and is rejected after it, on every public verify path.
- Receipts without a hint and with a matching hint still verify.
- The crate's tests and strict Clippy pass.

## Log
- 2026-10-09T09:37:53Z connor: created
