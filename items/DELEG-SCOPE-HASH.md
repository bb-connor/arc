---
id: "DELEG-SCOPE-HASH"
title: "Decide and enforce scope_hash on every delegation hop (PROTOCOL.md 507-516 vs plain-chain compatibility)"
severity: "P2"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/core/chio-core-types/src/capability/token.rs", "crates/kernel/chio-kernel-core/src/capability_verify.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 4
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Found by Codex's cross-vendor review of PR #1171 (2026-10-09). `spec/PROTOCOL.md` lines 507-516 require a signed `scope_hash` on every delegation hop and reject chains that omit it, but the implementation accepts a correctly signed plain chain without them as compatibility behavior (`capability/token.rs` around 451-458, `capability_verify.rs` around 600-618). Either enforce the normative rule (with a migration note for any legacy tokens) or amend PROTOCOL.md through an ADR if plain chains are meant to stay valid; the IETF draft states the normative rule and records this gap under Implementation Status.

## Acceptance

- The spec and the verifier agree, with a test for a plain chain lacking scope_hash (rejected, or accepted under an explicit, documented compatibility rule).
- If behavior changes, existing token fixtures are updated and the change is noted.

## Log
- 2026-10-09T09:37:54Z connor: created
