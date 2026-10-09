---
id: "SSE-CR-SPLIT"
title: "SSE parser ignores lone CR line ends, letting a provider hide data lines from inspection"
severity: "P2"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: []
paths: ["crates/protocol/chio-provider-adapter-core/src/sse.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 3
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Pre-existing on main, found during the #1160 review (protocol/products reviewer). `crates/protocol/chio-provider-adapter-core/src/sse.rs` (locate the module by name if the path differs) splits server-sent-event lines only on LF, while SSE clients also treat a lone CR as a line end. A malicious provider can put a `data:` line after a lone CR inside what Chio parses as a comment: Chio skips it, but the raw bytes are forwarded and the client receives it as data, so a tool call can bypass Chio's inspection.

## Acceptance

- The parser treats CRLF, LF and lone CR as line terminators per the SSE specification.
- A regression test with a lone-CR smuggled data line fails before the fix and passes after.
- Forwarded bytes match what Chio inspected (no parse-forward mismatch).
- The crate's tests and strict Clippy pass.

## Log
- 2026-10-09T04:28:59Z connor: created
