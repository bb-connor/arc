---
id: "REL-2.1"
title: "MCP edge and adapter negotiate 2025-11-25 and 2026-07-28"
severity: "P1"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["REL-2.0", "REL-1.SALVAGE-1046", "CT-ABI.2"]
paths: ["crates/protocol/chio-mcp-edge/src/runtime.rs", "crates/protocol/chio-mcp-edge/src/runtime/jsonrpc.rs", "crates/protocol/chio-mcp-edge/src/runtime/protocol/**", "spec/versions/chio-protocol-negotiation.v1.json", "spec/WIRE_PROTOCOL.md", "crates/protocol/chio-mcp-adapter/src/transport/utils.rs", "crates/protocol/chio-mcp-adapter/src/transport.rs", "crates/protocol/chio-mcp-edge/tests/protocol_versions.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: REL-2 ("interop with MCP revision 2026-07-28 (stateless core); today the edge accepts only 2025-11-25"). Replace the single `MCP_PROTOCOL_VERSION` constants with a supported-version set and negotiation, implement the stateless-core request handling the research note (REL-2.0) specifies, and keep 2025-11-25 working. Also carry #1046's ledger row `inherited-thread:r3695800375` ("Update the authoritative negotiation artifact": `spec/versions/chio-protocol-negotiation.v1.json`, `spec/WIRE_PROTOCOL.md:271-285`); today `runtime.rs:93` and `runtime/jsonrpc.rs:68` reject anything but 2025-11-25. Every request is still authorized or denied before effect with a signed receipt; an unknown version fails closed with a protocol error. Also update the hardcoded version in `crates/products/chio-cli/src/cli/mcp/wrap.rs` and `crates/products/chio-cli/src/cli/mcp/provision/discovery/transport.rs` only if the note says the CLI must offer the new version (list them in the PR; they are outside this item's lease, so coordinate). Boundary: `prevent` (G1 claim, CT-WIRE).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `crates/protocol/chio-mcp-edge/tests/protocol_versions.rs`: `initialize_negotiates_2025_11_25`, `stateless_request_2026_07_28_is_admitted_with_receipt`, `unknown_protocol_version_fails_closed`, `deny_receipt_emitted_for_stateless_denied_call`.
- `cargo test -p chio-mcp-edge` and `cargo test -p chio-mcp-adapter` pass.

## Log
- 2026-10-09T04:51:58Z connor: created
