---
phase: 378
milestone: v3.12
verified: 2026-04-14
verdict: pass
---

# Phase 378 Verification

Phase `378` passes after the latest local changes.

## Requirement Verdicts

- `EDGE-01`: Pass. `arc-a2a-edge` now routes the default live send/JSON-RPC paths through the ARC kernel via `handle_send_message(...)` and `handle_jsonrpc(...)` rather than direct adapter invocation. The old direct path remains only as explicitly named compatibility helpers: `handle_send_message_passthrough(...)` and `handle_jsonrpc_passthrough(...)`. Evidence: [crates/arc-a2a-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-a2a-edge/src/lib.rs:337), [crates/arc-a2a-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-a2a-edge/src/lib.rs:433), [crates/arc-a2a-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-a2a-edge/src/lib.rs:375), [crates/arc-a2a-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-a2a-edge/src/lib.rs:462).

- `EDGE-02`: Pass. The A2A kernel path emits signed receipt metadata with `authorityPath: "kernel"` and `authoritative: true`, while the explicit compatibility path emits truthful non-authoritative references with `authorityPath: "passthrough_compatibility"` and no receipt. Allow, deny, failed, and streaming cases are exercised in the crate tests. Evidence: [crates/arc-a2a-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-a2a-edge/src/lib.rs:690), [crates/arc-a2a-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-a2a-edge/src/lib.rs:733), [crates/arc-a2a-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-a2a-edge/src/lib.rs:747), [crates/arc-a2a-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-a2a-edge/src/lib.rs:1200), [crates/arc-a2a-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-a2a-edge/src/lib.rs:1226), [crates/arc-a2a-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-a2a-edge/src/lib.rs:1499), [crates/arc-a2a-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-a2a-edge/src/lib.rs:1535).

- `EDGE-03`: Pass. `arc-acp-edge` now uses kernel-backed defaults for outward `tool/invoke`, while `session/request_permission` is explicitly narrowed to a non-authoritative permission preview with metadata marking `authorityPath: "capability_preview"` and `authoritative: false`. Remaining non-kernel behavior exists only in explicitly named compatibility helpers and is marked `config_preview` / `passthrough_compatibility`, which excludes it from enforcement claims. Evidence: [crates/arc-acp-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-acp-edge/src/lib.rs:237), [crates/arc-acp-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-acp-edge/src/lib.rs:298), [crates/arc-acp-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-acp-edge/src/lib.rs:392), [crates/arc-acp-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-acp-edge/src/lib.rs:436), [crates/arc-acp-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-acp-edge/src/lib.rs:477), [crates/arc-acp-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-acp-edge/src/lib.rs:634), [crates/arc-acp-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-acp-edge/src/lib.rs:662), [crates/arc-acp-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-acp-edge/src/lib.rs:1177), [crates/arc-acp-edge/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-acp-edge/src/lib.rs:1273).

## Verification Notes

- I verified this by code inspection against the requirement language in [REQUIREMENTS.md](/Users/connor/Medica/backbay/standalone/arc/.planning/REQUIREMENTS.md:2903).
- I relied on the locally validated test fact you provided: `cargo test -p arc-a2a-edge -p arc-acp-edge` passed after these changes.

## Conclusion

Phase `378` is complete as implemented. The live outward A2A/ACP entrypoints now default to the kernel-backed path, and any remaining non-kernel behavior is explicitly labeled as non-authoritative compatibility or preview behavior.
