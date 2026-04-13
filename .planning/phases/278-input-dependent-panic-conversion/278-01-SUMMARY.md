# Summary 278-01

Phase `278-01` corrected the milestone to the transport surface ARC actually
ships:

- [transport.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/transport.rs) now normalizes EOF during frame-body reads to `TransportError::ConnectionClosed`, so half-sent frames fail with the same typed error as header-time disconnects
- [ROADMAP.md](/Users/connor/Medica/backbay/standalone/arc/.planning/ROADMAP.md) and [REQUIREMENTS.md](/Users/connor/Medica/backbay/standalone/arc/.planning/REQUIREMENTS.md) now describe ARC's length-prefixed canonical JSON `AgentMessage` protocol and the audit-confirmed absence of live production literal panic conversions

Verification:

- `cargo test -p arc-kernel --test adversarial_inputs -- --nocapture`
- `cargo test -p arc-kernel transport::tests::transport_agent_message_roundtrip -- --nocapture`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs verify plan-structure .planning/phases/278-input-dependent-panic-conversion/278-01-PLAN.md`
