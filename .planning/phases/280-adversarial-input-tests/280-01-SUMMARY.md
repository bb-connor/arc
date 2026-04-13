# Summary 280-01

Phase `280-01` added black-box adversarial transport coverage for the real ARC
wire protocol:

- [adversarial_inputs.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/tests/adversarial_inputs.rs) now proves malformed canonical JSON, zero-length bodies, truncated frames, missing required fields, and wrong-type payloads all return typed transport errors without crashing
- The tests exercise `ArcTransport::recv()` and `read_frame()` directly, so the coverage sits on the real byte boundary rather than on mocked parser helpers

Verification:

- `cargo test -p arc-kernel --test adversarial_inputs -- --nocapture`
- `cargo fmt --all -- --check`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs verify plan-structure .planning/phases/280-adversarial-input-tests/280-01-PLAN.md`
