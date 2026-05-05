# TRJ4-033 Evidence - Mobile Threat Coverage

## PR1 status

Partial. PR1 adds deterministic fail-closed tests that exercise the mobile attestation replay classes, but does not flip threat-model JSON coverage because real-device fixtures are still absent.

## Deterministic coverage added

- App Attest replay and rollback behavior:
  - wrong challenge rejects with `app-attest-challenge-mismatch`
  - same-or-lower counter rejects with `app-attest-counter-rollback`
  - production path rejects missing x5c fail-closed
- Device key binding:
  - App Attest key id must match credential id from `authData`
  - mobile FFI rejects malformed App Attest evidence as `AttestationRejected`
- Play Integrity token replay:
  - wrong nonce rejects
  - expired token rejects
  - wrong audience rejects
  - downgraded token algorithm rejects

## Validation

- `cargo test -p chio-custody-hw -- --nocapture` passed.
- `cargo test -p chio-kernel-mobile --test ffi_roundtrip -- --nocapture` passed.
- `cargo clippy -p chio-kernel-mobile --lib --test ffi_roundtrip -- -D warnings` passed.

## Remaining gap

The threat-model rows `mobile_attestation_replay`, `device_key_extraction`, and `play_integrity_token_replay` remain pending in PR1. They should flip only after real App Attest and Play Integrity device fixtures are captured and wired into conformance tests.
