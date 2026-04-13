---
phase: 314-native-protocol-conformance-and-standards-track
created: 2026-04-13
status: complete
---

# Phase 314 Validation

## Required Evidence

- JSON native conformance scenarios exist for:
  - capability validation
  - delegation attenuation
  - receipt integrity
  - revocation propagation
  - DPoP verification
  - governed transaction enforcement
- The native suite can be executed by a third party through a language-neutral
  runner with `stdio` and `http` driver contracts.
- A checked-in Internet-Draft captures the normative ARC protocol in
  standards-track document shape.
- A checked-in standards alignment matrix maps ARC concepts to GNAP, SCITT,
  RATS, RFC 9449, W3C VC, OID4VCI/VP, and RFC 8785.

## Verification Commands

- `cargo test -p arc-conformance native_`
- `git diff --check -- crates/arc-conformance tests/conformance/native tests/conformance/README.md spec/ietf/draft-arc-protocol-00.md docs/standards/ARC_PROTOCOL_ALIGNMENT_MATRIX.md .planning/phases/314-native-protocol-conformance-and-standards-track`

## Regression Focus

- the new native lane does not break the existing Wave 1-5 MCP harness
- the native runner remains executable without requiring target implementations
  to link ARC Rust crates
- the standards docs stay bounded and aligned to the shipped ARC surfaces from
  phases `311`-`313`
