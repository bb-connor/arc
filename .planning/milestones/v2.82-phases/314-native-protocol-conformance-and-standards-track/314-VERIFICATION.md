---
phase: 314
status: passed
completed: 2026-04-13
---

# Phase 314 Verification

## Outcome

Phase `314` passed. ARC now has a dedicated native conformance lane with
language-neutral `artifact`, `stdio`, and `http` drivers, plus an IETF-style
Internet-Draft and a standards alignment matrix for the shipped protocol.

## Automated Verification

- `cargo test -p arc-conformance native_`
- `git diff --check -- crates/arc-conformance tests/conformance/native tests/conformance/README.md spec/ietf/draft-arc-protocol-00.md docs/standards/ARC_PROTOCOL_ALIGNMENT_MATRIX.md .planning/phases/314-native-protocol-conformance-and-standards-track`

## Evidence

- `tests/conformance/native/scenarios/` contains the required scenario
  categories for native ARC and adjacent governed/security behavior.
- `arc-native-conformance-runner` executes those JSON scenarios and writes JSON
  result artifacts plus a generated Markdown report.
- `arc-native-conformance-fixture` provides deterministic `stdio` and `http`
  targets used by the integration test.
- `spec/ietf/draft-arc-protocol-00.md` and
  `docs/standards/ARC_PROTOCOL_ALIGNMENT_MATRIX.md` provide the required
  standards-track documentation.

## Requirement Closure

- `SPEC-11`: the checked-in native suite covers capability validation,
  delegation attenuation, receipt integrity, revocation propagation, DPoP
  verification, and governed transaction enforcement.
- `SPEC-12`: the native suite is executable through JSON scenarios and
  language-neutral `artifact`, `stdio`, and `http` driver contracts.
- `SPEC-13`: an IETF-style Internet-Draft now captures the normative protocol
  shape in standards-track document form.
- `SPEC-14`: a standards alignment matrix now maps ARC concepts to GNAP,
  SCITT, RATS, RFC 9449, W3C VC, OID4VCI/VP, and RFC 8785.
