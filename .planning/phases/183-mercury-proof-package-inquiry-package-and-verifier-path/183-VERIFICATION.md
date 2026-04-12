---
status: passed
---

# Phase 183 Verification

## Outcome

Phase `183` freezes MERCURY's first portable proof surfaces without creating a
second truth contract. ARC evidence export remains canonical; `arc-mercury-core`
now wraps that truth into `Proof Package v1`, `Publication Profile v1`, and
`Inquiry Package v1`; and `arc-cli` ships the first supported export plus
verification path over those contracts.

## Evidence

- [crates/arc-mercury-core/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/lib.rs)
- [crates/arc-mercury-core/src/proof_package.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/proof_package.rs)
- [crates/arc-mercury-core/src/receipt_metadata.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/receipt_metadata.rs)
- [crates/arc-cli/src/evidence_export.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/evidence_export.rs)
- [crates/arc-cli/src/mercury.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/mercury.rs)
- [crates/arc-cli/src/main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/main.rs)
- [crates/arc-cli/tests/evidence_export.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/tests/evidence_export.rs)
- [PHASE_0_1_BUILD_CHECKLIST.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/PHASE_0_1_BUILD_CHECKLIST.md)
- [REQUIREMENTS.md](/Users/connor/Medica/backbay/standalone/arc/.planning/REQUIREMENTS.md)
- [ROADMAP.md](/Users/connor/Medica/backbay/standalone/arc/.planning/ROADMAP.md)
- [STATE.md](/Users/connor/Medica/backbay/standalone/arc/.planning/STATE.md)

## Validation

- `cargo check -p arc-mercury-core -p arc-cli`
- `cargo test -p arc-mercury-core`
- `cargo test -p arc-cli mercury_proof_and_inquiry_packages_export_and_verify --test evidence_export`
- `git diff --check`

## Requirement Closure

- `MERC-04` complete

## Next Step

Phase `184` can now build the replay/shadow pilot harness, generate the gold
workflow corpus, and publish the design-partner-ready pilot package on top of
the now-stable MERCURY proof contract.
