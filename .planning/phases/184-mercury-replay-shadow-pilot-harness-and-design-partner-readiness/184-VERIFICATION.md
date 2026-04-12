---
status: passed
---

# Phase 184 Verification

## Outcome

Phase `184` makes MERCURY's first workflow demonstrable and externally legible
without widening the product boundary. The repo now ships an executable pilot
corpus generator, a gold primary proof-plus-inquiry path, a rollback proof
variant, evaluator-facing runbooks, and an explicit supervised-live bridge
decision for what happens after the pilot.

## Evidence

- [crates/arc-mercury-core/src/pilot.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/pilot.rs)
- [crates/arc-mercury-core/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/lib.rs)
- [crates/arc-cli/src/mercury.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/mercury.rs)
- [crates/arc-cli/src/main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/main.rs)
- [crates/arc-cli/tests/mercury.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/tests/mercury.rs)
- [docs/mercury/PILOT_RUNBOOK.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/PILOT_RUNBOOK.md)
- [docs/mercury/DEMO_STORYBOARD.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/DEMO_STORYBOARD.md)
- [docs/mercury/EVALUATOR_VERIFICATION_FLOW.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/EVALUATOR_VERIFICATION_FLOW.md)
- [docs/mercury/SUPERVISED_LIVE_BRIDGE.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/SUPERVISED_LIVE_BRIDGE.md)
- [v2.43-MILESTONE-AUDIT.md](/Users/connor/Medica/backbay/standalone/arc/.planning/v2.43-MILESTONE-AUDIT.md)

## Validation

- `cargo check -p arc-mercury-core -p arc-cli`
- `cargo test -p arc-mercury-core`
- `cargo test -p arc-cli mercury_proof_and_inquiry_packages_export_and_verify --test evidence_export`
- `cargo test -p arc-cli mercury_pilot_export_writes_primary_and_rollback_corpus --test mercury`
- `git diff --check`

## Requirement Closure

- `MERC-05` complete

## Next Step

`v2.43` is complete locally. The next work, if scheduled, should be the
explicit supervised-live bridge for the same workflow rather than a broader
connector or product-surface expansion.
