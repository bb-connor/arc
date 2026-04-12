# Summary 184-01

Phase `184-01` turned the Phase 0-1 pilot from a document-level plan into an
executable corpus generator:

- [crates/arc-mercury-core/src/pilot.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/pilot.rs) defines the gold primary workflow plus rollback variant for the first MERCURY corpus
- [crates/arc-mercury-core/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/lib.rs) re-exports the pilot scenario contract so it stays in the Mercury-specific layer rather than drifting into ARC-generic code
- [crates/arc-cli/src/mercury.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/mercury.rs) now implements `arc mercury pilot export`, which generates the scenario, receipt DBs, ARC evidence packages, proof packages, inquiry packages, and verification reports for both primary and rollback paths
- [crates/arc-cli/tests/mercury.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/tests/mercury.rs) validates that the pilot command emits the expected corpus and verification artifacts
