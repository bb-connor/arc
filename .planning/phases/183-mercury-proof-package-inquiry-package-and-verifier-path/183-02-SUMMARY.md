# Summary 183-02

Phase `183-02` added the reviewed-export contract on top of the proof package:

- [crates/arc-mercury-core/src/proof_package.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/proof_package.rs) now defines `Inquiry Package v1`, rendered-export digest validation, and verifier-equivalence reporting
- [crates/arc-mercury-core/src/lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/lib.rs) re-exports the proof, inquiry, publication-profile, and verification report contracts for downstream use
- [crates/arc-cli/tests/evidence_export.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/tests/evidence_export.rs) now builds a real ARC evidence package, exports a MERCURY proof package, derives an inquiry package, and verifies both end to end
