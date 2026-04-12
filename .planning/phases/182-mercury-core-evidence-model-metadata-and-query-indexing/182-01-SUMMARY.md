# Summary 182-01

Phase `182-01` introduced `arc-mercury-core` as the typed contract layer for
MERCURY evidence on top of ARC truth:

- [Cargo.toml](/Users/connor/Medica/backbay/standalone/arc/Cargo.toml) now includes `crates/arc-mercury-core` in the workspace
- [crates/arc-mercury-core/src/receipt_metadata.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/receipt_metadata.rs) defines typed `receipt.metadata.mercury` contracts for business IDs, chronology, provenance, sensitivity, disclosure, and approval state
- [crates/arc-mercury-core/src/bundle.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/bundle.rs) adds bundle-manifest, artifact-reference, and hashing helpers for later proof-package work
- [crates/arc-mercury-core/src/query.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/query.rs) and [crates/arc-mercury-core/src/fixtures.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/fixtures.rs) provide the extracted query record and fixture corpus used by later phases
