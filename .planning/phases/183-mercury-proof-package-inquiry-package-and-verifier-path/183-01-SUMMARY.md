# Summary 183-01

Phase `183-01` turned MERCURY's proof-package contract into a strict wrapper
over verified ARC evidence export truth:

- [crates/arc-mercury-core/src/proof_package.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/proof_package.rs) defines `Publication Profile v1`, `Proof Package v1`, receipt-summary records, and ARC-bundle integrity verification
- [crates/arc-mercury-core/src/receipt_metadata.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/receipt_metadata.rs) adds explicit validation-error support so package assembly fails closed on malformed MERCURY metadata
- [crates/arc-cli/src/evidence_export.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/evidence_export.rs) now exposes a verified ARC evidence-package summary that includes the manifest hash, schema, and export timestamp needed to bind the proof package to ARC truth
