# Summary 182-03

Phase `182-03` wired the typed MERCURY query model through ARC's local and
remote receipt-query surfaces:

- [crates/arc-kernel/src/receipt_query.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/receipt_query.rs) now carries MERCURY business-identifier and approval-state filters
- [crates/arc-cli/src/main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/main.rs) exposes the same filters through `arc receipt list`
- [crates/arc-cli/src/trust_control.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/trust_control.rs) exposes the same filter contract through trust-control HTTP query handling
- [crates/arc-store-sqlite/src/receipt_query.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-store-sqlite/src/receipt_query.rs), [crates/arc-kernel/src/evidence_export.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/evidence_export.rs), and [crates/arc-kernel/src/operator_report.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/operator_report.rs) now compile and test against the widened query contract
