# Summary 182-02

Phase `182-02` extended SQLite persistence so MERCURY investigation flows do
not depend on raw JSON scans:

- [crates/arc-store-sqlite/src/receipt_store.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-store-sqlite/src/receipt_store.rs) now validates `receipt.metadata.mercury` on insert, mirrors the extracted fields into `mercury_receipt_index`, and backfills the index for existing receipt rows
- the new index table stores workflow, account, desk, strategy, release, rollback, exception, inquiry, decision-type, and approval-state fields keyed by `receipt_id`
- malformed MERCURY metadata now fails closed during persistence instead of creating partial or silently divergent index state
