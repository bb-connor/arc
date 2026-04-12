# Summary 186-02

Phase `186-02` preserved source and bundle continuity from supervised-live
intake into the existing proof contracts:

- [supervised_live.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/supervised_live.rs) now requires `source_record_id`, `idempotency_key`, and workflow-aligned bundle manifests for supervised-live captures
- [commands.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury/src/commands.rs) reuses the same receipt-store, checkpoint, evidence-export, proof-package, and inquiry-package builders instead of creating a parallel live-only path
- [TECHNICAL_ARCHITECTURE.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/TECHNICAL_ARCHITECTURE.md) now documents the supervised-live capture contract and the continuity fields that must survive into later review
