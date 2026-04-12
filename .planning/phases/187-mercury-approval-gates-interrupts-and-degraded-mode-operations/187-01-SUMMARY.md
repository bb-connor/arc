# Summary 187-01

Phase `187-01` added a typed supervised-live control-state contract and bound
it to export readiness:

- [supervised_live.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/supervised_live.rs) now defines explicit release and rollback gates, coverage state, evidence-health state, and interruption records for supervised-live captures
- [lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/lib.rs) now exports the control-state types from `arc-mercury-core`
- [commands.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury/src/commands.rs) now requires export-ready control state and includes that control summary in `supervised-live-summary.json`
