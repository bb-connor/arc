# Summary 186-03

Phase `186-03` qualified the supervised-live intake path against the existing
pilot verifier expectations:

- [cli.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury/tests/cli.rs) now verifies that supervised-live export preserves source-record continuity and that both the pilot and supervised-live paths still verify through the same CLI surface
- [supervised_live.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/supervised_live.rs) now includes contract tests for the required live-ingestion continuity fields
- the targeted Mercury checks and tests now pass for both the new capture flow and the existing pilot path
