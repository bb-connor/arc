# Summary 186-01

Phase `186-01` added the supervised-live intake contract and CLI export path
without redefining ARC truth:

- [supervised_live.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/supervised_live.rs) now defines `Supervised Live Capture v1` with `live` and `mirrored` modes over the same workflow
- [lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/lib.rs) now exports the new capture contract from `arc-mercury-core`
- [commands.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury/src/commands.rs) now exports supervised-live captures through the same ARC evidence-export and Mercury proof-package pipeline used by the pilot path
- [main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury/src/main.rs) now exposes `mercury supervised-live export --input ... --output ...`
