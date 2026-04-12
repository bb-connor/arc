# Summary 211-01

Phase `211-01` created the dedicated ARC-Wall app surface:

- [Cargo.toml](/Users/connor/Medica/backbay/standalone/arc/crates/arc-wall/Cargo.toml) now defines the separate ARC-Wall package and binary
- [main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-wall/src/main.rs) now exposes `control-path export` and `control-path validate`
- [commands.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-wall/src/commands.rs) now keeps ARC-Wall implementation outside MERCURY
