# Summary 207-01

Phase `207-01` added the repo-native Mercury surface for trust-network work:

- [main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury/src/main.rs) now exposes `trust-network export` and `trust-network validate`
- [commands.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury/src/commands.rs) now wires the corresponding command handlers
- the new surface remains Mercury-specific and layered on top of the embedded-OEM lane
