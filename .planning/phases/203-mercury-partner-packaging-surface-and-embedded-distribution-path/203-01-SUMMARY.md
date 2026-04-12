# Summary 203-01

Phase `203-01` added the repo-native Mercury surface for embedded OEM work:

- [main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury/src/main.rs) now exposes `embedded-oem export` and `embedded-oem validate`
- [commands.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury/src/commands.rs) now wires the corresponding command handlers
- the new surface remains Mercury-specific and layered on top of existing Mercury exports
