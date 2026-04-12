# Summary 183-03

Phase `183-03` shipped the first supported MERCURY verifier path through
`arc-cli`:

- [crates/arc-cli/src/main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/main.rs) adds the `mercury` command family with `proof export`, `inquiry export`, and `verify`
- [crates/arc-cli/src/mercury.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/mercury.rs) implements the package export helpers and the schema-aware verifier path
- the CLI remains thin on purpose: ARC evidence export stays canonical, `arc-mercury-core` owns the product contract, and `arc-cli` is only the first supported distribution surface
