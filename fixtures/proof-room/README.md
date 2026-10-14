# Proof Room fixtures

Every directory listed in `catalog.json` is the output of
`chio proof fixture generate <id>` under the fixed fixture seeds and trust
profile in `crates/products/chio-cli/src/cli/dispatch/proof/`. Signed bytes in
this tree are never edited by hand.

After changing a fixture source, a generator, or a schema the fixtures carry,
rewrite the tree from the repository root:

```bash
cargo run -p chio-cli --bin chio -- proof fixture regenerate
```

Fixtures embed one another, so the command repeats passes until one changes
nothing. `--check` runs a single pass and fails, without writing, when any
fixture would change.
