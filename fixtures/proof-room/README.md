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

### Runtime fixture parity

The recursive runtime fixture qualifies one fresh physical source and executes its admissions once. Its generator independently assembles the proof twice from the retained signed receipts and evidence for that qualified source. Both assemblies must pass the verifier, have zero semantic mismatches, and produce byte-identical artifacts. The committed package is also verified independently by the static fixture consumer tests.

Parity is scoped to that qualified source. A fresh SQLite source has a different physical identity and qualification digest, which changes the operation plan and signed receipts. Cross-store byte equality is not a v1 property. Generation preserves those bindings and does not reset custody or repeat tool effects to reproduce receipt bytes.
