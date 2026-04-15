# Summary 317-19

Phase `317` then removed the remaining `arc-core` wildcard compatibility
facade modules.

The implemented refactor updated:

- `crates/arc-core/src/lib.rs`

and deleted the one-line wildcard facade modules for:

- `appraisal`
- `autonomy`
- `canonical`
- `capability`
- `credit`
- `crypto`
- `error`
- `federation`
- `governance`
- `hashing`
- `listing`
- `manifest`
- `market`
- `merkle`
- `message`
- `open_market`
- `receipt`
- `session`
- `underwriting`
- `web3`

Verification that passed during this wave:

- `cargo fmt -p arc-core`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave19-core cargo test -p arc-core --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave19-workflow cargo check -p arc-workflow`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave19-settle cargo check -p arc-settle`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave19-reputation cargo check -p arc-reputation`
- `rg -n 'pub use .*\\*;|pub use [A-Za-z0-9_:]+::\\*;' crates/arc-core-types crates/arc-core`
- `git diff --check -- crates/arc-core/src/lib.rs`

This wave replaced the `arc-core` one-line wildcard facade modules with direct
crate/module re-exports at the crate root, preserving the public
`arc_core::<module>::...` surface without keeping local wildcard wrapper files.

The wildcard export gap is now narrowed to `arc-core-types/src/lib.rs`.
