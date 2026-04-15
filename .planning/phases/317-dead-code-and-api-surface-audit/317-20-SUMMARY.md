# Summary 317-20

Phase `317` then closed the remaining wildcard export gap by replacing the
`arc-core-types` crate-root wildcard re-exports with an explicit allowlist.

The implemented refactor updated:

- `crates/arc-core-types/src/lib.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-core-types`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave20-core-types cargo test -p arc-core-types --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave20-core cargo check -p arc-core`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave20-http cargo check -p arc-http-core`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave20-openapi cargo check -p arc-openapi`
- `rg -n 'pub use .*\\*;|pub use [A-Za-z0-9_:]+::\\*;' crates/arc-core-types crates/arc-core`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**'`
- `git diff --check -- crates/arc-core-types/src/lib.rs crates/arc-core/src/lib.rs`

This wave preserved the existing root compatibility surface while removing the
last wildcard crate-root facade. With `arc-core` already converted to direct
module re-exports, phase `317` now satisfies both the oversized-signature and
public-surface cleanup goals.
