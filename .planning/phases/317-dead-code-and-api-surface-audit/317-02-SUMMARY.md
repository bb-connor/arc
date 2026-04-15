# Summary 317-02

Phase `317` then took a bounded `too_many_arguments` slice in the shared
operations/reporting constructors inside `arc-anchor` and `arc-settle`.

The implemented refactor updated:

- `crates/arc-anchor/src/ops.rs`
- `crates/arc-anchor/src/lib.rs`
- `crates/arc-settle/src/ops.rs`
- `crates/arc-settle/src/lib.rs`
- `crates/arc-control-plane/tests/web3_ops_qualification.rs`

Verification that passed during this wave:

- `rustfmt --edition 2021 crates/arc-anchor/src/ops.rs crates/arc-settle/src/ops.rs crates/arc-anchor/src/lib.rs crates/arc-settle/src/lib.rs crates/arc-control-plane/tests/web3_ops_qualification.rs`
- `cargo check -p arc-anchor -p arc-settle`
- `cargo test -p arc-control-plane --test web3_ops_qualification --no-run`
- `git diff --check -- crates/arc-anchor/src/ops.rs crates/arc-settle/src/ops.rs crates/arc-anchor/src/lib.rs crates/arc-settle/src/lib.rs crates/arc-control-plane/tests/web3_ops_qualification.rs`

This wave removed four constructor-style
`#[allow(clippy::too_many_arguments)]` suppressions by replacing positional
argument lists with typed input structs:

- `AnchorIndexerCursor::from_sequences`
- `AnchorLaneRuntimeStatus::from_indexer`
- `SettlementIndexerCursor::from_blocks`
- `SettlementLaneRuntimeStatus::new`

The refactor keeps the public runtime-reporting behavior intact while making
call sites in the control-plane qualification test more explicit about which
fields belong to each constructor.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `75`
