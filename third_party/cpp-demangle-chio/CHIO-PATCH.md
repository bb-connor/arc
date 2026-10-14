# cpp_demangle 0.5.1 transparent newtype repair

Unpublished path fork of cpp_demangle 0.5.1 (MIT OR Apache-2.0), selected
through `[patch.crates-io]` in the root, fuzz and Docker workspaces. It
reaches the build through `wasmtime-environ`.

## Provenance

- Archive: `https://static.crates.io/crates/cpp_demangle/cpp_demangle-0.5.1.crate`,
  SHA-256 `0667304c32ea56cb4cd6d2d7c0cfe9a2f8041229db8c033af7f8d69492429def`
  (the registry checksum Cargo.lock records).
- Upstream commit: `6fc3a53ba2ae11bdcf470ed44058a233af517160` (`.cargo_vcs_info.json`).
- All published files are retained. `CHIO-SOURCE-HASHES.sha256` holds the
  SHA-256 of every file after patching; `CHIO-PATCH.patch` is the complete
  delta from the archive.

## Delta

1. `reference_newtype!` wrappers carry `#[repr(transparent)]`, backported
   from upstream commit
   <https://github.com/gimli-rs/cpp_demangle/commit/0aabe553c667bf2241d8c65aef5526a8c968398e>.
   `new` casts `&T` to `&Wrapper(T)`, including the unsized
   `[TypeHandle]` slice wrapper. Without the attribute Rust does not
   guarantee the wrapper shares the field's layout or slice metadata, so the
   cast is unsound. The returned borrow inherits the input lifetime and is
   immutable.
2. Two tests in `src/ast.rs` (`reference_newtype_tests`) check that the vector
   and slice views keep the original storage, pointer, length, size and
   alignment.
3. `Cargo.toml` sets `publish = false` and declares an empty `[workspace]` so
   the fork builds standalone.

## Tests

```bash
cargo test --manifest-path third_party/cpp-demangle-chio/Cargo.toml --lib
```

crates.io excludes upstream's `tests/` and `in/` fixtures, so the retained
package runs the library unit tests only.
