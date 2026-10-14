# rusqlite 0.39.0 callback ownership and argument repairs

Unpublished path fork of rusqlite 0.39.0 (MIT), selected through
`[patch.crates-io]` in the root, fuzz and Docker workspaces.

## Provenance

- Archive: `https://static.crates.io/crates/rusqlite/rusqlite-0.39.0.crate`,
  SHA-256 `a0d2b0146dd9661bf67bb107c0bb2a55064d556eeb3fc314151b957f313bcd4e`
  (the registry checksum Cargo.lock records).
- Upstream commit: `2a1790a69107cd03dae85d501dcbdb11c5b32ef3` (`.cargo_vcs_info.json`).
- All 70 published files are retained. `CHIO-SOURCE-HASHES.sha256` holds the
  SHA-256 of every file after patching; `CHIO-PATCH.patch` is the complete
  delta from the archive.

## Delta

1. Scalar, aggregate and window function registration convert the function
   name before transferring callback ownership to SQLite. A name conversion
   error or panic drops the boxed callback and its captures in Rust. Upstream
   leaked the callback on that path, because ownership had already moved into
   a raw pointer that SQLite never received. After a successful conversion
   SQLite keeps its destructor responsibility, so no double free is possible.
2. Scalar, aggregate-step and window-inverse callbacks borrow an empty slice
   when SQLite reports zero arguments. SQLite passes a null `argv` for
   zero-argument expressions during STAT4 evaluation, and
   `slice::from_raw_parts` requires a non-null pointer even for length zero.
   Positive counts keep the original pointer-array borrow.
3. `Cargo.toml` sets `publish = false` and declares an empty `[workspace]` so
   the fork builds standalone.

No public API or callback ABI changes.

## Tests

`src/functions/registration_ownership.rs` covers conversion errors and
panics, SQLite rejection, temporary names, successful evaluation,
replacement, removal, connection close and moving-window inverse evaluation.
`src/functions/empty_arguments_tests.rs` covers the null/zero boundary,
nonempty pointer slots, variable arity, scalar evaluation, empty aggregate
input and moving-window step, inverse, value and final callbacks.

```bash
cargo test --manifest-path third_party/rusqlite-chio/Cargo.toml \
  --features bundled,functions,hooks,trace,window --lib
```
