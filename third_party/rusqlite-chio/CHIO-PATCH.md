# Rusqlite callback ownership repair

This unpublished path package retains rusqlite 0.39.0 and its MIT license.
The workspace selects it through `[patch.crates-io]`.

The starting published archive is `rusqlite-0.39.0.crate`, SHA-256
`a0d2b0146dd9661bf67bb107c0bb2a55064d556eeb3fc314151b957f313bcd4e`.
Its archive metadata identifies commit `2a1790a69107cd03dae85d501dcbdb11c5b32ef3`.
All 70 published files are retained. The original manifest, lock, license,
documentation, examples and integration tests remain available.

Scalar, aggregate and window function registration now convert the function
name before transferring callback ownership to SQLite. Name conversion errors
and unwinding conversion panics drop the callback and its captures normally.
After successful conversion, SQLite keeps its existing destructor responsibility.
No second free, public API change or callback ABI change is introduced.

`CHIO-PATCH.patch` records the production reorderings, test wiring and package
metadata. `CHIO-SOURCE-HASHES.sha256` identifies the published-file postimages.

The added ownership controls exercise conversion errors and panics, SQLite
rejection, temporary names, successful SQL evaluation, replacement, removal,
connection closure and moving-window inverse evaluation. On GNU/Linux, the
original code failed the nine conversion cleanup cases; the repair passed all
31 controls with window functions and 20 with the workspace feature set.
Those runs used the same real library sources and bundled SQLite 3.51.3 with
an isolated control manifest. Complete package, platform and workspace
qualification remain separate from these scoped ownership results.
