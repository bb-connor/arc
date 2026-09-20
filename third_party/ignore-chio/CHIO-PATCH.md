# Chio ignore filter composition repair

This unpublished fork retains ignore 0.4.32 from BurntSushi/ripgrep commit
`5ed408e17eccfc59bcec48f584feece902873e54`, directory `crates/ignore`.
Registry archive SHA-256:
`0b17771570a2b94107741a7b033f19132c2eee21d59d21b24d2ced26500bd66e`.
The original MIT and Unlicense notices are retained.

Two production hunks repair independently reproduced file-selection defects:

- The serial walker returns early only when the file size exceeds its limit.
  Smaller files still pass through the caller's custom filter, matching the
  parallel walker's behavior.
- The Unix basename helper excludes dot and dot-dot path components, while
  retaining ordinary filenames ending in dots. Hidden-file filtering then
  recognizes `.hidden.` and `.hidden..` correctly.

All upstream source, tests and fixtures remain present. No original test
assertion changes. Seven additional tests cover these regressions, partial
ignore-file errors, anchoring and escaped literals, serial/parallel/incremental
selection, cached rules, lexical normalization, symlink descent and loops.
The manifest disables publication and adds a standalone test workspace. Its
lockfile records the qualification inputs.

This library selects files. It does not authorize access or confine traversal.
Chio's current confinement entrypoint does not call it; nono's separate rollback
module imports its Gitignore API. That unused module does not establish a
qualified Chio rollback integration. Resource limits and race-free access
remain the caller's responsibility.

```sh
cargo test --locked --all-features --manifest-path third_party/ignore-chio/Cargo.toml
```

The original package does not pass strict Clippy on Rust 1.94.1. Those existing
warnings are retained and documented in the review, rather than suppressed.
