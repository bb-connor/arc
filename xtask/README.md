# Workspace tasks

Run `cargo xtask --help` for available tasks. The task runner selects the Chio
checkout containing its current working directory. This also works from a
workspace member or an ordinary subdirectory.

The same rule applies to a saved `xtask` executable, including one built in a
different Git worktree or reused through `CARGO_TARGET_DIR`:

```sh
cd /path/to/intended/chio-checkout
/path/to/saved/xtask gen proof-coverage --check
```

The compiled source path and `CARGO_MANIFEST_DIR` environment variable never
select the checkout. Workspace tasks called from outside a Chio workspace fail.
Root discovery also stops at an unrelated nested Cargo workspace, Git repository,
or package that is not a member of the containing workspace. When using
`cargo run` with `--manifest-path`, change into the intended checkout first.
