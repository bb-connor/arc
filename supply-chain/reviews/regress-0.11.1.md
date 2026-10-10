# regress 0.11.1 UTF-8 search-start backport

Status, October 6, 2026: this fork is not in the dependency graph. Every
lockfile resolves regress to registry 0.10.5; see the selection paragraph below.

## Inputs and repair

The selected registry release is 0.11.1, with archive SHA-256
`158a764437582235e3501f683b93a0a6f8d825d04a789dbe5ed30b8799b8908a`.
The archive is retained in `output/process-security-20260915/regress-audit-eb040d592/`
in the primary checkout. It was checksum-verified before extraction.

Backport the public API validation and regression assertions from upstream
[commit 5e5141c1f6d132f2890b09f998f6a0a93c5d94ab](https://github.com/ridiculousfish/regress/commit/5e5141c1f6d132f2890b09f998f6a0a93c5d94ab).
The UTF-8 search entry point checks character boundaries before constructing
the match iterator. Valid boundaries, out-of-range starts and the distinct
ASCII byte-index contract retain the upstream behavior.

The production API hunk is unchanged from upstream. The upstream regression
assertions are placed in a separate `chio_start_boundary` integration target
with an explicit `regress::Regex` import: the published release's test file
does not contain the later commit's surrounding context. No existing upstream
test assertions are edited. The manifest disables publication and gives the
vendored crate a standalone qualification workspace.

No workspace selects `third_party/regress-chio`. Every lockfile in the
repository (root, fuzz and both generated Docker workspaces) resolves regress
to registry 0.10.5, which `chio-core-types` requires as `regress = "0.10.5"`.
That version is covered only by the `[[exemptions.regress]]` 0.10.5
safe-to-deploy entry in `supply-chain/config.toml`, and its `find_from` still
accepts a start index that is not a character boundary. Chio cannot reach that
defect: the generated wire types call only `Regex::new` and `Regex::find`, and
`find` searches from index 0, which is always a boundary. Nothing in the
workspace calls `find_from`. The fork is not compiled into any artifact; it is
kept as reviewed source for an upgrade to 0.11. No safe-to-deploy audit or new
exemption is added.

## Qualification and scope

Commands and terminal results are retained in
`output/process-security-20260915/regress-repair-continuation-20260920/`.
The original reproducer and failures remain in the older evidence directory.

The unmodified release's complete test harness does not compile with
`--no-default-features --features std`: its common test helper unconditionally
references the disabled PikeVM executor. Retain that failed command as a
baseline limitation. Use the default upstream inventory, which includes both
backends, and run the standalone boundary target separately without PikeVM.
The boundary target also runs under Miri. Feature qualification includes
`index-positions`, `utf16`, and `prohibit-unsafe`.

This is a scoped backport of a published fix, not a new vulnerability discovery
or a certification of every API in the dependency. In particular, do not infer
that the public API regression proves every doc-hidden backend API safe.
The remaining AWS-LC registry audit requirements are unchanged.

## Execution-image follow-through

The updated selected root lockfile has SHA-256
`4f1b3528664a77eea1e703c425e351904f79181f14264d6c6edc6651d5e4b569`.
The Dockerfile's source-input check and structural checker's expected source
digest are updated together. This records a new reproducible build input; it
does not rebuild or authorize an execution image. The old image's dependency
cache and old frozen foundation run do not qualify this changed dependency
graph. Rebuild and verify the image/cache and run affected downstream foundation
and cage qualification before claiming integrated acceptance.

## Remaining repository hygiene blocker

The complete Rust file-hygiene gate currently fails on five existing vendored
files (four nono files and ignore's walker). This candidate additionally exposes
five untouched upstream regress files above the same caps: parse.rs,
unicodetables.rs, tests.rs, unicode_property_escapes.rs and unicodesets.rs.
Baseline and candidate logs are retained separately. No caps, exemptions or
file-selection logic in that checker were changed. This source checkpoint is
not merge-ready until the vendored-source hygiene requirement is resolved.
