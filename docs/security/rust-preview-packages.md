# Offline Rust preview packages

`cargo xtask release rust-preview --out /absolute/new-directory` assembles an
unpublished offline registry and a standalone Rust consumer. The directory must
be outside the source checkout. Release assembly requires committed source;
`--allow-dirty` produces an explicitly marked development artifact.

The selected API roots are `chio-kernel-core`, `chio-kernel`,
`chio-swarm-authority`, and `chio-store-sqlite` for durable embedding. The current
Linux x86_64 normal/build closure contains 50 Chio crates and the reviewed
AWS-LC source. Only those local packages receive artifacts. Package manifests
carry exact internal version requirements. Publication remains disabled for
every member; this command never publishes or changes registry ownership.

The bundle includes the complete locked upstream archive inventory so Cargo can
resolve optional and target dependencies without an internet connection.
Upstream archives must match their original workspace lock checksums. Patched
sources are packaged from the reviewed checkout and identified separately in
`package-manifest.json`. Every artifact receives its own SHA-256 and index entry.
The reserved `chio.invalid` URL binds the source commit and all registry file
hashes. It is an unpublished registry identity, replaced
only by the included local registry. Patched AWS-LC bytes are never represented
as an unchanged crates.io archive. No workspace path patches are required.

The supported consumer profile is Linux x86_64, Rust 1.94.1, and the default
features of these libraries. FIPS, post-quantum signing, other platforms and
registry publication require separate qualification. The source code's narrower
portable-library MSRVs do not qualify the complete SQLite/runtime closure.

From the assembled directory, use a clean Cargo home and the installed pinned
toolchain. The first command resolves only the included, checksum-verified
registry; retain the generated consumer lock for subsequent locked builds.

```sh
cd consumer
cargo generate-lockfile --offline
cargo run --locked --offline -- /absolute/new-private-state
```

The consumer invokes one allowed in-process echo tool and one denied out-of-scope
call. It verifies signatures against a pinned demonstration identity, starts a
new process over the original SQLite state, and requires the original receipt,
output and single tool effect with a newer serving fence. This embedding example
uses a public demonstration signing seed and an ephemeral transparency/revocation
view. It is not an operational identity, native cage demonstration or substitute
for the separately packaged confined runtime installation.

Assembly alone does not qualify installation. Retain terminal consumer build,
execution and lint results against the artifact manifest before making that
claim. Public registry eligibility, release version selection and signed release
provenance remain separate from this offline staging step.
