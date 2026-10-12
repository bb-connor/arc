# chio-release-evidence architecture

## Responsibility and boundary

The crate owns the `chio-release-qualification-manifest` command and its
`chio.release-qualification-manifest.v1` body schema. It has no library target.
The body records candidate commit and tree IDs, the lockfile SHA-256 digest,
generation time, source metadata, qualification scope, and artifact entries.
Each artifact entry contains a relative path, byte count, and SHA-256 digest.

The qualification scope identifies self-signed internal release evidence.
The command inventories existing files; it does not execute the gates that
produced them. Consumers must assess their contents and establish trust in the
signer. Verification accepts the public key embedded in the signed envelope.

## Structure

All implementation lives in [src/main.rs](src/main.rs).
`parse_args` selects signing or `--verify` mode and requires repository root,
artifact root, manifest path, and checksum path in both modes.
`qualify` creates the signed envelope; `verify` checks retained evidence.
`collect_artifacts`, `hash_file`, and `checksum_bytes` build the inventory.
`validate_signed_manifest` validates the signed body and signature.
`write_new_or_replace` installs each generated file through a temporary file.

There are no declared Cargo features. The package is unpublished and inherits
the workspace version, Rust toolchain requirements, and lint configuration.

## Data and control flow

Signing canonicalizes both roots and requires the artifact root to be inside
the repository. The resolved seed must be outside that artifact root.
Output parents are canonicalized and must already exist; both outputs must
reside inside the artifact root and have distinct paths.

`qualify` checks Git status, reads `HEAD` commit and tree IDs, hashes
`Cargo.lock`, and walks the artifact tree. It sorts entries by relative path,
loads an Ed25519 seed, and signs a `SignedExportEnvelope`.
It then checks the commit, clean status, and artifact inventory again before
writing canonical JSON and deterministic `SHA256SUMS` bytes.

Verification rejects a supplied seed. It reads the manifest, checks canonical
JSON and the envelope, compares the current artifact inventory and checksums,
then repeats the inventory and Git checks. Relative output paths resolve under
the repository root; the artifact root resolves from the process directory.

When `GITHUB_ACTIONS=true`, signing records `GITHUB_RUN_ID` and
`GITHUB_RUN_ATTEMPT`. Verification checks numeric metadata shape and pairing.
These environment values record provenance asserted by the invoking process.

## Trust and invariants

`validate_signed_manifest` requires a non-weak Ed25519 signer key, a valid
signature, the fixed schema and scope, and matching commit, tree, and lockfile.
Generation time must be positive and at most 300 seconds ahead of the clock.
There is no maximum age check.

Artifact metadata must contain 1 through 100,000 strictly sorted entries with
portable relative paths and lowercase 64-character hexadecimal digests.
The directory walker rejects symlinks, special files, control characters,
and names suggesting seeds, private keys, or `.env` files.
This filename rule does not inspect artifact contents for secrets.

Manifest and checksum reads reject symlinks, empty files, and metadata sizes
above 64 MiB and 16 MiB respectively before calling `fs::read`.
Artifact hashing streams through a 1 MiB buffer with checked byte accounting.
Repeated inventories detect observed changes; they do not lock the filesystem.

Each output is written, synced, renamed, and followed by a directory sync.
The two outputs are installed separately, so a failed second write can leave
the first installed. Verification checks their consistency on the next run.

## Dependencies

`chio-core-types` supplies canonical JSON, Ed25519 key handling, and signed
export envelopes. `serde` and `serde_json` encode the manifest schema.
`sha2` and `hex` implement streaming artifact digests. `tempfile` supports
unit tests. Git is an external executable used for candidate inspection.

## Verification

The unit tests in `src/main.rs` cover deterministic hashes and checksums,
secret-like and non-portable names, Unix symlink rejection, output replacement,
and a clean temporary Git candidate that signs and verifies successfully.
That candidate test also changes an artifact and requires verification failure.
Run `cargo test -p chio-release-evidence --all-targets` for those checks.

The [README example](README.md#usage) exercises signing and verification with
a disposable candidate. Passing these checks establishes the exercised file
binding and signature behavior; release acceptance requires the caller's gates.
