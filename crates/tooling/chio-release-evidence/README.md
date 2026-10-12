# chio-release-evidence

`chio-release-evidence` produces and verifies signed inventories of release
artifacts for one clean Git candidate. Its binary is
`chio-release-qualification-manifest`; qualification scripts use it to bind
retained files to the candidate commit, tree, and `Cargo.lock` digest.

## Usage

Run from the workspace root with Cargo, Git, and Python 3 installed. This
offline example creates a disposable repository and demonstration signing key.
The key is suitable only for this example. All generated evidence stays in the
temporary directory, which the shell removes on exit.

```sh
set -eu
umask 077
evidence_demo=$(mktemp -d)
trap 'rm -rf "$evidence_demo"' EXIT
printf 'artifacts/\nexample.seed\n' > "$evidence_demo/.gitignore"
printf 'version = 4\n' > "$evidence_demo/Cargo.lock"
git -C "$evidence_demo" init --quiet
git -C "$evidence_demo" add .gitignore Cargo.lock
git -C "$evidence_demo" -c commit.gpgsign=false \
  -c core.hooksPath=/dev/null commit --quiet -m 'test: example candidate'
mkdir "$evidence_demo/artifacts"
printf 'example artifact\n' > "$evidence_demo/artifacts/check.log"
python3 -c 'import sys; print("11" * 32, file=open(sys.argv[1], "w"))' \
  "$evidence_demo/example.seed"
git -C "$evidence_demo" status --porcelain
GITHUB_ACTIONS=false cargo run --locked -p chio-release-evidence \
  --bin chio-release-qualification-manifest -- \
  --repo-root "$evidence_demo" --artifact-root "$evidence_demo/artifacts" \
  --signing-seed "$evidence_demo/example.seed" \
  --output artifacts/manifest.json --checksums artifacts/SHA256SUMS
GITHUB_ACTIONS=false cargo run --locked -p chio-release-evidence \
  --bin chio-release-qualification-manifest -- --verify \
  --repo-root "$evidence_demo" --artifact-root "$evidence_demo/artifacts" \
  --output artifacts/manifest.json --checksums artifacts/SHA256SUMS
```

Git must already have a configured author identity. The example ignores both
the artifact directory and seed so the candidate remains clean. Signing an
existing candidate also requires the seed to stay outside the artifact root.

Both commands return zero on success. Add `--expected-candidate` with the
expected 40-character commit ID to require an explicit candidate match.
The manifest and checksum paths must have existing parent directories inside
the artifact root. Verification rejects `--signing-seed`.

## Guarantees

- `qualify` and `verify` check a clean Git status and candidate identity before
  and after processing, and compare two artifact inventories.
- `collect_artifacts` hashes regular files, rejects symlinks and secret-like
  filenames, and excludes the manifest and checksum files from the inventory.
- `validate_signed_manifest` verifies Ed25519 signatures, candidate and lockfile
  binding, generation time, source metadata, and sorted artifact metadata.
- `verify` requires canonical manifest JSON and exact checksum-file bytes.

## Status

This unpublished binary implements self-signed internal evidence packaging.
The verifier uses the envelope's signer key; callers establish signer trust
separately. Artifact contents, workflow success, and deployment acceptance
remain decisions for the qualification system consuming the inventory.
There are no declared Cargo features.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol evidence boundary](../../../spec/PROTOCOL.md#54-safety-properties-and-evidence-boundary)
- [Trace validator](../chio-trace-validate/README.md)
- [Release qualification script](../../../scripts/qualify-release.sh)
- [License](../../../LICENSE)
