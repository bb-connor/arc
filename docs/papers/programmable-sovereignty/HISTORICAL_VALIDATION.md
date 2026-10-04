# Historical artifact validation

This paper retains measurements of an earlier implementation. Kernel changes
and verifier fixes after that experiment do not qualify the new implementation
with the old measurements. The hosted Paper Artifact Check therefore explicitly
validates the historical artifact:

```sh
python3 scripts/tests/programmable-sovereignty-artifact.test.py
python3 scripts/generate-programmable-sovereignty-artifact.py --check-historical
```

The current verifier executes both commands. It never executes the historical
generator or benchmark scripts. The manuscript, PDFs, result files, generated
macros, claim ledger, supplementary outputs, and manifest are read from the
current checkout and must match the retained artifact's hashes and consistency
checks. The Lean archive is reconstructed in memory from its original inputs
and compared byte for byte; this command does not run Lean or the listed tests.
CI installs `pdftotext` for the additional PDF measurement-text check.

## Two immutable identities

- `supplementary/source-commit.txt` retains measured-source snapshot
  `b13ceda988f299855aa86799c9c7cc3cabb1bbf7`. The enumerated source files,
  implementation symbols, corpora, benchmark scripts, toolchain, and Lean
  archive inputs are checked at this commit. Each result's own producer commit
  must exist, precede this source snapshot, and have the same recorded benchmark
  input-tree digest. The digest is recomputed from both actual Git trees.
- `supplementary/artifact-commit.txt` identifies artifact assembly commit
  `884fd7894d14b763fbabce67f1b188c5274cbfa5`. The source pin and original manifest
  are authenticated against this commit. The manifest's generator hash names
  the assembler at this commit. The generator was already explicitly excluded
  from measured input trees; its later revisions do not become measured code.

Both pins and every producer object are required. Missing or invalid identities
fail validation. There is no fallback to `HEAD`, no automatic repinning, and no
output write in historical mode. CI fetches full history for these checks.

The retained bilateral result has schema v2, which predates the concurrency
sweep. The current renderer supports that exact schema and v3, where concurrency
and bottleneck fields remain required. Unknown schema versions are rejected.

## Aggregate digest erratum

Artifact assembly commit `884fd7894d14b763fbabce67f1b188c5274cbfa5` added test
inventory entry PS-T13 and changed the generator's per-file hash, but left the
aggregate `source.contentSetSha256` at its earlier value. This is a metadata
integrity defect in the retained manifest, independent of the later source
compatibility failure.

The repair changes only that derived aggregate field:

| Field | SHA-256 |
| --- | --- |
| Original manifest bytes at the assembly commit | `118b9f02b8c2674d615e44ce15f3fe67c047a1f9f3dfe0eed29dc6cc9f5e56ff` |
| Stale aggregate | `418d07c3038ca7e54d3b2f98ba5f2b7b9db66fe4df73d9a0f3ff85d7cf88e63a` |
| Correct aggregate | `36fde2d95a83c18da60d28f8d98b398b70f4923735f2ffae7e55578d69afc54a` |

Historical validation permits this single field to differ from the original
manifest. It independently regenerates the complete expected manifest from the
bound file bytes and checks the corrected aggregate. An incorrect aggregate,
including the original stale value, is rejected. Every other manifest field
must remain unchanged. Measurements, individual hashes, source identities, and
the archived manuscript are preserved.

## Current-source qualification remains separate

`--check` retains its strict working-source comparison and continues to reject
this evolved checkout with `working artifact differs from pinned commit`.
The original supplementary README and its full-reproduction command remain
archival documents; their command is not a current-source qualification result.
New measurements require an explicit new source revision and a separate
experiment. Passing historical validation establishes retained artifact
integrity, not present-code benchmark, security, or production qualification.
