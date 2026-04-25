# Chio Fuzzing

This directory contains Chio's repo-owned `cargo-fuzz` harnesses. It is a
standalone Cargo workspace so nightly/libFuzzer requirements do not leak into
the main stable/MSRV workspace lanes.

## Setup

CI uses a dated nightly so fuzz failures are reproducible across machines:

```bash
rustup toolchain install nightly-2026-04-24
cargo install cargo-fuzz --locked --version 0.13.1
```

Use the same nightly locally unless you are deliberately testing a toolchain
upgrade.

`fuzz/Cargo.lock` is intentionally standalone. Treat it as a semver canary for
the fuzz workspace, but keep direct fuzz dependencies aligned with production
behavior. Fuzz-only dependencies must not enable production-divergent features
unless the root workspace enables the same behavior.

## Targets

- `fuzz_canonical_json` - JSON canonicalization idempotence and binding vectors.
- `fuzz_policy_parse_compile` - HushSpec parse, validation, YAML roundtrip, and guard compilation.
- `fuzz_sql_parser` - SQL dialect parsing, normalized metadata, fail-closed batch handling, and guard checks.
- `fuzz_merkle_checkpoint` - Merkle roots, inclusion proofs, checkpoint signatures, and tamper rejection.
- `fuzz_capability_receipt` - capability and receipt signing, hash checks, tenant metadata, and lineage fixtures.
- `fuzz_manifest_roundtrip` - manifest vectors, duplicate-name rejection, signing, and tamper rejection.
- `fuzz_tool_action` - tool-action extraction and representative shell, egress, and MCP guard verdicts.

## Local Smoke

Run the same high-signal targets used by PR CI:

```bash
cd fuzz
cargo +nightly-2026-04-24 fuzz build
for target in fuzz_canonical_json fuzz_policy_parse_compile fuzz_sql_parser; do
  mkdir -p "/tmp/chio-fuzz/${target}"
  cargo +nightly-2026-04-24 fuzz run "${target}" \
    "/tmp/chio-fuzz/${target}" \
    "corpus/${target}" \
    -- -max_total_time=30
done
```

Always put a temporary corpus first and the checked-in corpus second for local
runs. This lets libFuzzer write discoveries outside the tracked seed corpus.

On macOS, `--sanitizer none` is smoke-only. It is useful when the default
address sanitizer hangs during startup, but Linux ASan CI is the authoritative
validation lane:

```bash
cargo +nightly-2026-04-24 fuzz run --sanitizer none fuzz_canonical_json \
  /tmp/chio-fuzz/fuzz_canonical_json \
  corpus/fuzz_canonical_json \
  -- -runs=100
```

## Scheduled All-Target Smoke

```bash
cd fuzz
for target in \
  fuzz_canonical_json \
  fuzz_policy_parse_compile \
  fuzz_sql_parser \
  fuzz_merkle_checkpoint \
  fuzz_capability_receipt \
  fuzz_manifest_roundtrip \
  fuzz_tool_action; do
  mkdir -p "/tmp/chio-fuzz/${target}"
  cargo +nightly-2026-04-24 fuzz run "${target}" \
    "/tmp/chio-fuzz/${target}" \
    "corpus/${target}" \
    -- -max_total_time=120
done
```

## Crash Triage

Owner: Chio maintainers. Backup owner until `CODEOWNERS` exists:
release/repo maintainers.

PR fuzz failures block merge. Scheduled and manual fuzz crashes require triage
within one business day.

1. Download and unpack the artifact from GitHub Actions:

   ```bash
   unzip fuzz-artifacts-<target>-<sha>.zip -d /tmp/chio-fuzz-artifacts
   find /tmp/chio-fuzz-artifacts -type f -exec shasum -a 256 {} \;
   ```

2. Reproduce the crash from the artifact:

   ```bash
   cd fuzz
   cargo +nightly-2026-04-24 fuzz run <target> /tmp/chio-fuzz-artifacts/<crash-file> -- -runs=1
   ```

3. Minimize the crashing input:

   ```bash
   cargo +nightly-2026-04-24 fuzz tmin <target> /tmp/chio-fuzz-artifacts/<crash-file>
   ```

4. Optionally minimize the corpus when coverage has grown too large:

   ```bash
   mkdir -p /tmp/chio-fuzz/<target>-cmin
   cargo +nightly-2026-04-24 fuzz cmin <target> /tmp/chio-fuzz/<target>-cmin corpus/<target>
   ```

5. Fix the bug in normal code.

6. Add a regular Rust regression test for the fixed failure mode before closing
   the bug.

Regression test template:

```rust
#[test]
fn regression_fuzz_<target>_<issue_or_sha>() {
    let input = include_bytes!("fixtures/<artifact-sha>.bin");
    // Assert the fixed stable behavior here.
}
```

Inline minimized UTF-8 input directly in the test when it is small. Use
`include_bytes!` for binary or larger inputs. Reference the artifact SHA in a
test comment or fixture name.

Promote a minimized input into `fuzz/corpus/<target>/` only when all gates pass:
it is minimized, contains no secrets, has bounded size, has a stable regression
test, has considered `cmin` when the corpus is growing, and has owner approval.

## Regression Test Homes

| Fuzz target | Normal regression home |
|-------------|------------------------|
| `fuzz_canonical_json` | `chio-core` or `chio-core-types` |
| `fuzz_capability_receipt` | `chio-core` or `chio-core-types` |
| `fuzz_policy_parse_compile` | `chio-policy` |
| `fuzz_sql_parser` | `chio-data-guards` |
| `fuzz_merkle_checkpoint` | `chio-kernel` |
| `fuzz_manifest_roundtrip` | `chio-manifest` |
| `fuzz_tool_action` | `chio-guards` |

## CI

PR CI builds every fuzz target with the pinned nightly and runs 30-second smoke
runs in the same warm job for:

```bash
fuzz_canonical_json
fuzz_policy_parse_compile
fuzz_sql_parser
```

Scheduled and manual CI run every target in a fail-fast-disabled matrix. Crash
artifacts are uploaded per target with retention days set in the workflow.
Manual runs accept a single target or `all`, plus a per-target
`max_total_time`.

Generated artifacts belong under `fuzz/artifacts/`, `fuzz/coverage/`, and
`fuzz/target/`; those directories are intentionally ignored.
