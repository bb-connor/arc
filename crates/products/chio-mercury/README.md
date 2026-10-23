# chio-mercury

`chio-mercury` provides the `mercury` binary for packaging release-control
workflow evidence. It loads Chio evidence exports, adds the contracts from
`chio-mercury-core`, and writes proof, inquiry, reviewer, and distribution
artifacts to local files.

## Usage

Run this offline example from the workspace root with Bash. The built-in
`MercuryPilotScenario::gold_release_control()` fixture supplies the workflow;
all generated databases and JSON files stay in a fresh temporary directory.

```bash
mercury_example_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-mercury-example.XXXXXX")"
trap 'rm -rf -- "$mercury_example_dir"' EXIT
cargo run -p chio-mercury -- pilot export \
  --output "$mercury_example_dir/pilot"
kernel_public_key="$(jq -r .primary.kernelPublicKey "$mercury_example_dir/pilot/pilot-summary.json")"
jq -n --arg key "$kernel_public_key" \
  '{schema: "chio.verifier-trust.v1", kernel_keys: [$key], exchange_keys: [], root_policy_keys: []}' \
  > "$mercury_example_dir/verifier-trust.json"
cargo run -p chio-mercury -- --json verify \
  --input "$mercury_example_dir/pilot/primary/proof-package.json" \
  --trust "$mercury_example_dir/verifier-trust.json"
```

The export includes primary and rollback receipt databases, evidence exports,
proof packages, and a primary inquiry package. The JSON verification report
has `verifierEquivalent: false`.

| Command | Inputs and result |
| --- | --- |
| `proof export` | Evidence directory, bundle manifests, and a `chio.verifier-trust.v1` trust file (`--trust`); writes proof-package v2. |
| `inquiry export` | Proof package, audience, and a trust file (`--trust`); writes inquiry-package v1 with a deterministic rendered projection. |
| `verify` | Current proof or inquiry JSON and a trust file (`--trust`); prints the verification steps with `--explain`. |
| `pilot export` | Built-in scenario; creates signed synthetic receipts and checkpoints. |
| `supervised-live export` | Typed capture JSON; requires export-ready control state. |
| `supervised-live qualify` | Built-in capture and pilot; writes fixture qualification artifacts. |

Review and distribution subcommands also expose `export` and `validate`.
They assemble local packages through the shared workflow, including governance,
assurance, OEM, trust-network, account, and portfolio contracts. `validate`
writes a validation report and a decision record with predefined scope text.
These records describe the fixture exercise.

## Guarantees

- `build_proof_package` verifies evidence through `chio-bundle-verify` with the
  verifier-owned trust file.
- Every CLI verdict and export calls `verify_with_trusted_kernel_keys`: `verify`,
  `proof export`, and `inquiry export` against the `--trust` file's kernel keys,
  and the pipeline exports against the kernel key their own run generated and
  signed with (`kernelPublicKey` in the run paths). The core `verify` method is a
  library-only integrity check that selects no trusted kernel-key set.
- `read_json_file` rejects duplicate keys through `decode_signed`; its file
  read itself is unbounded.
- `ensure_empty_directory` rejects nonempty export directories.
  `write_json_file` creates parent directories and can overwrite an individual
  file selected by the caller.

## Status

Implemented as a local evidence CLI with synthetic pilot and capture exports.
`populate_mercury_receipt_store` signs modeled events directly; it does not run
an external trading tool through kernel admission. The supervision mode and
release gates are supplied capture data. Product package names and generated
qualification decisions do not establish deployment acceptance.

There are no package-defined Cargo features. CLI tests exercise filesystem
exports, verification, duplicate-key rejection, and package validation.

## Related

- [Architecture](ARCHITECTURE.md)
- [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [Mercury core](../chio-mercury-core/README.md)
- [Control plane](../../platform/chio-control-plane/README.md)
- [License](../../../LICENSE)
