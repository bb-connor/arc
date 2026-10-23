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
cargo run -p chio-mercury -- --json verify \
  --input "$mercury_example_dir/pilot/primary/proof-package.json"
```

The export includes primary and rollback receipt databases, evidence exports,
proof packages, and a primary inquiry package. The JSON verification report
has `verifierEquivalent: false`.

| Command | Inputs and result |
| --- | --- |
| `proof export` | Evidence directory, bundle manifests, and explicit trusted kernel keys; writes proof-package v2. |
| `inquiry export` | Proof package and audience; writes inquiry-package v1 with a deterministic rendered projection. |
| `verify` | Current proof or inquiry JSON; prints an integrity-only report (`scope: integrity_only`), optionally with `--explain`. |
| `pilot export` | Built-in scenario; creates signed synthetic receipts and checkpoints. |
| `supervised-live export` | Typed capture JSON; requires export-ready control state. |
| `supervised-live qualify` | Built-in capture and pilot; writes fixture qualification artifacts. |

Review and distribution subcommands also expose `export` and `validate`.
They assemble local packages through the shared workflow, including governance,
assurance, OEM, trust-network, account, and portfolio contracts. `validate`
writes a validation report and a decision record with predefined scope text.
These records describe the fixture exercise.

## Guarantees

- `build_proof_package` loads evidence through
  `load_verified_evidence_package_summary` with an explicit verification policy.
- `cmd_mercury_verify` calls the core package's `verify_integrity_only` method.
  It checks receipt self-signatures and package bindings without a trusted
  kernel-key set, labels its output integrity-only, and never prints
  "verified". Authority-sensitive consumers use the core
  `verify_with_trusted_kernel_keys` API.
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
