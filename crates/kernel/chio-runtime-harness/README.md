# chio-runtime-harness

A live loopback harness for regenerating Chio runtime proof artifacts.
It combines fixture proof baselines, runtime admission, a local native kernel,
SQLite authority and receipt stores, and buyer/federation evidence assembly.
The output is a set of local evidence files for verification and regression work.

## Usage

`run_runtime_loopback_scenario` takes a scenario JSON path, a private store
directory, an evaluation time in milliseconds, and an output directory.
For caller-supplied baselines, use `run_runtime_loopback_scenario_with_static_artifacts`.
This offline example exercises its early malformed-baseline rejection:

```rust
use std::path::Path;
use chio_runtime_harness::run_runtime_loopback_scenario_with_static_artifacts;

let result = run_runtime_loopback_scenario_with_static_artifacts(
    Path::new("scenario.json"),
    Path::new("runtime-store"),
    1_800_000_000_000,
    Path::new("runtime-output"),
    "{",
    "{",
);
assert!(result.is_err());
```

This uses the package's ordinary dependencies. Parsing fails before paths are
opened or created. Successful runs need Unix SQLite authority serving support, a valid scenario,
and writable local store/output paths. Windows authority startup rejects
before creating store/output directories.

## Guarantees

- `normalize_runtime_loopback_steps` validates scenario step selection.
- The harness calls `SqliteAuthorityStore::ensure_serving_supported` before setup.
- Receipt startup waits for the durable writer's head verification.
- `validate_runtime_relative_path` rejects traversal in emitted evidence paths.
- `write_runtime_json_artifact_string` hashes the exact bytes written,
  including the final newline, and records their length in the manifest.
- Proof assembly validates step/admission bindings and checks baseline parity.

## Status

Implemented test and proof-regeneration support with deterministic fixture
identities. Runs are serialized within the process to protect their shared
artificial authority identity. The harness executes local kernel calls and
writes files; it does not operate a hosted provider deployment.
Its fixture keys and baseline evidence are for controlled verification runs.
A parity failure returns an error after writing rejection reports and evidence.
There are no declared Cargo features.

## Related

- [Architecture](ARCHITECTURE.md)
- [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [Runtime implementation](../chio-runtime-core/README.md)
- [License](../../../LICENSE)
