# chio-trace-validate

`chio-trace-validate` authenticates signed runtime observations and projects
revocation behavior into the bounded `RevocationPropagation` TLA+ model.
It provides a Rust library for capture, decoding, projection, and reports,
plus a CLI that invokes Apalache for invariant and reachability checks.

## Usage

This offline example verifies and projects the checked repository fixture.
It uses the fixture's pinned observer key and requires no external checker.

```rust
use chio_core_types::crypto::PublicKey;
use chio_trace_validate::{decode_observations, project_revocation_trace, TraceError};

fn main() -> Result<(), TraceError> {
    let key = PublicKey::from_hex(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../formal/tla/trace/fixtures/trusted-observer-key.txt"
    )).trim())?;
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../formal/tla/trace/fixtures/revocation-good.ndjson"
    ));
    let trace = decode_observations(bytes, &[key])?;
    let projection = project_revocation_trace(&trace)?;
    assert_eq!(projection.events().len(), 3);
    assert_eq!(projection.action_coverage().revoke, 1);
    assert_eq!(projection.action_coverage().post_revocation_evaluate, 1);
    Ok(())
}
```

`validate_file(&ValidationOptions)` adds action floors, invariant witness
requirements, Apalache invariant evaluation, and bounded prefix reachability.
It requires Apalache 0.50.1 and `timeout` or `gtimeout` on the host.
The CLI requires `--log` and at least one `--trusted-key`; optional output
flags retain projected ITF, checker witnesses, and the validation report.
Its only supported `--spec` value is `revocation-propagation`.

## Guarantees

- `decode_observations` requires canonical newline-terminated records, trusted
  observer signatures, contiguous visible sequence numbers, consistent trace
  metadata, and complete accounting of the declared runtime callback sequence.
- `project_revocation_trace` checks receipt signatures, action hashes, authority
  keys, allow/deny decisions, and referenced revocation epochs before projection.
- `validate_file` requires witnesses for `NoAllowAfterRevoke`, `MonotoneLog`,
  `AttenuationPreserving`, and `RevocationFreshness` before model checking.
- `ApalacheOracle` checks the pinned version, bounds execution time, validates
  checker output and ITF witnesses, and detects observed executable changes.

## Status

This unpublished tool validates supplied traces against one bounded model.
The README example exercises authentication and projection. Full file
validation additionally checks model invariants and reachability.
Callers select trusted observers and establish capture provenance.
`validate_projection_with` accepts a caller-provided oracle and runs only
prefix reachability; its report depends on that oracle's answer.
There are no declared Cargo features.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol evidence boundary](../../../spec/PROTOCOL.md#54-safety-properties-and-evidence-boundary)
- [Trace model and fixtures](../../../formal/tla/trace/README.md)
- [Release evidence](../chio-release-evidence/README.md)
- [License](../../../LICENSE)
