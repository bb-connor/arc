# chio-cage

`chio-cage` admits native tools from registry-issued manifest authorization,
retains filesystem and executable descriptors, and compiles the Linux launch
contract used by `chio-cage-init`. Its supervisor observes target execution
before returning an `EnforcedChild`; its receipt API signs cage decisions into
Chio receipts.

## Usage

Build a rejection receipt body offline when admission has denied an attempt:

```rust
use chio_cage::{
    CageEnforcementFailure, CageEnforcementFailureCode, CageEnforcementRecord,
    CageReceiptBody, CageReceiptStage,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let failure = CageEnforcementFailure::new(
        CageEnforcementFailureCode::InvalidPlan,
        "operator_admission",
    )?;
    let record = CageEnforcementRecord::rejected(failure)?;
    let body = CageReceiptBody::new("attempt-1", None, record, 1_000, 1_001)?;
    assert_eq!(body.stage, CageReceiptStage::Rejection);
    body.validate()?;
    Ok(())
}
```

This example uses default features, needs no Linux enforcement primitives, and
creates an unsigned body. `sign_cage_receipt` additionally needs a signing backend
and caller-supplied `CageReceiptSigningContext`.

For native execution, pass `VerifiedCageManifest` and `OperatorCeilings` to
`admit`, retain `RuntimeResourcePaths`, then call `compile` and `prepare_launch`.
`compile` may create missing exact write-grant files. `launch_prepared` starts
the helper and target; preparation itself creates stdio sockets and a sealed
plan memfd without spawning a process.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `real-linux-enforcement` | Off | Enables Linux x86_64 integration probes; launch APIs already exist without it. |
| `enforcement-mutants` | Off | Enables test mutation hooks and forwards them to plan/init crates; release builds reject it. |

No Cargo features are enabled by default.

## Guarantees

- `admit` requires explicit permissions, operator ceilings, and a configured
  forbidden-path set, then retains grants and rejects path or inode overlaps.
- `compile` binds the registry authorization, runtime artifacts, argv, execution
  identity, environment, FD table, and policy digests into canonical plans.
- `launch_prepared` requires full Landlock filesystem/network status, installed
  seccomp, matching prepared evidence, status EOF, and an observed target exec.
- `verify_signed_cage_receipt_with_trusted_key` verifies content, state semantics,
  signature, timestamps, and the configured signer before persistence.

## Status

Native launch supports Linux x86_64 with Landlock ABI 4 or newer, `openat2`,
memfd sealing, pidfds, `close_range`, procfs, and permitted parent-child ptrace.
The helper must be a static PIE. Unsupported or partial enforcement fails closed.
The helper applies a non-root Unix identity and `RLIMIT_NOFILE`; namespace,
cgroup, CPU, and memory isolation require deployment controls outside this crate.
Direct network creation is blocked; brokered access uses an authenticated,
preconnected Unix socket. Real enforcement tests require a separately built
helper and probe fixtures; ordinary tests cover compilation and evidence shapes.

## Related

- [Architecture](ARCHITECTURE.md)
- [Manifest contract](../../../spec/PROTOCOL.md#7-manifest-contract)
- [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [Shared plan](../chio-cage-plan/README.md) and [bootstrap](../chio-cage-init/README.md)
- [Manifest registry](../../platform/chio-manifest/README.md)

## License

See [LICENSE](../../../LICENSE).
