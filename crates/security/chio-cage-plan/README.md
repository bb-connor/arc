# chio-cage-plan

`chio-cage-plan` defines the shared confinement plan, fixed descriptor roles,
launch envelope, and enforcement evidence used by `chio-cage` and
`chio-cage-init`. It validates plan components and evidence joins before those
crates transfer descriptors or report native execution.

## Usage

Construct and validate a small seccomp plan in memory:

```rust
use chio_cage_plan::{
    NativeSyscallProfile, SandboxArchitecture, SeccompDefaultAction,
    SeccompPlanError, SeccompProfilePlan, Syscall,
};
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plan = SeccompProfilePlan::new(
        SandboxArchitecture::X86_64,
        NativeSyscallProfile::NativeMinimalV1,
        vec![Syscall::Exit, Syscall::ExitGroup],
        BTreeMap::new(),
    )?;
    assert_eq!(plan.default_action(), SeccompDefaultAction::KillProcess);
    plan.validate()?;
    let denied = SeccompProfilePlan::new(
        SandboxArchitecture::X86_64,
        NativeSyscallProfile::NativeMinimalV1,
        vec![Syscall::Socket],
        BTreeMap::new(),
    );
    assert_eq!(denied, Err(SeccompPlanError::ForbiddenSyscall(Syscall::Socket)));
    Ok(())
}
```

This default-feature example runs offline on any platform. It constructs policy
only. Filter compilation and installation belong to the Linux bootstrap.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `enforcement-mutants` | Off | Exposes unchecked/test mutation helpers and the mutation environment key; release builds reject it. |

No Cargo features are enabled by default.

## Guarantees

- `SeccompProfilePlan::new` and its deserializer apply the same validator for
  duplicate syscalls, forbidden network/signaling authority, argument rules,
  and self-only `prlimit64` constraints.
- `ExecutionIdentity::new` rejects root and sentinel identities and requires
  sorted, unique supplementary groups within the 64-group limit.
- `FullyEnforcedEvidence::new` requires validated prepared/exec records, status
  EOF, matching process/trace/target bindings, and ordered timestamps.
- `validate_cage_target_fd_binding` checks the target entry against observed
  identity/content and the target FD constraint on every `execveat` alternative.

## Status

The shared contracts are implemented and used by admission and bootstrap.
`CageInitPlan` and evidence records remain deserializable data requiring their
relevant validators at consumption. `SandboxArchitecture` represents Aarch64,
but native architecture selection and prepared evidence currently accept only
x86_64. Linux descriptor inspection requires procfs. This crate supplies no
manifest authentication, sandbox installation, receipt signing, or persistence.

## Related

- [Architecture](ARCHITECTURE.md)
- [Manifest contract](../../../spec/PROTOCOL.md#7-manifest-contract)
- [Admission and supervision](../chio-cage/README.md)
- [Linux bootstrap](../chio-cage-init/README.md)

## License

See [LICENSE](../../../LICENSE).
