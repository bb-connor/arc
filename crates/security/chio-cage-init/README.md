# chio-cage-init

`chio-cage-init` is the Linux bootstrap library and executable launched by
`chio-cage`. It receives a sealed plan and retained descriptors, verifies their
bindings, applies the target identity and confinement, and executes the retained
target. The supervisor owns manifest admission and observation of target exec.

## Usage

Validate a seccomp plan through the bootstrap boundary helper offline on Linux:

```rust
use chio_cage_init::seccomp_profile_is_fail_closed;
use chio_cage_plan::{
    NativeSyscallProfile, SandboxArchitecture, SeccompProfilePlan, Syscall,
};
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plan = SeccompProfilePlan::new(
        SandboxArchitecture::X86_64,
        NativeSyscallProfile::NativeMinimalV1,
        vec![Syscall::Exit, Syscall::ExitGroup],
        BTreeMap::new(),
    )?;
    assert!(seccomp_profile_is_fail_closed(&plan));
    Ok(())
}
```

The example uses default features and runs on Linux, including Aarch64. It
checks plan consistency without compiling or installing a filter. It needs no
elevated privileges, Landlock support, service, or sandbox process.
`compile_seccomp_filter` additionally requires a Linux x86_64 host.

The executable consumes the authenticated launcher protocol through FD 0 and
`CHIO_CAGE_CONTROL_FD=0`. It has no argument-based launch interface. Invocation
without this control descriptor exits with code 127. Use `chio-cage` to prepare
and supervise a real launch.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `real-linux-enforcement` | Off | Declares a feature used by enforcement builds; this crate has no source conditional for it. |
| `enforcement-mutants` | Off | Enables caught bootstrap mutations and forwards plan mutation support; release builds reject it. |

No Cargo features are enabled by default.

## Guarantees

- `run_cage_init` requires a single-threaded helper, authenticated parent,
  canonical sealed envelope, matching descriptor table, and matching helper image.
- `apply_execution_identity` applies or verifies the exact non-root identity;
  bootstrap then sets parent-death `SIGKILL` and irreversible `no_new_privs`.
- `apply_landlock` uses retained FDs through `nono-chio`; prepared validation
  requires fully enforced filesystem and network rulesets before target exec.
- `compile_seccomp_filter` validates the plan and native architecture and emits
  default `KillProcess` BPF; bootstrap installs it before emitting prepared status.

## Status

The library is Linux-only and native filter compilation currently supports
x86_64. Real launch requires Landlock ABI 4 or newer, procfs, pidfds,
memfd seals, `close_range`, seccomp, and the supervisor's ptrace contract.
The launcher requires a static PIE helper without an ELF interpreter or dynamic
library dependencies. The helper sets `RLIMIT_NOFILE`, closes unnamed FDs, and
uses `execveat`; namespace and cgroup setup belong to deployment controls.
The prepared status record becomes full launch evidence only after the parent
observes the target exec and status EOF.

## Related

- [Architecture](ARCHITECTURE.md)
- [Manifest contract](../../../spec/PROTOCOL.md#7-manifest-contract)
- [Admission and supervision](../chio-cage/README.md)
- [Shared plan and evidence](../chio-cage-plan/README.md)

## License

See [LICENSE](../../../LICENSE).
