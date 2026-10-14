# chio-process

Durable, capability-bound process trees for trusted Chio hosts.
`ProcessRuntime` journals process state in SQLite and sends logical tool calls
through the native kernel's durable admission coordinator.
`ProcessRegistry` lets native services share process identity without retaining
a kernel reference cycle.

## Usage

A host supplies an already configured kernel and a journal in a private directory.
This helper opens the runtime through its primary constructor:

```rust
use std::{path::Path, sync::Arc};
use chio_kernel::ChioKernel;
use chio_process::{ProcessError, ProcessRuntime};

fn open_processes(
    journal: &Path,
    kernel: Arc<ChioKernel>,
) -> Result<ProcessRuntime, ProcessError> {
    ProcessRuntime::open(journal, kernel)
}
```

The helper compiles with default features. Calling it requires
`DurableAdmissionMode::All` and a qualified durable authority store installed
on the kernel. The host issues a root capability, calls `create_root`, and uses
`tool_request` followed by `invoke` for process-bound work.
The journal contains capabilities and checkpoints; its directory is host-private.

## Features

| Feature | Default | Effect |
|---------|---------|--------|
| `default` | Yes, empty | Enables the process journal and trusted host APIs. |
| `worker-server` | No | Enables authenticated worker services; `WorkerServer` uses Unix sockets on Unix. |
| `mailboxes` | No | Enables the native `chio-ipc` mailbox tool server and durable message/claim storage. |

## Guarantees

- `ProcessRegistry::open` rejects kernels without all-call durable admission.
- `Store::open` binds a versioned journal to the authority UUID and kernel key.
- `spawn` and `validate_child` require one-hop capability attenuation.
- `invoke_with_recovery` freezes request identity, route, and security-profile bindings;
  attempt-scoped credentials are not part of the request identity.
- `invoke_known_only` prevents fresh dispatch after an unknown outcome.
- `read_blob` checks ownership and stored content hashes.

## Status

Implemented host library, with optional worker and mailbox surfaces.
Unknown side-effecting outcomes stay closed. Eligible read-only recovery is
bounded to three dispatch attempts. Cancellation blocks new admission and
withholds output, while an already admitted effect may finish.
Worker credentials need private delivery and OS isolation supplied by the host.

## Related

- [Architecture](ARCHITECTURE.md)
- [Capability verification](../../../spec/PROTOCOL.md#53-verification-rules)
- [Native kernel](../chio-kernel/README.md)
- [License](../../../LICENSE)
