# Container workers on a local Linux host

`chio_process.container.run_container_worker` is an operator-side launcher for
one Python worker attempt. The trusted operator retains Docker access and
supplies an immutable, already installed image ID, application bytes and a
private Chio connection descriptor. The worker receives its own scoped RPC
authority. It receives no Docker administration handle or host state directory.

For persistent attempt budgets and cleanup after host restart, use the
[native container runner](../../../crates/products/chio-cli/PROCESS_CONTAINERS.md).
This Python helper retains the one-attempt contract described below.

```python
from pathlib import Path
from chio_process.container import run_container_worker

attempt = run_container_worker(
    image=installed_image_id,
    connection=private_descriptor,
    program=Path("my_worker.py").read_bytes(),
    arguments=["--connection", "/run/chio/connection.json"],
    timeout=120,
)
print(attempt.exit_code)
consume_bounded_worker_output(attempt.output)
```

The worker image must provide Python at `/usr/local/bin/python`. The launcher
overrides its entrypoint and disables image healthchecks. It refuses mutable
image tags, images declaring additional volumes, non-private sockets, symlinked
sockets and socket paths containing mount-option delimiters. No image is pulled
implicitly. This initial profile uses the local Linux Docker engine at
`unix:///var/run/docker.sock`, a non-root operator UID and the engine's default
seccomp profile. Rootless engines, user namespace remapping, Docker Desktop and
remote engines are outside the qualified profile.

## Worker access

Cgroup v2 and engine support for memory, swap, CPU quota and PID limits are
required. Unsupported or missing limits are refused before image inspection or
worker creation; launch options alone are insufficient evidence of enforcement.

The worker runs as the operator's numeric UID inside separate Docker namespaces,
with all capabilities dropped and `no-new-privileges` enabled. Its root filesystem
is read-only, network mode is `none`, and it has three read-only bind mounts:

| Worker path | Content |
| --- | --- |
| `/run/chio/process.sock` | The socket inode for its Chio worker service |
| `/run/chio/connection.json` | Its credential and the socket's container path |
| `/app/worker.py` | An operator-owned private copy of the application bytes |

A read-only socket mount still permits RPC. Chio's authenticated worker protocol
and capability checks govern the allowed methods and tool calls. The worker
cannot change the socket's host permissions or obtain an administrative API.
The descriptor is separate from the authority databases and signing keys.

Writable scratch consists of a 64 MiB `/work` tmpfs, 16 MiB `/tmp` tmpfs and
8 MiB shared memory. Memory is capped at 512 MiB with no additional swap, CPU at
one core, and process count at 64. Core dumps are disabled, open files are capped
at 128 and individual files at 16 MiB. Worker stdout/stderr is collected with a
separate byte ceiling (2 MiB by default, at most 8 MiB). There is no writable
host artifact directory and no persistent Docker log stream.

## Lifetime and recovery

The operator removes the actual container on normal completion, nonzero exit,
timeout or output overflow. It closes the Docker attachment before removing the
container so an unread output pipe cannot block cleanup. Killing the Docker
client alone never establishes that the worker stopped. Cleanup errors propagate
instead of reporting a completed attempt.

The operator process must remain alive to enforce its wall-clock deadline and
perform cleanup. Abrupt death of that operator, loss of Docker or loss of the
machine requires operator reconciliation; this helper has no durable orphan
reconciler. It also does not maintain the native runner's persistent attempt
budget or rotate worker credentials. It executes one explicitly requested
attempt and never retries automatically.

Scratch is disposable. Keep application progress in Chio checkpoints and blobs.
On restart, create a fresh worker bound to the current socket inode and resume
the same application/process identity. Treat returned bytes as untrusted data;
they must not select host paths or commands. Docker and the shared Linux kernel
remain trusted parts of this boundary. The profile does not claim resistance
to all container escapes.

The [mini-SWE-agent qualification](../../../examples/mini-swe-recovery/README.md)
tests actual namespace access, admin refusal, timeout/output cleanup and recovery
after both worker and Chio host death. The trusted operator survives that test.

Docker's [run reference](https://docs.docker.com/engine/containers/run/) and
[bind-mount documentation](https://docs.docker.com/engine/storage/bind-mounts/)
describe the underlying controls. The qualification checks the resulting
container and process state in addition to inspecting launch options.
