# Native container workers

`chio process run` can supervise Docker workers using the same process identity,
checkpoint, attempt budget, dependency graph and credential rotation as direct
workers. This Linux profile requires a non-root operator and the local rootful
Docker engine at `/var/run/docker.sock`, with built-in seccomp and no user
remapping. Cgroup v2 and engine support for memory, swap, CPU quota and PID limits
are required. Docker and the shared Linux kernel are trusted host components.

Initialize a [process host](PROCESS_HOST.md), install an image containing the
worker application and its dependencies, then select its immutable local image
ID in a [run plan](PROCESS_RUNNER.md):

```json
{
  "schema": "chio.process.run.v1",
  "max_parallel": 2,
  "workers": [{
    "process": "root",
    "container": {"image": "sha256:<64 lowercase hexadecimal characters>"},
    "command": ["/usr/local/bin/python", "/app/worker.py"],
    "cwd": "/work",
    "input": {"task": "Review the assigned repository"},
    "max_attempts": 3,
    "timeout_seconds": 300
  }]
}
```

Replace the image placeholder with an installed image ID. The runner does not
pull images. `command` is literal argv inside the image and replaces its
entrypoint. `cwd` must be `/work`. Adaptive templates accept the same `container`
field, and container and direct workers share the plan's concurrency ceiling.
Worker source and dependencies belong in the image; host source directories are
not mounted. The image's own environment remains part of its application, so
images must not contain host or provider secrets.

The worker reads one `chio.process.worker-bootstrap.v1` document from stdin and
then EOF. Its connection descriptor points to `/run/chio/process.sock`. The
credential is scoped to its process and rotates between attempts. Applications
must keep logical tool-operation keys stable across attempts. The bootstrap's
attempt number is diagnostic, and must not become part of those keys.

## Worker boundary

Only the current private worker socket inode is mounted from the host, read-only.
The authority databases, host directory, Docker socket and operator environment
are not exposed. The worker runs as the operator's numeric UID/GID with all Linux
capabilities dropped, `no-new-privileges`, the engine's built-in seccomp policy,
private namespaces, no external network and a read-only root filesystem.

The fixed limits are 512 MiB RAM with no additional swap, one CPU, 64 processes,
8 MiB shared memory, 64 MiB `/work` and 16 MiB `/tmp` tmpfs mounts. Scratch mounts
are `noexec,nosuid,nodev`. Core dumps are disabled; open files are capped at 128
and individual files at 16 MiB. Image-declared volumes are rejected. Restart,
health checks and Docker log persistence are disabled. The plan cannot override
these controls or combine this profile with direct-worker `resources`.

The runner enforces the attempt deadline and a 2 MiB combined stdout/stderr
ceiling, sampled every 50 ms. It retains at most 64 KiB from each stream and
redacts the current credential in retained logs. Output may exceed the sampling
ceiling briefly before attachment termination and engine cleanup. Docker control
commands have separate 30-second deadlines and 64 KiB output ceilings. Slow or
unavailable engine control can prevent prompt removal and causes the run to fail.
Container startup and cleanup run in each worker's scheduler slot, so they do
not block another worker's deadline supervision.

The resource limits apply to the container. Final cgroup CPU and peak memory
measurements are currently unavailable; reports and `process status` mark them
`unavailable_container_cgroup` and use zero placeholders. Direct workers retain
their existing `wait4` measurements. The Docker client's usage is never reported
as container usage.

## Host death and recovery

The private `runner.db` binds each container intent to its process, reserved
attempt, engine identity and random owner. The runner commits a create-only
intent before contacting Docker, then commits the exact returned container ID
before sending any start request. An interrupted create with no committed ID
cannot have received a start request from this runner.

On normal exit, timeout, output overflow or cooperative suspension, supervision
checks the actual container state and removes the exact owned container before
the attempt is recorded and another attempt starts. Attachment exit alone is
not proof of successful worker completion. Removal verifies both owner and name;
an engine failure is never interpreted as absence.

On SIGINT/SIGTERM, the runner stops its active attachments, revokes credentials,
reconciles its container records and drains the host. SIGKILL can leave a
container running with its fixed resource limits until the operator restarts
the same host and plan. There is no independent Docker-side wall-clock watchdog.
Startup revokes old credentials and removes recorded containers before binding
a new listener or launching replacements. Host loss consumes the reserved
attempt. A changed engine identity or container name fails closed before a new
attempt is reserved.

If a create request lost its response and no object is yet visible, its record
is retained. A late create can leave an inert container; later startup/shutdown
sweeps remove it once visible. An absent object alone cannot prove that an
in-flight create finished. This conservative record can remain unresolved if
the create never materializes. Preserve the original state and engine for
operator investigation; this version provides no override to forget uncertain
creation. `process export` refuses unresolved ownership before retiring the
authority. The run report exposes `pending_container_records` and cannot claim
completion while any remain. Export works after all records are reconciled.

## Qualification

`tests/process_host/container_runner.py` exercises the real native binary and
local Docker engine. It uses a prebuilt Python image with the installed
`chio-process` package, supplied through `--image-file`, and retains a JSON
evidence artifact. It checks worker and host death, original receipt replay,
credential rotation, isolation, cleanup, restart exhaustion, output and deadline
limits, and refusal of changed container ownership.

The separate Python [one-attempt helper](../../../sdks/python/chio-process/WORKER_CONTAINERS.md)
keeps its existing operator-lifetime contract. Its mini-SWE-agent qualification
does not itself establish native runner integration or live model effectiveness.
