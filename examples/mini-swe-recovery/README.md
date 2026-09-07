# mini-SWE-agent recovery through Chio

This qualification runs the installed mini-SWE-agent 2.4.6 coding loop with
Chio checkpoints and mediated commands. The upstream agent is inherited from
[its pinned release](https://github.com/SWE-agent/mini-swe-agent/blob/a83fcae82d2a08f0ee0c688f9d137b3566c097f8/src/minisweagent/agents/default.py).
Its existing model formatting, sequential tool calls, limits and completion
handling execute normally. No upstream source files are patched.

The fixture supplies three saved tool-call responses through upstream's
`DeterministicToolcallModel`. The commands repair a Python addition function and
run two existing tests in a disposable Docker container. After the patch tool
returns, SIGKILL stops the worker before its next checkpoint. SIGKILL then stops
the host. A fresh host and worker resume the same task with the original
decision, command identity and signed receipt.

Assertions require one patch effect, two distinct effects from identical audit
commands, five original receipts with verified signatures, three model queries,
passing repaired tests and an additional completed replay with no new effects
or model queries. This is installed application compatibility and controlled
recovery evidence. It does not establish live-model coding quality, comparative
performance, maintainer acceptance or independent adoption.

## Run

Linux, Docker and a Chio binary with the process host and signed native MCP
launch support are required. The caller must already have Docker access.

```sh
uv sync --project sdks/python/chio-mini-swe --locked --extra dev
uv run --project sdks/python/chio-mini-swe --locked --extra dev pytest -q sdks/python/chio-mini-swe/tests
MSWEA_SILENT_STARTUP=1 uv run --project sdks/python/chio-mini-swe --locked python examples/mini-swe-recovery/qualify.py --chio /absolute/path/to/chio --output /tmp/mini-swe-evidence
```

The output directory must be new. `--image` selects a Python image with bash;
the resolved image digest is recorded in the evidence. CI installs the built
Chio wheels before running the same qualification. The binary digest and
upstream package version are recorded with the result.

## Execution boundary

The default command above retains the original same-user worker profile. To
isolate the Python worker as well as the tool commands, build the local worker
image and select it explicitly:

```sh
docker --host unix:///var/run/docker.sock pull python:3.11-slim
python3 examples/mini-swe-recovery/build_worker_image.py --output /tmp/chio-worker-image.json
MSWEA_SILENT_STARTUP=1 uv run --project sdks/python/chio-mini-swe --locked python examples/mini-swe-recovery/qualify.py --chio /absolute/path/to/chio --worker-image-file /tmp/chio-worker-image.json --output /tmp/mini-swe-isolated-evidence
```

The builder resolves the base to its registry digest, installs dependencies from
the hash-locked export, installs built Chio wheels and records the resulting
local image ID. Nothing is pushed to a registry. The worker launcher accepts
only immutable installed IDs and refuses images declaring extra volumes.

The isolated profile runs the same agent and recovery assertions in fresh
worker containers. Runtime probes check that the worker cannot reach host
authority files or Docker's socket, cannot modify its RPC inputs or root
filesystem, has no external network route and cannot invoke an administrative
Chio method. It also checks actual capabilities, seccomp and scratch capacity.
Separate hostile programs prove timeout and output-limit cleanup, and an image
declaring an extra writable volume is refused before its worker starts.

See [the operator API and its boundaries](../../sdks/python/chio-process/WORKER_CONTAINERS.md).
The operator remains alive while the worker and Chio host are killed. Abrupt
operator death and native runner attempt-budget integration are not qualified.
This profile's network mode also excludes live hosted inference; the model
responses remain the saved upstream fixture.

The operator starts a container with no network, no bind mounts, a read-only
root filesystem, an unprivileged UID, dropped capabilities and bounded memory,
process count and temporary storage. The separate MCP bridge is pinned to that
container's full ID. Only command text and mini's tool-call metadata cross the
worker interface. The top-level `command` field lets Chio's shell guards inspect
the original command. The adapter stops on kernel denial, incomplete outcome,
an MCP error flag or an invalid result instead of requesting a replacement
decision.

The demo launch policy explicitly uses migration stage Disabled. It binds the
bridge command and signed manifest, and provides no OS containment for the
bridge or Python worker. Docker contains the tool commands. The default same-user
qualification does not establish isolation of an adversarial Python worker from
the host's Docker privileges. Deployments must put the worker in a separate
security boundary without Docker access, keep the privileged bridge on the
operator side and supply their own signed launch policy.

The Docker container survives the host interruption in this profile and is
removed at the end. Recovery of a lost container or its filesystem is outside
this profile. Command timeout or output overflow stops the agent; the operator
must inspect or terminate the sandbox because killing the Docker client does
not prove the command stopped. An interrupted host's Unix socket is removed
only after the harness has waited for that owned host to die.

## Native application recovery

The native profile runs the installed `chio-mini-swe-worker` under
`chio process run`. Chio owns container reconciliation, worker credentials and
attempt ceilings. Both model queries and commands cross scoped Chio tools;
the worker has neither provider credentials nor a network route. After building
the image above, run:

```sh
MSWEA_SILENT_STARTUP=1 uv run --project sdks/python/chio-mini-swe --locked python examples/mini-swe-recovery/qualify_native.py --chio /absolute/path/to/chio --worker-image-file /tmp/chio-worker-image.json --output /tmp/mini-swe-native-evidence
```

Three cases exercise the installed upstream loop. Baseline completes in one
attempt. Known-response recovery kills the host after its model response is
durable but before the agent checkpoint, then kills the replacement worker
after its patch receipt but before checkpoint. A third native attempt must
complete with three provider-fixture dispatches, one patch, two distinct audit
effects, and eight original verified receipts (three model, five command).
Replaying the completed plan must consume no attempt or provider query.

The unknown-response case pauses the gateway after dispatch, kills the host
and gateway, and restarts. The gateway deliberately misdeclares inference as
read-only. The worker's durable known-outcome-only policy must still stop it
with one provider dispatch, zero commands and a signed unknown-outcome denial.
The recovery policy cannot be relaxed on the original operation key.

The operator fixture asserts that its test credential is available only to
the gateway; the fault worker asserts that it receives neither that credential
nor Docker access, and verifies the unchanged upstream agent source. Full
trajectories and original receipts are read from the private process checkpoint
after worker exit, independently of bounded native stdout retention.

These cases use saved upstream decisions through the public model gateway.
They qualify application recovery, not live inference, provider-side retry
semantics or adoption. The demo gateway and sandbox bridge use explicitly
provisioned Disabled-stage launch policies; production tool-server containment
requires the operator's policy. The repository container survives worker/host
failure. Recovering a lost repository filesystem is outside this profile.
After host SIGKILL, a worker container can remain alive until that same native
host is restarted; an independent watchdog is not provided. Private state and
operator credentials remain under the printed temporary directory.
