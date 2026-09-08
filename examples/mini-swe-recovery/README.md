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

The installed state qualification exercises a longer synthetic conversation
through the native blob and checkpoint API, without invoking a model or tool:

```sh
/private/coding-venv/bin/python examples/mini-swe-recovery/qualify_state.py --chio /absolute/path/to/chio --output /tmp/mini-swe-state-evidence
```

It retains 120 turns with 4 KiB observations and three checkpoints per turn
under the default 64 MiB storage quota. Assertions cover complete history,
recovery after the host dies following a committed checkpoint whose reply is
lost, and offline reads without a worker credential or changes to database
pages and WAL contents. SQLite may create empty WAL and reader bookkeeping
files during read-only access.
The report records storage use, native and offline elapsed times, and installed
source identities. This tests storage and recovery, not live coding ability;
the model request size, tool budget and cumulative storage quotas still apply.

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

## Installed operator workflow

After installing the built Chio wheels into the operator environment and
building the worker image, run:

```sh
MSWEA_SILENT_STARTUP=1 uv run --project sdks/python/chio-mini-swe --locked python examples/mini-swe-recovery/qualify_operator.py --chio /absolute/path/to/chio --worker-image-file /tmp/chio-worker-image.json --output /tmp/mini-swe-operator-evidence
```

This exercises the installed `chio-mini-swe-model` and `chio-mini-swe` commands
outside the checkout. A controlled loopback HTTP endpoint returns the saved
coding decisions through the real Chat Completions transport. Assertions cover
the selected authorization header, model name and output-token limit, three
HTTP requests, one patch, two distinct audits, passing repaired tests and eight
verified receipts. Changed provider settings refuse before the native run.
Completed runs perform no new work.

After cancellation, the provider configuration is removed. Result export must
still succeed without starting tools or changing retained host files. A second
task receives HTTP 500: its two native attempts must issue only one HTTP request
and perform no new repository effect. The fixture provides explicit local-only
credentials and prices. No live model, external account or paid inference is
used. Its Disabled-stage tool policies are explicit test provisioning; the
[operator command](../../sdks/python/chio-mini-swe/OPERATOR.md) requires an
already provisioned signed policy and never weakens that policy.

## Installed repository service

The [repository service](../../sdks/python/chio-mini-swe/REPOSITORY.md) imports a
selected Git commit, persists completed command snapshots and exports a patch
whose workspace transitions can be checked against original Chio receipts.
It also supplies the execution backend for the installed coding operator.

```sh
python3 examples/mini-swe-recovery/build_repository_image.py \
  --worker-image-file /private/worker-image.json --output /private/repository-images.json
/private/coding-venv/bin/python examples/mini-swe-recovery/qualify_operator.py \
  --chio /private/bin/chio --worker-image-file /private/repository-images.json \
  --repository-service --output /private/repository-operator-evidence
/private/coding-venv/bin/python examples/mini-swe-recovery/qualify_repository.py \
  --worker-image-file /private/repository-images.json --output /private/repository-failure-evidence
```

The operator trial uses a committed Git fixture with binary data and a relative
symlink. It leaves dirty and untracked source data untouched, verifies the
exported patch applies to the imported baseline, and checks five workspace
transitions against eight verified model and command receipts. A forged receipt
must fail before creating a verified export directory. Provider responses remain
controlled HTTP fixtures.
The first repository command sleeps for 65 seconds, exercising the configured
host deadline and native worker socket deadline beyond their former defaults.

The separate repository profiles measure container limits and credential
isolation, exercise Git and background-process cleanup, preserve an unowned
container on an ownership mismatch, and reject timeouts, raw or escaped oversized output,
escaping symlinks and special files. A real service SIGKILL after a partial file
write must recover owned resources, retain the prior committed snapshot and
refuse automatic redispatch. These tests do not qualify an independent watchdog
or live-model coding quality.

`qualify_repository_storage.py` runs a separate installed component trial with
24 MiB of deterministic incompressible files and sixteen one-byte appends. It
reopens the workspace between commands, verifies every historical archive and
unchanged payload, checks owned-container cleanup and requires accounted storage
below 64 MiB. The trial guards against storing a full copy of the unchanged tree
on each command. It does not exercise model decisions or kernel receipts; the
operator and session trials above cover receipt and export integration.

To exercise a separate Python project with `src/` and `README.md`, point this
trial at an existing local checkout and a selected commit:

```sh
/private/coding-venv/bin/python examples/mini-swe-recovery/qualify_public_repository.py \
  --chio /private/bin/chio --worker-image-file /private/repository-images.json \
  --repository /code/project --revision <commit> --output /private/public-repository-evidence
```

This imports the selected tree, compiles its Python sources, replays a completed
command after host restart, and exports a README probe patch bound to two
verified receipts. It checks a command longer than 60 seconds, large ASCII and
escaped output, patch applicability and an unchanged source checkout. It uses
explicit qualification commands. It does not assess model coding quality or
submit a change to the source project's maintainers.

## Installed coding session

The [session command](../../sdks/python/chio-mini-swe/SESSION.md) combines Git
import, exact tool provisioning requests, native execution and verified result
export. Install the wheels into a dedicated environment using copies, then
protect that environment and run the installed qualification:

```sh
umask 077
/private/coding-venv/bin/python examples/mini-swe-recovery/prepare_session_environment.py
/private/coding-venv/bin/python examples/mini-swe-recovery/qualify_session.py \
  --chio /private/bin/chio --worker-image-file /private/repository-images.json \
  --output /private/coding-session-evidence
```

The trial initializes without provider credentials or inference, supplies
separately provisioned signed fixture policies, and executes the controlled
coding task through the installed session commands. A 65-second first model
response crosses the former request deadline. Holding the native host lock
must prevent recovery and export; replaying a completed task makes no new
provider request. After stopping the provider and removing its configuration,
offline export combines eight verified receipts with five repository
transitions. A recipient verifies the exported patch against its own source
commit and separately supplied kernel key. The source checkout stays unchanged.

Fixture authority uses explicit Disabled-stage launch policies and a literal
test credential. The session command itself requires operator-supplied signed
policies and never generates authority. This trial qualifies the installed
lifecycle with controlled model responses; it does not measure live-model
coding quality or qualify a production deployment.

## Compare with upstream execution

The [upstream comparison](COMPARISON.md) runs the actual installed mini-SWE
Docker environment and native Chio session on the same task and fixed provider
decisions. It records clean execution and a crash after a returned patch,
checks repaired source and effects, and separates preparation, execution and
export timing. Upstream reruns are explicit operator actions. The controlled
provider supports no live-model quality or billing claim.
