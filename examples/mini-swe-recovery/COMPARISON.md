# Compare the native coding session with upstream mini-SWE

This comparison runs mini-SWE-agent 2.4.6's actual `DefaultAgent`,
`DockerEnvironment` and `LitellmModel` against the installed Chio coding session.
Both execute the same committed calculator fixture, prompts, model decisions,
five shell commands and immutable execution image. Both must repair the source
and pass its tests. The source checkout stays unchanged.

The comparison uses a loopback Chat Completions endpoint and a literal fixture
credential. It makes no paid inference call. The endpoint returns three fixed
decision batches according to the conversation's assistant-message count.
It deliberately ignores observations, including whether an earlier attempt
already repaired the workspace. Results describe this fixed-decision recovery
contract, not how a live model would respond to a repaired repository.

## Run the comparison

Use the protected installed environment and immutable images described in
[SESSION.md](../../sdks/python/chio-mini-swe/SESSION.md). Supply a protected,
stable native CLI executable. The comparison references that executable
directly and records its digest. It builds one local fault-instrumented worker
image from the supplied worker image; it neither installs dependencies nor
publishes an image.

Retain the supplied CLI's build profile and compiler flags alongside the
reports. The CI workflow uses a development build for compatibility checks.
Use an optimized release build before drawing native performance conclusions;
development-build hashing and other runtime work can dominate these timings.

```sh
umask 077
PYTHONDONTWRITEBYTECODE=1 /private/coding-venv/bin/python \
  examples/mini-swe-recovery/compare.py \
  --chio /private/bin/chio \
  --worker-image-file /private/repository-images.json \
  --trials 2 \
  --output /private/mini-swe-comparison
```

Each trial runs the uninterrupted and returned-patch crash scenarios through
both execution paths. Execution order alternates by trial and scenario.
The first run is not a cold-machine measurement: the input images and installed
dependencies already exist. There is no intentional provider delay in timing
trials. One trial is a compatibility smoke test; repeated trials expose some
local variation without establishing a broad performance result.

`progress.json` identifies the live case and its private working directory.
Completed cases produce individual JSON reports. The final `comparison.json`
is written only after all requested cases and shared oracles pass. A failed
run's partial reports remain diagnostic evidence.

Private state retains commands, diagnostics, trajectories, fixture launch
authority, source imports and verified exports. Share only the comparison
reports after inspecting them. Do not publish the private native host directory
or its launch keys.

## What differs between the paths

The upstream parent retains one real `DockerEnvironment` instance. Each attempt
runs a fresh upstream `DefaultAgent` and `LitellmModel`. The native path runs
the installed session commands, mediates model calls and repository commands,
checkpoints the agent, and snapshots the repository after each command in a
separate bounded container lease. Chio's worker runs in its native container
profile; the upstream agent runs as the comparison's local child process.
This measures complete execution configurations, not isolated kernel overhead.

The execution image, unprivileged UID/GID, network denial, read-only root,
capability drop, process/memory/CPU limits, shell flags, command timeout and
workspace capacity are aligned. Upstream retains its bounded workspace tmpfs;
Chio restores a fresh bounded workspace lease for each command. Reports retain
both paths' image identities and the upstream container's actual Docker
configuration. Upstream agent
source hashes must match the agent source executing inside the native fault
worker. The Python interpreter and model transport implementations can differ
between the installed upstream driver and native worker architecture.

Chio's comparison authority is explicitly issued by the harness using
Disabled-stage fixture policies. Product session commands still consume
operator-supplied signed policies. This comparison does not qualify production
tool containment or grant an operator's provider credentials to an agent.

## Crash and result oracles

In the crash scenario, the first worker dies immediately after the patch command
returns and before the agent records the next step. The native fault hook runs
after the real Chio invocation returns its original signed receipt. The upstream
hook runs after the real `DockerEnvironment.execute` returns. Neither changes
the upstream control loop or substitutes a callback command executor.

The upstream default agent has no built-in partial-batch resume method. Its
original SIGKILL is recorded as a stopped process. The comparison parent then
explicitly starts a fresh agent over the retained workspace, without restoring
the saved trajectory. This is an operator rerun policy, not upstream automatic
recovery. Observed requests and effects from both attempts are retained.

Every clean case must submit, pass the repaired tests, make three provider
requests and leave the effects `patched`, `audit`, `audit`. The two identical
audit commands are distinct requested operations. The native crash case must
show the injected event, complete on its second attempt with the same three
provider requests and effects, and retain the crash-boundary receipt unchanged
among eight independently verified receipts. Its five workspace transitions
and exported patch are verified against the recipient's own Git source and
separately supplied kernel public key.

The controlled upstream crash case must record the original SIGKILL and the
explicit second attempt, with five provider requests and the observed effects
`patched`, `patched`, `audit`, `audit`. This oracle depends on the fixture's
decision sequence ignoring the already repaired source.

The native result is read after removing the provider credential and the
captured provider configuration. Upstream exports its final files and saved
trajectories; those artifacts do not have Chio's receipt verification.

## Measurements and operational limits

Reports separate preparation, execution and export wall time. Native fixture
authority provisioning and recipient verification are separate measurements.
Raw provider request counts and observed effects are the recovery measurements.
Fixed usage values and configured prices are synthetic; they support no claim
about actual billing savings or model quality.

Driver and waited-child CPU measurements exclude Docker daemon and container
cgroup work. Complete system CPU and container memory accounting are marked
unavailable. Do not interpret these partial counters as total operating cost
or compare a reported native container zero with a host process's resident
memory. Retained native-state size is reported separately from the upstream
trajectory/export artifacts.

The upstream driver records each worker PID and start time durably before a
pipe releases it to execute, and records exact container ownership. Its own
watchdog precedes the outer observation deadline. On driver failure, fallback
cleanup validates private records, process UID/start time/exact arguments and
container ID/owner/image. It signals the pinned process through a Linux pidfd;
it never signals a reused numeric PID or deletes a mismatched container.
Uncertain ownership is preserved and reported as unresolved cleanup.

The fixture is deliberately small. It establishes execution compatibility,
this crash-recovery behavior and local timing. Independent adoption,
representative repository tasks, live-model success rates, production
containment and broader performance remain separate work.
