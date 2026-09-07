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
bridge or Python worker. Docker contains the tool commands. This same-user
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
