# mini-SWE-agent on Chio

Experimental adapter for mini-SWE-agent 2.4.6. `ChioAgent` inherits the upstream
`DefaultAgent` run loop and adds checkpoint hooks. `ChioEnvironment` routes its
commands through a host-selected Chio tool. Model selection, prompt formatting,
command order, step/cost limits and submission handling remain with mini.

The [installed session workflow](SESSION.md) connects repository import,
operator provisioning, native execution and verified patch export through
`chio-mini-swe session`. It emits an unsigned provisioning request and consumes
explicit signed launch policies before preparing a task.

The [operator commands](OPERATOR.md) prepare and run native coding tasks using
provisioned tool servers. `chio-mini-swe-model` serves a configured Chat
Completions endpoint without custom gateway Python. `chio-mini-swe result`
exports and verifies retained results without starting tools or obtaining a
worker credential, including after cancellation or capability expiry.

The [repository service](REPOSITORY.md) supplies the execution tool for a selected
Git commit. It persists completed workspace snapshots and exports a reviewable
patch with optional verification against the original Chio receipts.
Recipients can use `chio-mini-swe-repository verify-export` to check that bundle
against their own source commit and trusted kernel key, without the producer's
private state or a running Docker engine.

Use one fresh agent instance per attempt, the same task/configuration and
`run_id` on restart, and the same authenticated Chio process. `model_id` is an
operator-selected identity for the provider configuration. This adapter owns
that process's checkpoint. Model and tool output are stored in private immutable
blobs, with an 8 MiB snapshot limit and the host's persistent storage quotas.
This first profile stores full conversation snapshots. Long trajectories can
exhaust the host's cumulative storage quota and then stop; automatic compaction
and storage reclamation are not implemented in this adapter.

Completed provider responses are saved before any command runs. Recovery uses
the original turn and command ordinal, so identical commands in different turns
remain distinct operations. An incomplete provider response stops recovery.
Kernel denials and unknown command outcomes stop the agent instead of becoming
observations that invite a fresh command. No retry grants additional authority.

The operator configures the execution sandbox behind the selected tool.
The Python adapter itself does not sandbox agent code. A worker must not also
receive a local shell callback, sandbox administration credentials or Docker
socket access. Wall-clock limits include time spent stopped between attempts.
Interactive agents and externally mutated conversation histories are outside
this initial profile. Compatibility tests do not establish external adoption.

## Integration

Keep the application's existing model instance and default-agent configuration:

```python
from chio_mini_swe import ChioAgent, ChioEnvironment
from chio_process import ProcessClient

client = ProcessClient(connection["socket_path"], connection["credential"])
environment = ChioEnvironment(
    client,
    server_id="sandbox",
    tool_name="execute",
    template_vars={"cwd": "/workspace"},
)
agent = ChioAgent(
    model,
    environment,
    run_id="issue-123-attempted-repair",
    model_id="operator-pinned-provider-configuration",
    **agent_config,
)
result = agent.run(task)
```

The private connection descriptor comes from `chio process credential`, or the
equivalent native worker launch. Keep it out of model prompts and trajectories.
`agent_config` is the same keyword configuration accepted by upstream
`DefaultAgent`. Resume with the same values; the output trajectory path may
change. The original start time and accrued model costs survive restart.

The host-selected tool accepts mini's action fields directly, including
`command` and optional `tool_call_id`. It returns `output` (string), `returncode`
(integer), and `exception_info` (string), directly or as MCP `structuredContent`.
An MCP `isError` flag stops execution even if structured output is present.
The usual `COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT` marker retains mini's
submission behavior.

The [Docker qualification](../../../examples/mini-swe-recovery/README.md) includes
a bounded operator-side bridge and real worker/host crash recovery. Its README
describes the supported isolation and recovery boundaries.

## Native worker and mediated inference

The installed `chio-mini-swe-worker` entrypoint reads a native
`chio.process.worker-bootstrap.v1` message from stdin. Run it in the native
runner's [container backend](../../../crates/products/chio-cli/PROCESS_RUNNER.md)
with both model and execution tools granted to the same child process. Its
`input` has this shape:

```json
{
  "schema": "chio.mini-swe.worker.v1",
  "run_id": "issue-123-repair",
  "task": "Fix the failing addition tests.",
  "model": {
    "server_id": "model",
    "tool_name": "model_infer",
    "model_id": "operator-pinned-provider-configuration"
  },
  "environment": {
    "server_id": "sandbox",
    "tool_name": "execute",
    "template_vars": {"cwd": "/workspace"}
  },
  "agent": {
    "system_template": "Repair the repository using bash commands.",
    "instance_template": "{{task}}",
    "step_limit": 8,
    "cost_limit": 10,
    "wall_time_limit_seconds": 600
  }
}
```

The entrypoint requires positive bounded step, cost and total elapsed-time
limits. It accepts prompt settings and granted routes; provider configuration
and output paths are rejected. Credentials arrive privately through the native
bootstrap. Native attempt numbers never change model or command operation keys.

`ChioModel` routes inference through Chio with `known_outcome_only=True`.
Completed responses and their original signed receipts can survive host death
before the agent checkpoint. Unknown outcomes stop the task even when a model
tool is mistakenly declared read-only. Existing integrations using a direct
model instance retain their stricter application checkpoint boundary: a response
lost before checkpoint cannot be reconstructed automatically.

On the operator side, wrap one configured upstream tool-call model instance:

```python
from chio_mini_swe.gateway import serve

# model is the operator's existing, configured upstream mini-SWE model.
serve(model, model_id="operator-pinned-provider-configuration")
```

Provision this gateway under a signed native MCP launch policy. Keep its
provider access outside the worker, and use a stable identity for the exact
provider/model/options configuration. Replacing that configuration under the
same identity is not verified by the adapter. The worker receives no API key,
network route or provider-selection callback. The gateway accepts only the
bound model identity, logical turn and conversation, and adds no provider
retries. Configure retries and billing limits on the underlying model/provider:
Chio's replay guarantee does not control their internal retry behavior, and
upstream cost limits are checked between queries, not before provider billing.

The gateway contract uses `chio.mini-swe.model-query.v1` requests and
`chio.mini-swe.model-result.v1` responses. This profile accepts upstream
OpenAI-style `bash` tool calls whose IDs and command arguments exactly match
their parsed action batch, with finite nonnegative cost. A format error carries
one user observation with its cost. Malformed responses and provider failures
stop execution; provider exception details are withheld from the worker. This
profile does not support arbitrary model dialects or streaming inference.

Stdout contains a bounded result locator and short submission preview. Read the
full completed trajectory with `chio_mini_swe.worker.export_result(client)` using
a privately issued credential for the same process. It reads retained state
without invoking tools. Native container cleanup, attempt ceilings and the
remaining host-loss limits are described in the runner documentation. The
[native qualification](../../../examples/mini-swe-recovery/README.md#native-application-recovery)
uses saved model responses and makes no live-provider quality claim.
