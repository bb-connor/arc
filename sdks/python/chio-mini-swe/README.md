# mini-SWE-agent on Chio

Experimental adapter for mini-SWE-agent 2.4.6. `ChioAgent` inherits the upstream
`DefaultAgent` run loop and adds checkpoint hooks. `ChioEnvironment` routes its
commands through a host-selected Chio tool. Model selection, prompt formatting,
command order, step/cost limits and submission handling remain with mini.

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

The operator must provide the execution sandbox behind the configured tool.
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
