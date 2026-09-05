# chio-langgraph

LangGraph integration for the [Chio protocol](../../../spec/PROTOCOL.md).
Plugs into LangGraph's state-graph model so every node transition is
capability-checked via the Chio sidecar kernel, and HITL approval nodes
bridge LangGraph's `interrupt()` pause/resume cycle to Chio's
`Verdict::PendingApproval` path.

## Install

```bash
uv pip install chio-langgraph
# or
pip install chio-langgraph
```

The package depends on `chio-sdk-python`, `langgraph>=0.6,<2`, and
`pydantic>=2.5`.

## Durable process tools

`ChioProcessToolNode` executes tools through an authenticated Chio process
while LangGraph keeps the model, graph control flow and checkpoint store.
Use it as the tool node in a `MessagesState` graph. The host must already
provision the process, its capability and its tool servers using
[chio-process](../../../crates/kernel/chio-process/WORKER_PROTOCOL.md).

Install the experimental process extra from this checkout:

```bash
uv sync --project sdks/python/chio-langgraph --locked --extra process --extra dev
```

```python
from chio_process import ProcessClient
from chio_langgraph import ChioProcessToolNode, ProcessTool

# The trusted host delivers these privately. Keep credentials out of graph
# state, RunnableConfig, model prompts and tracing metadata.
client = ProcessClient(socket_path, credential)
tool_node = ChioProcessToolNode(client, [
    ProcessTool("publish_report", "reports", "publish", "Publish a report.", {
        "type": "object",
        "properties": {"report": {"type": "string"}},
        "required": ["report"],
    }),
], namespace="research-workflow-v1")

model_with_tools = model.bind_tools(tool_node.model_schemas())
builder.add_node("tools", tool_node)
app = builder.compile(checkpointer=your_persistent_checkpointer)
config = {"configurable": {"thread_id": "research-42"}}
result = app.invoke(initial_state, config, durability="sync")
# After restarting the worker, rebuild with its host-issued credential and
# resume the same graph thread from the existing checkpoint.
result = app.invoke(None, config, durability="sync")
```

The stable operation key includes the configured namespace, thread id,
persisted assistant message id and tool-call id. Missing ids, duplicate call
ids or unconfigured tools reject before batch dispatch. The `MessagesState`
reducer assigns message ids; a persistent checkpointer retains them across
restart. Recreating an earlier prompt and asking the model for a new plan is
a new operation, not recovery. Keep the namespace stable when resuming.

Tool name and arguments are excluded from the identity hash so changing them
under a persisted call id produces a kernel conflict rather than another
effect. Credential rotation likewise preserves the operation key. The host
selects model aliases and kernel tool routes; the model supplies arguments.

Successful results are standard `ToolMessage` objects. The tool output is
model-visible content; the original signed `receipt_json` and kernel response
are retained in `message.artifact["chio"]`. This adapter preserves receipt text
without independently verifying it. Transport failures, kernel denials,
pending approvals and incomplete results raise and stop the graph. They must
not be converted to a new model tool request to retry an uncertain effect.
Previously admitted siblings may finish; resume the original checkpoint to
recover their results under the same identities.

The node supports at most 64 calls per assistant message and up to 32 active
client calls per batch, with a default of four. RunnableConfig's
`max_concurrency` can reduce this configured ceiling. Sync and async graph
invocation are supported.
This profile does not execute local callbacks, inject graph state/store into
tools, or interpret tool output as LangGraph `Command` objects. Keep planning
nodes local and install effectful tools in the kernel's existing tool-server
adapters. OS isolation remains a host responsibility.

The existing `chio_node` and approval wrappers remain available for sidecar
authorization around local node bodies. Their local effects do not acquire
the process runtime's operation journal or recovery behavior.

### Reproduce the failure comparison

```bash
uv sync --project sdks/python/chio-langgraph --locked --extra process --extra dev
cargo run -p chio-process --features worker-server --example langgraph_report
```

The same deterministic report graph runs with native LangGraph `ToolNode`
and with `ChioProcessToolNode`. Both use persistent `SqliteSaver` checkpoints
and synchronous durability. The worker exits after publication returns but
before the LangGraph node checkpoint. On resume, the native tool publishes
again; Chio recovers the original signed receipt and retains one publication.
A third run gives the graph read-only authority and must stop before publishing.
The Rust host verifies returned receipt signatures against its fixture key.

The example writes `target/langgraph-report/report.md` and `comparison.json`.
It records framework versions, completion, publication counts and worker wall
time. Time includes interpreter startup, graph recovery and tools; it is not
a kernel latency benchmark. The graph's planning trace is deterministic and
uses no LLM. The native publication tool has no external idempotency mechanism;
applications that already provide one may avoid the same duplicate. This
experiment establishes one recovery boundary, not a general framework ranking
or evidence of external adoption.

The adapter suite and failure comparison run on the locked LangGraph 1.2.11
profile and the hash-pinned 0.6.11 compatibility profile in CI. The compatibility
overlay is in `qualification/compatibility.txt`. Optional `CHIO_LANGGRAPH_PYTHON`
and `CHIO_GRAPH_REPORT_OUTPUT` select an installed interpreter and evidence
directory for the Rust example.

Framework contracts: [LangGraph checkpointers](https://docs.langchain.com/oss/python/langgraph/persistence)
and [ToolNode](https://reference.langchain.com/python/langgraph.prebuilt/tool_node/ToolNode).

## Quickstart

```python
import asyncio
from typing import TypedDict

from chio_sdk.client import ChioClient
from chio_sdk.models import ChioScope, Operation, ToolGrant
from chio_langgraph import ChioGraphConfig, chio_node
from langgraph.graph import StateGraph, START, END


class AgentState(TypedDict, total=False):
    value: str


def _scope(*tools: str) -> ChioScope:
    return ChioScope(
        grants=[
            ToolGrant(
                server_id="tools-srv",
                tool_name=name,
                operations=[Operation.INVOKE],
            )
            for name in tools
        ]
    )


def search_node(state: AgentState) -> dict:
    return {"value": f"searched:{state['value']}"}


def write_node(state: AgentState) -> dict:
    return {"value": f"wrote:{state['value']}"}


async def main() -> None:
    async with ChioClient("http://127.0.0.1:9090") as chio:
        cfg = ChioGraphConfig(
            chio_client=chio,
            workflow_scope=_scope("search", "write"),
            node_scopes={
                "search": _scope("search"),
                "write": _scope("write"),
            },
            subject="agent:demo",
        )
        await cfg.provision()

        graph = StateGraph(AgentState)
        graph.add_node("search", chio_node(search_node, scope=_scope("search"), config=cfg))
        graph.add_node("write", chio_node(write_node, scope=_scope("write"), config=cfg))
        graph.add_edge(START, "search")
        graph.add_edge("search", "write")
        graph.add_edge("write", END)
        app = graph.compile()

        result = await app.ainvoke({"value": "hello"})
        print(result)


asyncio.run(main())
```

At runtime:

* Each node dispatch is evaluated by the Chio sidecar with the node's
  capability token before the wrapped body runs.
* Nodes whose capability scope does not authorise their action raise
  `ChioLangGraphError` -- LangGraph surfaces the exception through its
  standard error path.
* Per-node receipts are signed by the kernel and chained.

## HITL approval node

`chio_approval_node` wraps a node that must wait for a human decision.
It posts an approval request (optionally to the sidecar's `/approvals`
surface via a dispatcher hook), pauses the graph with
`langgraph.types.interrupt`, and resumes when the caller hands back a
decision through `Command(resume=...)`.

```python
from langgraph.graph import StateGraph, START, END
from langgraph.types import Command
from langgraph.checkpoint.memory import MemorySaver

from chio_langgraph import chio_approval_node


async def run_dangerous(state: AgentState) -> dict:
    # Only reached after a human approves.
    return {"value": f"executed:{state['value']}"}


async def main() -> None:
    cfg = ChioGraphConfig(chio_client=chio, node_scopes={"danger": _scope("danger")})
    await cfg.provision()

    wrapped = chio_approval_node(
        run_dangerous,
        scope=_scope("danger"),
        config=cfg,
        name="danger",
        summary="Please approve deletion of the production bucket",
    )

    graph = StateGraph(AgentState)
    graph.add_node("danger", wrapped)
    graph.add_edge(START, "danger")
    graph.add_edge("danger", END)
    app = graph.compile(checkpointer=MemorySaver())

    config = {"configurable": {"thread_id": "wf-1"}}

    # First invocation pauses at the approval node.
    first = await app.ainvoke({"value": "x"}, config=config)
    pending = first["__interrupt__"][0].value
    # Human reviews `pending` and decides.
    resumed = await app.ainvoke(
        Command(resume={"outcome": "approved", "approver": "ops@acme"}),
        config=config,
    )
    print(resumed)
```

The resume payload is normalised into an `ApprovalResolution`. The
wrapper accepts any of these shapes:

* `{"outcome": "approved" | "denied" | "rejected", "reason": "...", "approver": "..."}`
* `ApprovalResolution(outcome="approved", ...)`
* `True` / `False`
* `"approved"` / `"denied"` / `"rejected"` (plain string)

A denied or rejected decision raises `ChioLangGraphError` carrying the
`approval_id` so the graph can branch on it.

## Subgraph scope ceiling

A subgraph inherits a scope ceiling from its parent graph. Nodes
inside the subgraph must attenuate the ceiling, never widen it.
`ChioGraphConfig.subgraph_config(...)` builds a child config whose
`parent_ceiling` is the parent's effective ceiling:

```python
outer = ChioGraphConfig(chio_client=chio, workflow_scope=_scope("search", "browse"))
inner = outer.subgraph_config(workflow_scope=_scope("search"))
inner.register_node_scope("search", _scope("search"))  # ok
inner.register_node_scope("write",  _scope("write"))   # ChioLangGraphConfigError
```

The same check runs when you call `chio_node(..., scope=...)` -- the
wrapper refuses to build a node whose scope exceeds the enclosing
graph's ceiling. This makes supervisor / subgraph delegation strictly
monotonic: a child capability is always `child subset-of parent`.

## Delegation via runtime config

Supervisor nodes narrow a child node's capability by passing a
different token id through LangGraph's `configurable` dict:

```python
async def supervisor(state, runtime_config):
    narrow = await chio.attenuate_capability(
        parent_token, new_scope=_scope("search"),
    )
    # LangGraph propagates `configurable` to downstream nodes.
    return {
        **state,
        "__config__": {"configurable": {"chio_capability_id": narrow.id}},
    }
```

The `chio_node` wrapper picks up `configurable["chio_capability_id"]` and
evaluates under that token. The SDK's own `attenuate_capability`
refuses to widen scope, so delegation is strictly attenuating end-to-end.

## Error types

* `ChioLangGraphError` -- raised when the Chio kernel denies a node
  dispatch or when an approval node receives a denial from the human
  reviewer. Carries `node_name`, `tool_server`, `tool_name`, `guard`,
  `reason`, `receipt_id`, and (for approval nodes) `approval_id`.
* `ChioLangGraphConfigError` -- raised on invalid configuration: a
  subgraph scope that exceeds the parent ceiling, a node wrapped
  without a provisioned capability, or an `chio_approval_node` wired
  without the required graph config.

## Reference

See
[`docs/protocols/LANGGRAPH-INTEGRATION.md`](../../../docs/protocols/LANGGRAPH-INTEGRATION.md)
for the full integration design (node scoping topology, delegation
chain, checkpoint correlation, subgraph attenuation).

## Development

```bash
uv venv --python 3.11
uv pip install -e '.[dev]'
uv pip install -e ../chio-sdk-python

uv run pytest
uv run mypy src/
uv run ruff check src/ tests/
```
