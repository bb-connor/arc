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

The package depends on `chio-sdk-python`, `langgraph>=0.2,<1`, and
`pydantic>=2.5`.

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
