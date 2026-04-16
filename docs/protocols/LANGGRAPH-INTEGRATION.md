# LangGraph Integration: Stateful Agent Graph Security

> **Status**: Tier 1 -- proposed April 2026
> **Priority**: High -- LangGraph is the stateful orchestration layer for
> multi-agent systems built on LangChain. Each node transition is a
> capability boundary. Extends the existing `arc-langchain` SDK.

## 1. Why LangGraph

ARC already ships `arc-langchain` which wraps ARC tools as LangChain
`BaseTool` instances. But LangChain is the tool layer; LangGraph is the
orchestration layer. LangGraph adds:

- **Stateful graphs** -- nodes (agents, tools, humans) connected by edges
  with conditional routing, cycles, and persistence
- **Human-in-the-loop** -- interrupt nodes that pause execution for approval
- **Multi-agent** -- supervisor/worker patterns, handoffs, parallel branches
- **Checkpointing** -- graph state persisted across invocations

Each of these creates a natural ARC enforcement point. A node transition
is a capability boundary. A human-in-the-loop interrupt maps to an ARC
approval guard. A supervisor dispatching to workers is a capability
delegation chain.

### What ARC Adds to LangGraph

| LangGraph alone | LangGraph + ARC |
|-----------------|-----------------|
| Graph structure defines control flow | Capability tokens scope what each node can do |
| Human-in-the-loop is UX-driven | Approval guards are policy-driven (human approval is one guard type) |
| Tool calls via LangChain tools | Tool calls attested with signed receipts |
| State checkpointed per thread | Receipt chain provides cryptographic audit trail |
| Multi-agent trust is implicit | Delegation creates scoped child capabilities |

## 2. Architecture

```
+------------------------------------------------------------------+
|  LangGraph                                                       |
|                                                                  |
|  [Supervisor Node]                                               |
|       |                                                          |
|       | ARC: delegate(scope="research:*")                        |
|       |                                                          |
|  +----v-----------+    +------------------+                      |
|  | Researcher Node|    | Writer Node      |                      |
|  | cap: research:*|    | cap: write:*     |                      |
|  |   |            |    |   |              |                      |
|  |   | tool_call  |    |   | tool_call    |                      |
|  |   v            |    |   v              |                      |
|  | [ARC evaluate] |    | [ARC evaluate]   |                      |
|  +----------------+    +------------------+                      |
|                                                                  |
+------------------------------------------------------------------+
         |                        |
         v                        v
  ARC Kernel Sidecar (shared, :9090)
  Capability | Guard | Receipt | Budget
```

### Node-Level Capability Scoping

Each node in the graph operates under a capability scope. When the graph
transitions from one node to another, the capability context changes:

```
Supervisor (cap: agent:supervisor)
    |
    +---> Researcher (cap: tools:search, tools:browse)
    |         |
    |         +---> [search tool] -- ARC evaluates against tools:search
    |         +---> [browse tool] -- ARC evaluates against tools:browse
    |         +---> [write tool]  -- ARC DENIES (not in researcher scope)
    |
    +---> Writer (cap: tools:write, tools:format)
              |
              +---> [write tool]  -- ARC evaluates against tools:write
              +---> [search tool] -- ARC DENIES (not in writer scope)
```

## 3. Integration Model

### 3.1 Graph-Level Configuration

```python
from langgraph.graph import StateGraph, START, END
from arc_langgraph import ArcGraphConfig, arc_node

# Define the graph with ARC capability scoping
graph = StateGraph(AgentState)

# Each node gets a capability scope
graph.add_node("supervisor", arc_node(
    supervisor_agent,
    scope="agent:supervisor",
    can_delegate=["tools:search", "tools:browse", "tools:write"],
))

graph.add_node("researcher", arc_node(
    researcher_agent,
    scope="tools:search,tools:browse",
    budget={"max_calls": 20, "max_cost_usd": 0.50},
))

graph.add_node("writer", arc_node(
    writer_agent,
    scope="tools:write,tools:format",
    budget={"max_calls": 10},
))

# Edges with capability-aware routing
graph.add_conditional_edges("supervisor", route_to_worker)
graph.add_edge("researcher", "supervisor")
graph.add_edge("writer", "supervisor")

graph.add_edge(START, "supervisor")

app = graph.compile(
    checkpointer=MemorySaver(),
    # ARC configuration applied to the compiled graph
    arc=ArcGraphConfig(
        sidecar_url="http://127.0.0.1:9090",
        # Workflow-level grant acquired on graph start
        workflow_scope="agent:full-pipeline",
    ),
)
```

### 3.2 The `arc_node` Wrapper

`arc_node` wraps any LangGraph node function with ARC capability context:

```python
from arc_langgraph import ArcNodeContext

def arc_node(fn, scope: str, budget: dict | None = None, can_delegate: list[str] | None = None):
    """Wrap a LangGraph node with ARC capability enforcement."""

    async def wrapper(state: AgentState, config: RunnableConfig) -> AgentState:
        arc_ctx = ArcNodeContext.from_config(config)

        # Enter the node's capability scope
        async with arc_ctx.scoped(scope, budget=budget) as node_ctx:
            # Inject ARC-aware tools into the agent
            state["arc_context"] = node_ctx

            result = await fn(state, config)

            # Record node completion receipt
            await node_ctx.record_node_completion(
                node_name=fn.__name__,
                input_hash=state.hash(),
                output_hash=result.hash() if hasattr(result, 'hash') else None,
            )

            return result

    wrapper.__name__ = fn.__name__
    return wrapper
```

### 3.3 Human-in-the-Loop as Approval Guard

LangGraph's `interrupt()` mechanism maps to ARC's approval guard:

```python
from langgraph.types import interrupt
from arc_langgraph import arc_approval_node

@arc_approval_node(
    scope="tools:dangerous",
    guard="human-approval",
    # ARC guard config -- who can approve, timeout, escalation
    approval_config={
        "approvers": ["admin@example.com"],
        "timeout_seconds": 3600,
        "escalation": "deny",  # deny if no approval within timeout
    },
)
async def dangerous_action(state: AgentState, config: RunnableConfig):
    """This node requires human approval via ARC guard before executing."""
    # If we reach here, the approval guard passed
    result = await execute_dangerous_tool(state["action"])
    return {"result": result}
```

Under the hood, `arc_approval_node` does:

1. Calls `arc.evaluate()` with the `human-approval` guard
2. If the guard returns `pending`, calls `interrupt()` to pause the graph
3. When the graph resumes (human approved), re-evaluates -- guard now passes
4. If the guard returns `denied` (human rejected or timeout), raises `NodeInterrupt`

### 3.4 Multi-Agent Delegation

When a supervisor delegates to a worker, the capability chain narrows:

```python
from arc_langgraph import ArcDelegation

async def supervisor_node(state: AgentState, config: RunnableConfig):
    arc_ctx = ArcNodeContext.from_config(config)

    # Supervisor decides which worker to route to
    decision = await supervisor_llm.invoke(state["messages"])

    if decision.worker == "researcher":
        # Create a delegated capability for the researcher
        # Scope is narrowed: supervisor has agent:supervisor,
        # researcher gets only tools:search,tools:browse
        delegation = await arc_ctx.delegate(
            target_node="researcher",
            scope="tools:search,tools:browse",
            budget={"max_calls": 20},
            # Delegation is recorded in the receipt chain
        )
        state["arc_delegation"] = delegation

    return {**state, "next": decision.worker}
```

### 3.5 Subgraph Isolation

LangGraph supports nested subgraphs. Each subgraph gets its own capability
boundary:

```python
# Inner graph -- research pipeline
research_graph = StateGraph(ResearchState)
research_graph.add_node("search", arc_node(search_fn, scope="tools:search"))
research_graph.add_node("analyze", arc_node(analyze_fn, scope="tools:analyze"))

# Outer graph -- uses research as a subgraph
outer_graph = StateGraph(AgentState)
outer_graph.add_node("plan", arc_node(plan_fn, scope="agent:plan"))
outer_graph.add_node("research", arc_node(
    research_graph.compile(),
    scope="tools:search,tools:analyze",  # ceiling for the entire subgraph
))
outer_graph.add_node("write", arc_node(write_fn, scope="tools:write"))
```

The subgraph's nodes cannot exceed the scope ceiling set by the outer graph.

## 4. Checkpoint and Receipt Correlation

LangGraph checkpoints graph state at each node. ARC receipts record each
tool invocation. These should cross-reference:

```python
class ArcCheckpointAdapter:
    """Wraps a LangGraph checkpointer to include ARC receipt metadata."""

    def __init__(self, inner_checkpointer, arc_client):
        self.inner = inner_checkpointer
        self.arc = arc_client

    async def aput(self, config, checkpoint, metadata):
        # Attach receipt IDs to checkpoint metadata
        receipt_ids = ArcNodeContext.from_config(config).receipt_ids
        metadata["arc_receipt_ids"] = receipt_ids
        metadata["arc_receipt_chain_head"] = receipt_ids[-1] if receipt_ids else None
        return await self.inner.aput(config, checkpoint, metadata)
```

### Querying

```
# Find all ARC receipts for a LangGraph thread
arc receipt list --meta langgraph.thread_id=<thread-id>

# Find receipts for a specific node execution
arc receipt list --meta langgraph.thread_id=<thread-id> --meta langgraph.node=researcher

# Replay graph execution from receipt chain
arc receipt chain <head-receipt-id> --format langgraph
```

## 5. Tool Binding

The existing `arc-langchain` `ArcToolkit` works inside LangGraph nodes.
The integration adds scope awareness:

```python
from arc_langchain import ArcToolkit

async def researcher_agent(state: AgentState, config: RunnableConfig):
    arc_ctx = ArcNodeContext.from_config(config)

    # ArcToolkit filters to only tools within this node's scope
    toolkit = ArcToolkit.from_context(arc_ctx)
    tools = toolkit.get_tools()  # only search, browse -- not write

    agent = create_react_agent(llm, tools)
    result = await agent.ainvoke({"messages": state["messages"]})

    return {"messages": result["messages"]}
```

## 6. Package Structure

```
sdks/python/arc-langgraph/
  pyproject.toml            # deps: arc-sdk-python, arc-langchain, langgraph
  src/arc_langgraph/
    __init__.py
    config.py               # ArcGraphConfig
    node.py                 # arc_node wrapper
    context.py              # ArcNodeContext
    delegation.py           # ArcDelegation, capability narrowing
    approval.py             # arc_approval_node, guard-to-interrupt bridge
    checkpoint.py           # ArcCheckpointAdapter
  tests/
    test_node_scoping.py
    test_delegation.py
    test_approval.py
    test_subgraph.py
```

## 7. Relationship to `arc-langchain`

```
arc-sdk-python          (base HTTP client to sidecar)
    |
arc-langchain           (ArcToolkit, ArcTool -- tool wrapping)
    |
arc-langgraph           (graph-level scoping, delegation, approvals)
```

`arc-langgraph` depends on `arc-langchain` for tool binding and adds the
graph orchestration layer. Users who only need tool wrapping without graph
orchestration use `arc-langchain` directly.

## 8. Open Questions

1. **LangGraph Platform.** LangGraph Cloud runs graphs as a managed service.
   The sidecar model requires the ARC kernel to run in the same environment.
   Should ARC support a remote kernel mode for managed LangGraph deployments?

2. **Streaming.** LangGraph streams node outputs. Should ARC receipts be
   emitted as stream events, or only on node completion?

3. **Time travel.** LangGraph supports replaying from a checkpoint. If the
   graph is replayed, should ARC re-evaluate capabilities (they may have
   been revoked since the checkpoint), or honor the original evaluation?

4. **CrewAI / AutoGen.** These frameworks serve a similar multi-agent
   orchestration role. Should the `arc_node` pattern be generalized into a
   framework-agnostic multi-agent adapter, or should each framework get
   its own integration?
