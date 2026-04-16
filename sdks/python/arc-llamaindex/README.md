# arc-llamaindex

LlamaIndex integration for the [ARC protocol](../../../spec/PROTOCOL.md).
Wraps `llama_index.core.tools.FunctionTool` and
`llama_index.core.tools.QueryEngineTool` so every tool dispatch an
agent performs is evaluated by the ARC sidecar kernel for
capability-scoped authorization, guard enforcement, and signed
receipts.

## Install

```bash
uv pip install arc-llamaindex
# or
pip install arc-llamaindex
```

The package depends on `arc-sdk-python`, `llama-index-core>=0.11,<1`,
and `pydantic>=2.5`.

## Quickstart

```python
import asyncio

from arc_llamaindex import ArcAgentRunner, ArcFunctionTool, ArcQueryEngineTool
from arc_sdk.client import ArcClient
from arc_sdk.models import ArcScope, Constraint, Operation, ToolGrant
from llama_index.core.agent import AgentRunner
from llama_index.core.agent.openai.base import OpenAIAgentWorker
from llama_index.core.llms import MockLLM


def search_grant() -> ToolGrant:
    return ToolGrant(
        server_id="tools-srv",
        tool_name="search_documents",
        operations=[Operation.INVOKE],
    )


def rag_grant() -> ToolGrant:
    return ToolGrant(
        server_id="rag-srv",
        tool_name="query_prod-docs",
        operations=[Operation.INVOKE],
        constraints=[
            Constraint(type="memory_store_allowlist", value="prod-docs"),
        ],
    )


def search_documents(q: str) -> str:
    return f"hit for {q!r}"


search_tool = ArcFunctionTool(
    fn=search_documents,
    name="search_documents",
    description="Search the document index",
    server_id="tools-srv",
)

rag_tool = ArcQueryEngineTool(
    query_engine=my_index.as_query_engine(),  # type: ignore[name-defined]
    collection="prod-docs",
    server_id="rag-srv",
)


async def main() -> None:
    async with ArcClient("http://127.0.0.1:9090") as arc:
        worker = OpenAIAgentWorker.from_tools(
            [search_tool, rag_tool],
            llm=MockLLM(),
        )
        runner = AgentRunner(agent_worker=worker)

        arc_runner = ArcAgentRunner(
            runner=runner,
            capability_scope=ArcScope(grants=[search_grant(), rag_grant()]),
            arc_client=arc,
            agent_name="analyst",
        )
        await arc_runner.provision_capability()

        response = runner.chat("Summarise the Q4 filings.")
        print(response)


asyncio.run(main())
```

At runtime:

* Every `search_documents` call is evaluated by the ARC sidecar; a deny
  verdict raises `ArcToolError` (or returns an error `ToolOutput` if
  you pass `raise_on_deny=False`).
* Every RAG query is first checked against the `collection` allowlist
  in the agent's capability scope, then evaluated by the sidecar.
* Attempting to construct an `ArcQueryEngineTool` bound to a collection
  the capability does not cover is denied client-side before the
  retriever runs.

## Collection scoping

`ArcQueryEngineTool` enforces a two-layer check:

1. **Client-side allowlist.** The tool reads
   `Constraint(type="memory_store_allowlist", ...)` entries off the
   agent's `ArcScope` and only lets the call through if the bound
   `collection` is in the set. When no allowlist is provided, the
   client-side check is a no-op and the sidecar policy is the only
   gate. An explicit `capability_scope=ArcScope()` with no grants is
   fail-closed.
2. **Sidecar policy.** The sidecar receives `collection` and `query`
   in `parameters`, so kernel-level policies can veto based on any
   field (e.g. rate-limit per collection, block after a data-access
   violation).

```python
tool = ArcQueryEngineTool(
    query_engine=engine,
    collection="prod-docs",
    allowed_collections=["prod-docs", "qa-docs"],  # shortcut alternative
    capability_id="cap-analyst",
    server_id="rag-srv",
)
```

## Per-agent capability binding

`ArcAgentRunner` is a thin helper that mints one capability token for
an agent as a whole and binds it to every `ArcFunctionTool` /
`ArcQueryEngineTool` that the runner holds:

```python
arc_runner = ArcAgentRunner(
    runner=runner,
    capability_scope=ArcScope(grants=[search_grant()]),
    arc_client=arc,
    agent_name="analyst",
)
token = await arc_runner.provision_capability()

# Delegate to a narrower child capability for a nested/helper agent.
child = await arc_runner.attenuate(new_scope=ArcScope(grants=[search_grant()]))
```

`attenuate` enforces `child ⊆ parent`; the SDK raises
`ArcValidationError` if you try to broaden scope.

## Error types

* `ArcToolError` -- raised when the ARC kernel, or a client-side
  collection allowlist check, denies an invocation. Carries
  `tool_name`, `server_id`, `guard`, `reason`, `receipt_id`.
* `ArcLlamaIndexConfigError` -- raised on invalid SDK configuration
  (empty collection, missing capability before delegation, etc.).

## Reference

See
[`docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md`](../../../docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md)
section 7 for the full integration design (intercept points,
`QueryEngineTool` data access scoping, agent runner binding).

## Development

```bash
uv venv --python 3.11
uv pip install -e '.[dev]'
uv pip install -e ../arc-sdk-python

uv run pytest
uv run mypy src/
uv run ruff check src/ tests/
```
