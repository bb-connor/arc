# arc-crewai

CrewAI integration for the [ARC protocol](../../../spec/PROTOCOL.md). Wraps
`crewai.tools.BaseTool` so every tool invocation an agent attempts is
evaluated by the ARC sidecar kernel for capability-scoped authorization,
guard enforcement, and signed receipts.

## Install

```bash
uv pip install arc-crewai
# or
pip install arc-crewai
```

The package depends on `arc-sdk-python`, `crewai>=0.80,<1`, and
`pydantic>=2.5`.

## Quickstart

```python
import asyncio

from arc_crewai import ArcBaseTool, ArcCrew
from arc_sdk.client import ArcClient
from arc_sdk.models import ArcScope, Operation, ToolGrant
from crewai import Agent, Task


def search_grant() -> ToolGrant:
    return ToolGrant(
        server_id="tools-srv",
        tool_name="search",
        operations=[Operation.INVOKE],
    )


def write_grant() -> ToolGrant:
    return ToolGrant(
        server_id="tools-srv",
        tool_name="write",
        operations=[Operation.INVOKE],
    )


search_tool = ArcBaseTool(
    name="search",
    description="Search the web",
    server_id="tools-srv",
    executor=lambda q: {"results": [f"hit for {q!r}"]},
)

write_tool = ArcBaseTool(
    name="write",
    description="Write a file",
    server_id="tools-srv",
    executor=lambda path, content: {"ok": True, "path": path},
)

researcher = Agent(
    role="researcher",
    goal="Find accurate information",
    backstory="A careful researcher.",
    tools=[search_tool, write_tool],
)

writer = Agent(
    role="writer",
    goal="Produce clear prose",
    backstory="A technical writer.",
    tools=[search_tool, write_tool],
)

task = Task(
    description="Research then write.",
    expected_output="A short brief.",
    agent=researcher,
)


async def main() -> None:
    async with ArcClient("http://127.0.0.1:9090") as arc:
        crew = ArcCrew(
            capability_scope={
                "researcher": ArcScope(grants=[search_grant()]),
                "writer": ArcScope(grants=[write_grant()]),
            },
            arc_client=arc,
            agents=[researcher, writer],
            tasks=[task],
        )
        await crew.provision_capabilities()
        result = crew.kickoff()
        print(result)


asyncio.run(main())
```

At runtime:

* The researcher can call `search` but any attempt to call `write` is
  denied by the ARC kernel (even if the LLM hallucinates the call).
* The writer can call `write` but not `search`.
* Delegation between agents mints attenuated child tokens that are a
  strict subset of the delegator's scope.

## Delegation attenuation

```python
child = await crew.attenuate_for_delegation(
    delegator_role="writer",
    delegate_role="editor",
    new_scope=ArcScope(grants=[write_grant()]),
)
```

The child capability is always `child ⊆ parent`; the SDK raises
`ArcValidationError` if you try to broaden scope.

## Error types

* `ArcToolError` -- raised when the ARC kernel denies an invocation.
  Carries `tool_name`, `server_id`, `guard`, `reason`, `receipt_id`.
* `ArcCrewConfigError` -- raised on invalid crew configuration (missing
  scope for a role, empty scope map, delegator without a minted token).

## Reference

See
[`docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md`](../../../docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md)
section 5 for the full integration design (intercept points, scoping
model, delegation attenuation).

## Development

```bash
uv venv --python 3.11
uv pip install -e '.[dev]'
uv pip install -e ../arc-sdk-python

uv run pytest
uv run mypy src/
uv run ruff check src/ tests/
```
