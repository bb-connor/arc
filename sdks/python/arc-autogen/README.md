# arc-autogen

AutoGen integration for the [ARC protocol](../../../spec/PROTOCOL.md). Wraps
AutoGen's `register_function` / `function_map` and `GroupChat` so every
registered function an agent attempts to call is evaluated by the ARC
sidecar kernel for capability-scoped authorization, guard enforcement,
and signed receipts.

## Install

```bash
uv pip install arc-autogen
# or
pip install arc-autogen
```

The package depends on `arc-sdk-python`, `pyautogen>=0.2,<0.3`, and
`pydantic>=2.5`. We pin the classic `pyautogen` 0.2.x line because it
exposes the stable `ConversableAgent` / `GroupChat` /
`register_function` surface targeted by this integration. The newer
`autogen-agentchat` 0.4+ redesign pivots to an async actor model that
does not surface a drop-in `GroupChat`; adapting to it is tracked as
future work.

## Quickstart

```python
import asyncio

from autogen import ConversableAgent
from arc_autogen import (
    ArcFunctionRegistry,
    ArcGroupChat,
    ArcGroupChatManager,
    attach_registry,
)
from arc_sdk.client import ArcClient
from arc_sdk.models import ArcScope, Operation, ToolGrant


def grant(name: str) -> ToolGrant:
    return ToolGrant(
        server_id="tools-srv",
        tool_name=name,
        operations=[Operation.INVOKE],
    )


researcher = ConversableAgent(name="researcher", llm_config=False)
writer = ConversableAgent(name="writer", llm_config=False)


async def main() -> None:
    async with ArcClient("http://127.0.0.1:9090") as arc:
        # Register ARC-governed functions on each agent.
        r_registry = ArcFunctionRegistry(
            agent=researcher, arc_client=arc, server_id="tools-srv"
        )

        @r_registry.as_decorator()
        def search(query: str) -> str:
            """Search the web."""
            return f"hits for {query!r}"

        attach_registry(researcher, r_registry)

        w_registry = ArcFunctionRegistry(
            agent=writer, arc_client=arc, server_id="tools-srv"
        )

        @w_registry.as_decorator()
        def write(path: str, content: str) -> str:
            """Write a file."""
            return f"wrote {path}"

        attach_registry(writer, w_registry)

        # Build the capability-scoped GroupChat.
        groupchat = ArcGroupChat(
            capability_scope={
                "researcher": ArcScope(grants=[grant("search")]),
                "writer": ArcScope(grants=[grant("write")]),
            },
            agents=[researcher, writer],
            messages=[],
            max_round=6,
        )
        manager = ArcGroupChatManager(
            groupchat=groupchat,
            arc_client=arc,
            llm_config=False,
        )
        await manager.provision_capabilities()

        # The researcher can call `search`, but any attempt to call
        # `write` is denied by the ARC kernel -- even if the LLM
        # hallucinates the call. The writer can call `write` but not
        # `search`.


asyncio.run(main())
```

## Nested chat attenuation

AutoGen supports nested chats where an agent spawns a sub-conversation.
Each nesting level narrows authority via
`register_nested_chats_with_attenuation`:

```python
from arc_autogen import register_nested_chats_with_attenuation

child_token = await register_nested_chats_with_attenuation(
    parent_agent=researcher,
    child_configs=[
        {"recipient": editor, "message": "handoff", "max_turns": 2},
    ],
    parent_capability=manager.token_for("researcher"),
    child_scope=ArcScope(grants=[grant("search")]),  # strict subset
    arc_client=arc,
)
```

The child capability is always `child ⊆ parent`; the SDK raises
`ArcValidationError` if you try to broaden scope.

## Error types

* `ArcToolError` -- raised when the ARC kernel denies an invocation.
  Carries `tool_name`, `server_id`, `guard`, `reason`, `receipt_id`.
* `ArcAutogenConfigError` -- raised on invalid configuration (missing
  scope for a role, empty scope map, delegator without a minted token).

## Reference

See
[`docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md`](../../../docs/protocols/AGENT-FRAMEWORK-INTEGRATION.md)
section 6 for the full integration design (intercept points, scoping
model, nested delegation).

## Development

```bash
uv venv --python 3.11
uv pip install -e '.[dev]'
uv pip install -e ../arc-sdk-python

uv run pytest
uv run mypy src/
uv run ruff check src/ tests/
```
