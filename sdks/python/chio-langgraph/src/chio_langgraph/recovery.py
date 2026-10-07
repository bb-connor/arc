"""A thin StateGraph node whose saved values cannot authorize an effect."""
from __future__ import annotations
from collections.abc import Awaitable, Callable, Mapping
from chio_sdk.recovery_host import RecoveryHostSession


def recovery_node(session: RecoveryHostSession) -> Callable[[Mapping[str, object]], Awaitable[dict[str, object]]]:
    """Reauthorize every invocation through Rust; retain categories and IDs only.

    Invoke again with the same choice to request native exact replay. A saved
    category is historical advice, not permission to execute a fallback tool.
    Credentials and native bytes belong in the session, never graph state.
    """
    async def node(state: Mapping[str, object]) -> dict[str, object]:
        choice = state.get("choice")
        if not isinstance(choice, str):
            return {"recovery": {"category": "invalid_choice"}}
        outcome = await session.execute(choice)
        return {"recovery": outcome.as_dict()}
    return node
