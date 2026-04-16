"""Nested chat delegation with capability attenuation.

AutoGen supports nested chats where an agent spawns a sub-conversation
via :meth:`ConversableAgent.register_nested_chats` or the top-level
:func:`autogen.initiate_chats`. Each nesting level narrows authority:
the child agent(s) receive a capability token that is a strict subset
of the parent's, so a compromised or hallucinating nested agent cannot
escalate beyond what the spawner already had.

The helper :func:`register_nested_chats_with_attenuation` mints the
attenuated token via :meth:`arc_sdk.ArcClient.attenuate_capability`,
rewrites every child agent's :class:`arc_autogen.ArcFunctionRegistry`
to point at that token, and then delegates to AutoGen's native
``register_nested_chats``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from arc_sdk.models import ArcScope, CapabilityToken

from arc_autogen.errors import ArcAutogenConfigError
from arc_autogen.functions import (
    ArcClientLike,
    ArcFunctionRegistry,
    registry_for,
)

logger = logging.getLogger(__name__)

# Child chat config is a dict per AutoGen's register_nested_chats contract.
ChildChatConfig = dict[str, Any]


async def register_nested_chats_with_attenuation(
    *,
    parent_agent: Any,
    child_configs: Sequence[ChildChatConfig],
    parent_capability: CapabilityToken,
    child_scope: ArcScope,
    arc_client: ArcClientLike,
    trigger: Any = None,
    reply_func_from_nested_chats: str | Any = "summary_from_nested_chats",
    position: int = 2,
    use_async: bool | None = None,
    **register_kwargs: Any,
) -> CapabilityToken:
    """Register nested chats on ``parent_agent`` with an attenuated token.

    Parameters
    ----------
    parent_agent:
        The :class:`autogen.ConversableAgent` that spawns the nested
        chat(s). Must support ``register_nested_chats``.
    child_configs:
        Sequence of child chat config dicts as accepted by
        :meth:`ConversableAgent.register_nested_chats`. Each dict may
        carry a ``recipient`` that is itself a :class:`ConversableAgent`;
        when present, the recipient's attached
        :class:`ArcFunctionRegistry` is rebound to the attenuated token.
    parent_capability:
        The delegator's :class:`CapabilityToken`. The attenuated child
        capability must be a strict subset of this token.
    child_scope:
        The :class:`ArcScope` the nested chat is allowed to exercise.
        Must be ``child_scope.is_subset_of(parent_capability.scope)``;
        the SDK raises :class:`arc_sdk.errors.ArcValidationError` if
        not.
    arc_client:
        :class:`arc_sdk.ArcClient` (or test double) used to attenuate
        the capability.
    trigger:
        Forwarded to ``register_nested_chats``. Defaults to matching
        any agent on ``parent_agent``.
    reply_func_from_nested_chats, position, use_async, register_kwargs:
        Forwarded unchanged to AutoGen's ``register_nested_chats``.

    Returns
    -------
    CapabilityToken
        The minted child token. Callers typically ignore it, but it is
        returned so tests can inspect the delegation chain.

    Raises
    ------
    ArcAutogenConfigError
        If ``parent_agent`` does not expose ``register_nested_chats``.
    arc_sdk.errors.ArcValidationError
        If ``child_scope`` tries to broaden ``parent_capability.scope``.
    """
    if parent_agent is None:
        raise ArcAutogenConfigError("parent_agent must not be None")
    register = getattr(parent_agent, "register_nested_chats", None)
    if not callable(register):
        raise ArcAutogenConfigError(
            "parent_agent does not expose register_nested_chats; "
            "ensure it is a ConversableAgent"
        )

    # Mint the attenuated token -- the SDK enforces child ⊆ parent and
    # raises ArcValidationError otherwise.
    child_token = await arc_client.attenuate_capability(
        parent_capability, new_scope=child_scope
    )

    # Rebind every child recipient's registry so subsequent function
    # calls in the nested chat are evaluated against the narrower
    # capability.
    for cfg in child_configs:
        recipient = cfg.get("recipient") if isinstance(cfg, Mapping) else None
        _rebind_agent(recipient, child_token, arc_client)

    # AutoGen accepts a wide ``trigger``; default to "match any agent"
    # if the caller did not override.
    effective_trigger = trigger
    if effective_trigger is None:
        # A truthy lambda matches every agent, which is the idiomatic
        # "always nest" trigger shown in AutoGen's tutorials.
        effective_trigger = lambda _sender: True  # noqa: E731

    register(
        chat_queue=list(child_configs),
        trigger=effective_trigger,
        reply_func_from_nested_chats=reply_func_from_nested_chats,
        position=position,
        use_async=use_async,
        **register_kwargs,
    )
    return child_token


async def attenuate_for_initiate_chats(
    *,
    chat_queue: Sequence[ChildChatConfig],
    parent_capability: CapabilityToken,
    child_scope: ArcScope,
    arc_client: ArcClientLike,
) -> tuple[list[ChildChatConfig], CapabilityToken]:
    """Mint an attenuated token for each chat in an ``initiate_chats`` queue.

    Returns the (unchanged) chat queue plus the child token, having
    rebound the registries on every ``recipient`` / ``sender`` agent in
    the queue to that token.

    This is the recommended entry point when you want to use
    :func:`autogen.initiate_chats` rather than agent-level nesting.
    """
    child_token = await arc_client.attenuate_capability(
        parent_capability, new_scope=child_scope
    )
    for cfg in chat_queue:
        if not isinstance(cfg, Mapping):
            continue
        for key in ("recipient", "sender"):
            _rebind_agent(cfg.get(key), child_token, arc_client)
    return list(chat_queue), child_token


def rebind_registries(
    agents: Iterable[Any],
    *,
    capability: CapabilityToken,
    arc_client: ArcClientLike,
) -> list[ArcFunctionRegistry]:
    """Bind ``capability`` on every :class:`ArcFunctionRegistry` present.

    Returns the list of registries that were rebound. Agents that do
    not have an attached registry are silently skipped.
    """
    out: list[ArcFunctionRegistry] = []
    for agent in agents:
        reg = registry_for(agent)
        if reg is None:
            continue
        reg.bind_capability(capability)
        reg.bind_arc_client(arc_client)
        out.append(reg)
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _rebind_agent(
    agent: Any,
    token: CapabilityToken,
    arc_client: ArcClientLike,
) -> None:
    """Rebind the registry on a single agent, if it has one."""
    if agent is None:
        return
    reg = registry_for(agent)
    if reg is None:
        return
    reg.bind_capability(token)
    reg.bind_arc_client(arc_client)


__all__ = [
    "ChildChatConfig",
    "attenuate_for_initiate_chats",
    "rebind_registries",
    "register_nested_chats_with_attenuation",
]
