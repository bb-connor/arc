"""Capability-scoped AutoGen GroupChat.

:class:`ArcGroupChat` and :class:`ArcGroupChatManager` are drop-in
subclasses of :class:`autogen.GroupChat` / :class:`autogen.GroupChatManager`
that accept a per-role capability scope mapping. Every participant in
the chat receives a capability token scoped to that role, so:

* A ``researcher`` role whose scope grants ``search`` tools cannot
  invoke a ``write`` tool, even if the LLM hallucinates the call.
* Handoff between agents produces attenuated child capabilities
  (``child ⊆ parent``) via
  :meth:`arc_sdk.ArcClient.attenuate_capability`.

The actual enforcement happens in :class:`arc_autogen.ArcFunctionRegistry`,
which is installed on each agent ahead of time. This class is
responsible for minting the tokens and rebinding the registries when a
role changes.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from arc_sdk.errors import ArcValidationError
from arc_sdk.models import ArcScope, CapabilityToken
from autogen import GroupChat, GroupChatManager

from arc_autogen.errors import ArcAutogenConfigError
from arc_autogen.functions import (
    ArcClientLike,
    ArcFunctionRegistry,
    registry_for,
)

logger = logging.getLogger(__name__)


class ArcGroupChat(GroupChat):
    """A :class:`autogen.GroupChat` augmented with per-role scoping.

    Parameters
    ----------
    capability_scope:
        Mapping from agent ``name`` (or custom role label) to the
        :class:`ArcScope` that role is allowed to exercise. The
        :class:`ArcGroupChatManager` uses this map to mint and rebind
        capability tokens.
    role_key:
        Attribute on each agent to treat as the role. Defaults to
        ``"name"`` which matches the standard :class:`ConversableAgent`
        identity; set to ``"role"`` to match CrewAI-style labels.
    **groupchat_kwargs:
        Forwarded to :class:`autogen.GroupChat`.
    """

    def __init__(
        self,
        *,
        capability_scope: Mapping[str, ArcScope],
        role_key: str = "name",
        **groupchat_kwargs: Any,
    ) -> None:
        if not capability_scope:
            raise ArcAutogenConfigError(
                "capability_scope must contain at least one role"
            )
        super().__init__(**groupchat_kwargs)
        self._arc_capability_scope: dict[str, ArcScope] = dict(capability_scope)
        self._arc_role_key: str = role_key

    @property
    def capability_scope(self) -> dict[str, ArcScope]:
        """Role -> scope mapping in effect for this chat."""
        return dict(self._arc_capability_scope)

    @property
    def role_key(self) -> str:
        """Attribute name used to derive an agent's role."""
        return self._arc_role_key

    def role_of(self, agent: Any) -> str | None:
        """Return the role label for ``agent``.

        Falls back to the agent's ``name`` when the configured role key
        is absent; that keeps this helper stable on the heterogeneous
        agent types AutoGen accepts.
        """
        role = getattr(agent, self._arc_role_key, None)
        if role is None and self._arc_role_key != "name":
            role = getattr(agent, "name", None)
        return role

    def scope_for(self, role: str) -> ArcScope:
        """Return the :class:`ArcScope` granted to ``role``.

        Raises :class:`ArcAutogenConfigError` if no scope is configured.
        """
        if role not in self._arc_capability_scope:
            raise ArcAutogenConfigError(
                f"no capability scope configured for role {role!r}"
            )
        return self._arc_capability_scope[role]


class ArcGroupChatManager(GroupChatManager):
    """A :class:`autogen.GroupChatManager` that enforces role-scoped dispatch.

    Parameters
    ----------
    groupchat:
        The :class:`ArcGroupChat` (or compatible) to manage.
    arc_client:
        :class:`arc_sdk.ArcClient` (or test double) used to mint and
        attenuate capability tokens for participants.
    subject_map:
        Optional mapping from role to the hex-encoded Ed25519 public
        key to bind each capability to. Defaults to a deterministic
        ``agent:<role>`` placeholder.
    ttl_seconds:
        Lifetime of each minted capability token (default 1 hour).
    **manager_kwargs:
        Forwarded to :class:`autogen.GroupChatManager`.
    """

    def __init__(
        self,
        *,
        groupchat: ArcGroupChat,
        arc_client: ArcClientLike,
        subject_map: Mapping[str, str] | None = None,
        ttl_seconds: int = 3600,
        **manager_kwargs: Any,
    ) -> None:
        if not isinstance(groupchat, ArcGroupChat):
            raise ArcAutogenConfigError(
                "groupchat must be an ArcGroupChat instance"
            )
        super().__init__(groupchat=groupchat, **manager_kwargs)
        self._arc_client: ArcClientLike = arc_client
        self._arc_subject_map: dict[str, str] = dict(subject_map or {})
        self._arc_ttl_seconds: int = int(ttl_seconds)
        self._arc_role_tokens: dict[str, CapabilityToken] = {}
        self._arc_groupchat: ArcGroupChat = groupchat

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def arc_client(self) -> ArcClientLike:
        """The :class:`ArcClient` (or mock) bound to this manager."""
        return self._arc_client

    @property
    def arc_groupchat(self) -> ArcGroupChat:
        """The :class:`ArcGroupChat` managed here."""
        return self._arc_groupchat

    def token_for(self, role: str) -> CapabilityToken | None:
        """Return the :class:`CapabilityToken` minted for ``role``, if any."""
        return self._arc_role_tokens.get(role)

    # ------------------------------------------------------------------
    # Provisioning
    # ------------------------------------------------------------------

    async def provision_capabilities(self) -> dict[str, CapabilityToken]:
        """Mint a capability token per role and bind agent registries.

        Returns the mapping from role to :class:`CapabilityToken`.
        Registries previously attached to each agent via
        :func:`arc_autogen.functions.attach_registry` are updated in
        place so that subsequent invocations go through the ARC sidecar
        with the correct token.
        """
        tokens: dict[str, CapabilityToken] = {}
        for role, scope in self._arc_groupchat.capability_scope.items():
            subject = self._arc_subject_map.get(role, _default_subject(role))
            token = await self._arc_client.create_capability(
                subject=subject,
                scope=scope,
                ttl_seconds=self._arc_ttl_seconds,
            )
            tokens[role] = token

        self._arc_role_tokens = tokens
        self._bind_registries(tokens)
        return tokens

    async def attenuate_for_handoff(
        self,
        *,
        delegator_role: str,
        delegate_role: str,
        new_scope: ArcScope,
    ) -> CapabilityToken:
        """Produce a child token for an agent-to-agent handoff.

        The child is strictly narrower than the delegator's token.
        Raises :class:`ArcAutogenConfigError` if ``delegator_role`` has
        no active token, and :class:`arc_sdk.errors.ArcValidationError`
        if ``new_scope`` is not a subset of the delegator's scope.
        """
        parent = self.token_for(delegator_role)
        if parent is None:
            raise ArcAutogenConfigError(
                f"delegator role {delegator_role!r} has no minted capability; "
                "call provision_capabilities() first"
            )
        try:
            child = await self._arc_client.attenuate_capability(
                parent, new_scope=new_scope
            )
        except ArcValidationError:
            raise

        self._arc_role_tokens[delegate_role] = child
        self._bind_registries({delegate_role: child})
        return child

    # ------------------------------------------------------------------
    # Scope-aware invocation helper
    # ------------------------------------------------------------------

    def ensure_function_in_scope(self, role: str, function_name: str) -> None:
        """Assert ``function_name`` is within the scope granted to ``role``.

        Used for defence in depth: even if the LLM hallucinates a call
        into a cross-role function map, this local check refuses the
        dispatch before the ARC sidecar is bothered.

        Raises :class:`arc_autogen.ArcAutogenConfigError` when the role
        is not configured at all, and
        :class:`arc_autogen.ArcToolError` when the function is outside
        the role's scope.
        """
        from arc_autogen.errors import ArcToolError

        scope = self._arc_groupchat.scope_for(role)
        allowed = {g.tool_name for g in scope.grants}
        if function_name in allowed or "*" in allowed:
            return
        raise ArcToolError(
            f"function {function_name!r} not in scope for role {role!r}",
            tool_name=function_name,
            reason="not_in_role_scope",
            guard="ArcGroupChatManager",
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _bind_registries(
        self, tokens: Mapping[str, CapabilityToken]
    ) -> None:
        """Rewrite each agent's registry with the fresh token."""
        for agent in self._arc_groupchat.agents or []:
            role = self._arc_groupchat.role_of(agent)
            if role is None or role not in tokens:
                continue
            token = tokens[role]
            reg = registry_for(agent)
            if reg is None:
                continue
            reg.bind_capability(token)
            reg.bind_arc_client(self._arc_client)


def _default_subject(role: str) -> str:
    """Produce a deterministic subject placeholder for a role.

    A real deployment supplies its own ``subject_map``; this fallback
    keeps the chat runnable in tests and local demos.
    """
    safe = "".join(c if c.isalnum() else "_" for c in role.lower())
    return f"agent:{safe}"


__all__ = [
    "ArcGroupChat",
    "ArcGroupChatManager",
]

# Re-export used implicitly above so the symbol is available at module
# import time for static checkers.
_ = ArcFunctionRegistry
