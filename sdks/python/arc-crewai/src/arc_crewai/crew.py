"""Capability-scoped CrewAI crew.

:class:`ArcCrew` is a drop-in subclass of :class:`crewai.Crew` that
accepts a per-role capability scope mapping. Each agent's tools receive
a capability token scoped to that role, so:

* A researcher agent whose role scope grants ``search`` tools cannot
  invoke a ``write`` tool, even if the LLM hallucinates the call.
* Delegation between agents produces attenuated child capabilities
  (``child ⊆ parent``) via :meth:`arc_sdk.ArcClient.attenuate_capability`.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any

from arc_sdk.errors import ArcValidationError
from arc_sdk.models import ArcScope, CapabilityToken
from crewai import Crew

from arc_crewai.errors import ArcCrewConfigError
from arc_crewai.tool import ArcBaseTool, ArcClientLike

logger = logging.getLogger(__name__)


class ArcCrew(Crew):
    """A CrewAI :class:`Crew` whose tool calls are ARC-governed.

    Parameters
    ----------
    capability_scope:
        Mapping from agent ``role`` to the :class:`ArcScope` that role
        is allowed to exercise. Tools owned by the agent have their
        ``capability_id`` rewritten to a freshly-minted token whose
        scope is exactly this mapping.
    arc_client:
        :class:`arc_sdk.ArcClient` (or test double) used to mint
        capability tokens and evaluate calls. Reused across all tools
        in the crew.
    subject_map:
        Optional mapping from role to the hex-encoded Ed25519 public
        key to bind the capability to. Defaults to a deterministic
        ``agent:<role>`` placeholder.
    ttl_seconds:
        Lifetime of each minted capability token.
    **crew_kwargs:
        Forwarded to :class:`crewai.Crew`.
    """

    model_config = {"arbitrary_types_allowed": True}

    def __init__(
        self,
        *,
        capability_scope: Mapping[str, ArcScope],
        arc_client: ArcClientLike,
        subject_map: Mapping[str, str] | None = None,
        ttl_seconds: int = 3600,
        **crew_kwargs: Any,
    ) -> None:
        if not capability_scope:
            raise ArcCrewConfigError(
                "capability_scope must contain at least one role"
            )
        super().__init__(**crew_kwargs)
        # Pydantic will refuse unknown field assignment, so stash these
        # on ``__dict__`` directly.
        self.__dict__["_arc_client"] = arc_client
        self.__dict__["_capability_scope"] = dict(capability_scope)
        self.__dict__["_subject_map"] = dict(subject_map or {})
        self.__dict__["_ttl_seconds"] = int(ttl_seconds)
        self.__dict__["_role_tokens"] = {}

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def arc_client(self) -> ArcClientLike:
        """The :class:`ArcClient` (or mock) bound to this crew."""
        return self.__dict__["_arc_client"]

    @property
    def capability_scope(self) -> dict[str, ArcScope]:
        """Role → scope mapping in effect for this crew."""
        return dict(self.__dict__["_capability_scope"])

    def scope_for(self, role: str) -> ArcScope:
        """Return the :class:`ArcScope` granted to ``role``.

        Raises :class:`ArcCrewConfigError` if no scope is configured.
        """
        scopes: Mapping[str, ArcScope] = self.__dict__["_capability_scope"]
        if role not in scopes:
            raise ArcCrewConfigError(
                f"no capability scope configured for role {role!r}"
            )
        return scopes[role]

    def token_for(self, role: str) -> CapabilityToken | None:
        """Return the :class:`CapabilityToken` minted for ``role``, if any."""
        tokens: dict[str, CapabilityToken] = self.__dict__["_role_tokens"]
        return tokens.get(role)

    # ------------------------------------------------------------------
    # Wiring
    # ------------------------------------------------------------------

    async def provision_capabilities(self) -> dict[str, CapabilityToken]:
        """Mint a capability token per role and bind it to agent tools.

        Returns the mapping from role to :class:`CapabilityToken`. Tools
        on each agent are rewritten in place so that subsequent
        invocations go through the ARC sidecar with the correct token.
        """
        tokens: dict[str, CapabilityToken] = {}
        for role, scope in self.__dict__["_capability_scope"].items():
            subject = self.__dict__["_subject_map"].get(
                role, _default_subject(role)
            )
            token = await self.arc_client.create_capability(
                subject=subject,
                scope=scope,
                ttl_seconds=self.__dict__["_ttl_seconds"],
            )
            tokens[role] = token

        self.__dict__["_role_tokens"] = tokens
        self._bind_tools(tokens)
        return tokens

    async def attenuate_for_delegation(
        self,
        *,
        delegator_role: str,
        delegate_role: str,
        new_scope: ArcScope,
    ) -> CapabilityToken:
        """Produce a child token for an agent-to-agent delegation.

        The child is strictly narrower than the delegator's token.
        Raises :class:`ArcCrewConfigError` if ``delegator_role`` has no
        active token, and :class:`arc_sdk.errors.ArcValidationError` if
        ``new_scope`` is not a subset of the delegator's scope.
        """
        parent = self.token_for(delegator_role)
        if parent is None:
            raise ArcCrewConfigError(
                f"delegator role {delegator_role!r} has no minted capability; "
                "call provision_capabilities() first"
            )
        try:
            child = await self.arc_client.attenuate_capability(
                parent, new_scope=new_scope
            )
        except ArcValidationError:
            # Re-raise unchanged so callers can match on the SDK type.
            raise

        self.__dict__["_role_tokens"][delegate_role] = child
        # Rebind this role's tools to the new (narrower) token.
        self._bind_tools({delegate_role: child})
        return child

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _bind_tools(self, tokens: Mapping[str, CapabilityToken]) -> None:
        """Update every matching agent's :class:`ArcBaseTool` tools."""
        for agent in self.agents or []:
            role = getattr(agent, "role", None)
            if role is None or role not in tokens:
                continue
            token = tokens[role]
            tools: Iterable[Any] = getattr(agent, "tools", None) or []
            for tool in tools:
                if not isinstance(tool, ArcBaseTool):
                    continue
                tool.bind_capability(token.id)
                tool.bind_arc_client(self.arc_client)
                # Record the agent's scope on the tool for offline
                # assertion helpers. This does not influence sidecar
                # evaluation which is driven by the capability token.
                tool.scope = self.__dict__["_capability_scope"][role]


def _default_subject(role: str) -> str:
    """Produce a deterministic subject placeholder for a role.

    A real deployment supplies its own ``subject_map``; this fallback
    keeps the crew runnable in tests and local demos.
    """
    safe = "".join(c if c.isalnum() else "_" for c in role.lower())
    return f"agent:{safe}"


__all__ = [
    "ArcCrew",
]
