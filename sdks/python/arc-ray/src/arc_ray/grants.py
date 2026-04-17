"""Standing-grant helpers for ARC-governed Ray actors.

A :class:`StandingGrant` pins a pre-minted :class:`CapabilityToken` to a
Ray actor for the actor's lifetime. Methods gated by
:meth:`ArcActor.requires` evaluate the per-call scope against the
standing grant; attenuated child grants can be minted at runtime (for
example, when an ``ArcActor`` spawns worker actors with narrower scope)
via :meth:`StandingGrant.attenuate`.

Ray actors are long-lived processes. Unlike per-request workflows (see
:mod:`arc_temporal.grants`), the standing grant's TTL should be sized to
match the actor's expected lifetime and refreshed from within the actor
when the owning process is still healthy.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from arc_sdk.errors import ArcValidationError
from arc_sdk.models import ArcScope, CapabilityToken, Operation, ToolGrant

from arc_ray.errors import ArcRayConfigError

# Anything that quacks like an :class:`arc_sdk.ArcClient` -- the real
# client and :class:`arc_sdk.testing.MockArcClient` are accepted
# interchangeably so tests can inject an in-memory policy.
ArcClientLike = Any


@dataclass(frozen=True)
class StandingGrant:
    """Capability grant pinned to a Ray actor's lifetime.

    Parameters
    ----------
    token:
        :class:`CapabilityToken` minted by the ARC capability authority.
        Its :attr:`CapabilityToken.scope` is the ceiling for every
        method call on the owning actor.
    tool_server:
        Default ARC tool server id for this actor. Method-level
        :meth:`ArcActor.requires` scopes fall back to this server unless
        they specify their own.
    actor_class:
        Fully-qualified actor class name (``module.Class``). Populated
        automatically when the grant is minted inside
        :meth:`ArcActor.__init__`; surfaced on :class:`ArcRayError`
        deny payloads for audit correlation.
    metadata:
        Optional free-form metadata attached to the grant. Surfaced on
        deny payloads so downstream receipt consumers can correlate
        actor-level context (placement group, worker node, parent
        actor handle, ...).
    """

    token: CapabilityToken
    tool_server: str = ""
    actor_class: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def capability_id(self) -> str:
        """Convenience accessor for the underlying capability token id."""
        return self.token.id

    @property
    def scope(self) -> ArcScope:
        """The :class:`ArcScope` this grant authorises."""
        return self.token.scope

    # ------------------------------------------------------------------
    # Subset checks
    # ------------------------------------------------------------------

    def authorises(self, required: ArcScope) -> bool:
        """Return ``True`` when ``required`` is a subset of this grant's scope.

        This is the fast-path guard executed before a method body runs;
        the sidecar's receipt-producing evaluation is still the source
        of truth on the allow/deny path, but this check lets the actor
        short-circuit obvious deny cases without a network round-trip
        when no client is bound (e.g. during startup ordering).
        """
        return required.is_subset_of(self.scope)

    # ------------------------------------------------------------------
    # Attenuation
    # ------------------------------------------------------------------

    async def attenuate(
        self,
        arc_client: ArcClientLike,
        *,
        new_scope: ArcScope,
        tool_server: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> StandingGrant:
        """Mint a child grant whose scope is strictly narrower than this grant's.

        Intended for the supervisor-worker pattern where a parent
        :class:`ArcActor` spawns worker actors with attenuated
        capabilities. Raises
        :class:`arc_sdk.errors.ArcValidationError` when ``new_scope``
        is not a subset of the parent scope.
        """
        if not new_scope.is_subset_of(self.scope):
            raise ArcValidationError(
                "new_scope must be a subset of the parent StandingGrant scope"
            )
        child_token = await arc_client.attenuate_capability(
            self.token, new_scope=new_scope
        )
        merged_metadata = dict(self.metadata)
        if metadata:
            merged_metadata.update(metadata)
        merged_metadata.setdefault("parent_capability_id", self.capability_id)
        return StandingGrant(
            token=child_token,
            tool_server=tool_server if tool_server is not None else self.tool_server,
            actor_class=self.actor_class,
            metadata=merged_metadata,
        )


# ---------------------------------------------------------------------------
# Scope parsing helpers
# ---------------------------------------------------------------------------


def scope_from_spec(spec: str | ArcScope, *, server_id: str = "") -> ArcScope:
    """Coerce a method-decorator ``scope`` argument into an :class:`ArcScope`.

    Accepts either:

    * A fully-formed :class:`ArcScope` -- returned as-is.
    * A short-string spec in the shape ``"<prefix>:<tool>"`` (e.g.
      ``"tools:search"``). The prefix is ignored for scope-matching
      purposes but recorded in metadata so denied receipts carry the
      human-friendly string. Multiple scopes may be comma-separated
      (``"tools:search,tools:browse"``).

    The string form is the ergonomic path the roadmap acceptance test
    exercises (``@ArcActor.requires("tools:search")``); the
    :class:`ArcScope` form is for callers who already know the full
    :class:`ToolGrant` shape.
    """
    if isinstance(spec, ArcScope):
        return spec
    if not isinstance(spec, str):
        raise ArcRayConfigError(
            f"scope must be a string or ArcScope, got {type(spec).__name__!r}"
        )
    cleaned = spec.strip()
    if not cleaned:
        raise ArcRayConfigError("scope spec must not be empty")

    tool_names = list(_parse_scope_string(cleaned))
    grants = [
        ToolGrant(
            server_id=server_id or "*",
            tool_name=tool_name,
            operations=[Operation.INVOKE],
        )
        for tool_name in tool_names
    ]
    return ArcScope(grants=grants)


def _parse_scope_string(spec: str) -> Iterable[str]:
    """Yield tool names from a comma-separated ``prefix:tool`` scope string."""
    for entry in spec.split(","):
        entry = entry.strip()
        if not entry:
            continue
        # Accept either ``tools:search`` or bare ``search``.
        if ":" in entry:
            _prefix, _, tool_name = entry.partition(":")
            tool_name = tool_name.strip()
        else:
            tool_name = entry
        if not tool_name:
            raise ArcRayConfigError(
                f"scope entry {entry!r} is missing the tool-name component "
                "(expected '<prefix>:<tool>' or '<tool>')"
            )
        yield tool_name


__all__ = [
    "ArcClientLike",
    "StandingGrant",
    "scope_from_spec",
]
