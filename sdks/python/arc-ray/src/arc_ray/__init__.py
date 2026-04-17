"""ARC Ray integration.

Wraps Ray's Python SDK (:mod:`ray`) so every ``@ray.remote`` task and
every :class:`ArcActor` method call flows through the ARC sidecar for
capability-scoped authorisation.

Public surface:

* :func:`arc_remote` -- decorator that wraps :func:`ray.remote` with a
  pre-dispatch ARC capability check. Denied remote tasks raise
  :class:`PermissionError` inside the worker; Ray propagates the
  exception through :func:`ray.get` so the driver sees a
  ``RayTaskError`` whose cause is :class:`PermissionError`.
* :class:`ArcActor` -- base class Ray actors inherit from. Holds a
  standing capability grant minted at actor creation; method-level
  :meth:`ArcActor.requires` decorators validate a per-call scope
  against the grant before the method body runs.
* :func:`requires` -- standalone alias for :meth:`ArcActor.requires`
  for import convenience (``from arc_ray import requires``).
* :class:`StandingGrant` -- data class wrapping the capability token
  pinned to an :class:`ArcActor` instance. Supports
  :meth:`StandingGrant.attenuate` for delegating narrower scopes to
  child actors.
* :class:`ArcRayError` / :class:`ArcRayConfigError` -- error types.
"""

from arc_ray.actor import ArcActor
from arc_ray.errors import ArcRayConfigError, ArcRayError
from arc_ray.grants import StandingGrant, scope_from_spec
from arc_ray.remote import arc_remote

#: Standalone alias for :meth:`ArcActor.requires`. Import convenience:
#: ``from arc_ray import requires``; both spellings are stable public
#: API.
requires = ArcActor.requires

__all__ = [
    "ArcActor",
    "ArcRayConfigError",
    "ArcRayError",
    "StandingGrant",
    "arc_remote",
    "requires",
    "scope_from_spec",
]
