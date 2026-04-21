"""Chio Ray integration.

Wraps Ray's Python SDK (:mod:`ray`) so every ``@ray.remote`` task and
every :class:`ChioActor` method call flows through the Chio sidecar for
capability-scoped authorisation.

Public surface:

* :func:`chio_remote` -- decorator that wraps :func:`ray.remote` with a
  pre-dispatch Chio capability check. Denied remote tasks raise
  :class:`PermissionError` inside the worker; Ray propagates the
  exception through :func:`ray.get` so the driver sees a
  ``RayTaskError`` whose cause is :class:`PermissionError`.
* :class:`ChioActor` -- base class Ray actors inherit from. Holds a
  standing capability grant minted at actor creation; method-level
  :meth:`ChioActor.requires` decorators validate a per-call scope
  against the grant before the method body runs.
* :func:`requires` -- standalone alias for :meth:`ChioActor.requires`
  for import convenience (``from chio_ray import requires``).
* :class:`StandingGrant` -- data class wrapping the capability token
  pinned to an :class:`ChioActor` instance. Supports
  :meth:`StandingGrant.attenuate` for delegating narrower scopes to
  child actors.
* :class:`ChioRayError` / :class:`ChioRayConfigError` -- error types.
"""

from chio_ray.actor import ChioActor
from chio_ray.errors import ChioRayConfigError, ChioRayError
from chio_ray.grants import StandingGrant, scope_from_spec
from chio_ray.remote import chio_remote

#: Standalone alias for :meth:`ChioActor.requires`. Import convenience:
#: ``from chio_ray import requires``; both spellings are stable public
#: API.
requires = ChioActor.requires

__all__ = [
    "ChioActor",
    "ChioRayConfigError",
    "ChioRayError",
    "StandingGrant",
    "chio_remote",
    "requires",
    "scope_from_spec",
]
