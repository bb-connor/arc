"""Test fixtures for :mod:`chio_ray`.

Ray's full scheduler is heavy to spin up and not relevant to the
behaviour :mod:`chio_ray` is enforcing -- we are testing the
capability-check decorator plumbing, not the Ray scheduler. To keep
the suite fast and deterministic, this conftest installs a minimal
fake ``ray`` module into :data:`sys.modules` *before* the test
modules are imported. The fake implements just enough of the
``ray.remote`` / ``ray.get`` / actor-handle surface to exercise the
Chio enforcement path end-to-end.

The enforcement path is identical under the real Ray scheduler -- the
decorator calls the sidecar synchronously inside the wrapper
function, then dispatches to the wrapped callable -- so the fake
delivers the same behavioural coverage. Set
``CHIO_RAY_USE_REAL=1`` to let the real ``ray`` module be imported
instead (the Ray cluster is still not started; the tests drive the
wrapper function directly).
"""

from __future__ import annotations

import asyncio
import inspect
import os
import sys
import types
from typing import Any


def _maybe_await(value: Any) -> Any:
    """Run a coroutine to completion if ``value`` is one; otherwise return it.

    Real Ray awaits coroutines returned from ``async def`` remote
    functions on the worker's event loop. The fake runs everything
    in-process, so we do the same here by spinning up a fresh loop.
    """
    if inspect.iscoroutine(value):
        return asyncio.run(value)
    return value


# ---------------------------------------------------------------------------
# Fake ray: minimal ``ray.remote`` / ``ray.get`` stand-ins.
# ---------------------------------------------------------------------------


class _FakeObjectRef:
    """Holds the eventually-resolved value (or exception) of a remote call."""

    def __init__(self, value: Any = None, *, error: BaseException | None = None) -> None:
        self._value = value
        self._error = error

    def resolve(self) -> Any:
        if self._error is not None:
            raise self._error
        return self._value


class _FakeRemoteFunction:
    """Minimal drop-in for a Ray remote function handle.

    Calls the wrapped function in-process on ``.remote(...)`` and
    stores the result (or exception) on a :class:`_FakeObjectRef` so
    the test can resolve it via :func:`ray.get`.
    """

    def __init__(self, fn: Any) -> None:
        self._fn = fn
        # Mirror Ray's ``remote_function._function`` attribute so code
        # that wants to introspect the wrapped callable still works.
        self._function = fn

    def remote(self, *args: Any, **kwargs: Any) -> _FakeObjectRef:
        try:
            result = _maybe_await(self._fn(*args, **kwargs))
        except BaseException as exc:  # noqa: BLE001 -- mirror Ray's propagation
            return _FakeObjectRef(error=exc)
        return _FakeObjectRef(value=result)


class _FakeBoundMethod:
    """Minimal drop-in for ``actor_handle.method`` (pre-``.remote()``)."""

    def __init__(self, instance: Any, name: str) -> None:
        self._instance = instance
        self._name = name

    def remote(self, *args: Any, **kwargs: Any) -> _FakeObjectRef:
        try:
            method = getattr(self._instance, self._name)
            result = _maybe_await(method(*args, **kwargs))
        except BaseException as exc:  # noqa: BLE001 -- Ray parity
            return _FakeObjectRef(error=exc)
        return _FakeObjectRef(value=result)


class _FakeRemoteActorHandle:
    """Minimal drop-in for a Ray actor handle (post-``.remote()``)."""

    def __init__(self, instance: Any) -> None:
        self._instance = instance

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") or not hasattr(self._instance, name):
            raise AttributeError(name)
        return _FakeBoundMethod(self._instance, name)


class _FakeRemoteActorClass:
    """Minimal drop-in for a Ray remote actor class (pre-``.remote()``)."""

    def __init__(self, cls: Any) -> None:
        self._cls = cls

    def remote(self, *args: Any, **kwargs: Any) -> _FakeRemoteActorHandle:
        instance = self._cls(*args, **kwargs)
        return _FakeRemoteActorHandle(instance)


def _fake_remote(*args: Any, **kwargs: Any) -> Any:
    """Drop-in for :func:`ray.remote`.

    Matches the two call shapes we use in :mod:`chio_ray.remote`:

    * ``@ray.remote`` -- single positional ``args[0]`` is the target.
    * ``@ray.remote(**options)`` -- returns a decorator that wraps the
      target.
    """
    if args and not kwargs and len(args) == 1 and callable(args[0]):
        target = args[0]
        if isinstance(target, type):
            return _FakeRemoteActorClass(target)
        return _FakeRemoteFunction(target)

    def decorator(target: Any) -> Any:
        if isinstance(target, type):
            return _FakeRemoteActorClass(target)
        return _FakeRemoteFunction(target)

    return decorator


def _fake_get(ref: Any) -> Any:
    """Resolve a :class:`_FakeObjectRef` (or list of them)."""
    if isinstance(ref, list):
        return [_fake_get(r) for r in ref]
    if isinstance(ref, _FakeObjectRef):
        return ref.resolve()
    raise TypeError(f"ray.get expected _FakeObjectRef, got {type(ref).__name__}")


def _install_fake_ray() -> types.ModuleType:
    """Install a minimal fake ``ray`` module into :data:`sys.modules`."""
    module = types.ModuleType("ray")
    module.remote = _fake_remote  # type: ignore[attr-defined]
    module.get = _fake_get  # type: ignore[attr-defined]
    module.ObjectRef = _FakeObjectRef  # type: ignore[attr-defined]
    sys.modules["ray"] = module
    return module


# ---------------------------------------------------------------------------
# Install at import time so test modules `import ray` pick up the fake.
# ---------------------------------------------------------------------------


if os.environ.get("CHIO_RAY_USE_REAL") != "1":
    # Ensure no stale real-Ray module is lingering in sys.modules from
    # an earlier process; reinstall the fake under a predictable name
    # so ``import ray`` at the top of every test module picks it up.
    for _name in list(sys.modules):
        if _name == "ray" or _name.startswith("ray."):
            sys.modules.pop(_name, None)
    _install_fake_ray()
