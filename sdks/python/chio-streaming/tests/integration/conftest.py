"""Pytest fixtures for live-broker integration tests.

The whole module is auto-skipped unless ``CHIO_INTEGRATION=1`` is set in
the environment, so a normal ``uv run pytest`` invocation never touches
a real broker. When the gate is on, each broker fixture probes its
endpoint up front and skips (with a clear message) instead of letting a
connection error noise up the failure list -- so devs who forgot to
``docker compose up`` get a one-line "broker not reachable" instead of
a backtrace tower.

Endpoints default to the ports published by ``infra/streaming-compose.yml``
(redis 16379, nats 14222) and can be overridden via env vars to point at
an alternate stack.
"""

from __future__ import annotations

import asyncio
import os
import socket
import uuid
from collections.abc import AsyncIterator
from urllib.parse import urlparse

import pytest
import pytest_asyncio

INTEGRATION_FLAG = "CHIO_INTEGRATION"

DEFAULT_REDIS_URL = "redis://localhost:16379/0"
DEFAULT_NATS_URL = "nats://localhost:14222"

REDIS_URL_ENV = "CHIO_TEST_REDIS_URL"
NATS_URL_ENV = "CHIO_TEST_NATS_URL"


def _integration_enabled() -> bool:
    return os.environ.get(INTEGRATION_FLAG, "").strip() not in ("", "0", "false", "False")


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Skip every test in this directory when the gate is off.

    Pytest collects the integration tests regardless (the ``conftest`` is
    only consulted once collection reaches this directory), but the gate
    keeps a CI run that has not opted in from accidentally hitting real
    brokers.
    """
    if _integration_enabled():
        return
    skip = pytest.mark.skip(
        reason=f"set {INTEGRATION_FLAG}=1 to run live broker integration tests"
    )
    here = os.path.dirname(__file__)
    for item in items:
        if str(item.fspath).startswith(here):
            item.add_marker(skip)


def _tcp_reachable(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def redis_url() -> str:
    return os.environ.get(REDIS_URL_ENV, DEFAULT_REDIS_URL)


@pytest_asyncio.fixture
async def redis_client(redis_url: str) -> AsyncIterator[object]:
    """Yield a connected ``redis.asyncio.Redis`` or skip if unreachable."""
    parsed = urlparse(redis_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 6379
    if not _tcp_reachable(host, port):
        pytest.skip(
            f"redis not reachable at {host}:{port}; "
            f"start `docker compose -f infra/streaming-compose.yml up -d`"
        )
    try:
        from redis.asyncio import Redis  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("redis-py not installed; `uv sync --extra redis`")

    client = Redis.from_url(redis_url, decode_responses=False)
    try:
        # Ping verifies AUTH/db selection, not just the TCP open.
        await asyncio.wait_for(client.ping(), timeout=2.0)
    except Exception as exc:  # pragma: no cover - readiness probe
        await client.aclose()
        pytest.skip(f"redis ping failed at {redis_url}: {exc}")
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def redis_unique_stream() -> str:
    """A fresh stream name per test so XADD / XACK state never collides."""
    return f"chio-it-tasks-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# NATS / JetStream
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def nats_url() -> str:
    return os.environ.get(NATS_URL_ENV, DEFAULT_NATS_URL)


@pytest_asyncio.fixture
async def nats_connection(nats_url: str) -> AsyncIterator[object]:
    """Yield a connected ``nats.NATS`` or skip if unreachable."""
    parsed = urlparse(nats_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 4222
    if not _tcp_reachable(host, port):
        pytest.skip(
            f"nats not reachable at {host}:{port}; "
            f"start `docker compose -f infra/streaming-compose.yml up -d`"
        )
    try:
        import nats  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("nats-py not installed; `uv sync --extra nats`")

    try:
        nc = await asyncio.wait_for(nats.connect(nats_url), timeout=2.0)
    except Exception as exc:  # pragma: no cover - readiness probe
        pytest.skip(f"nats connect failed at {nats_url}: {exc}")
    try:
        yield nc
    finally:
        await nc.drain()


@pytest.fixture
def nats_unique_subject_root() -> str:
    """A unique subject prefix per test so streams / consumers do not collide."""
    return f"chio_it_{uuid.uuid4().hex[:12]}"
