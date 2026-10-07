"""Agent roster: agents/<id>.md front matter."""

from __future__ import annotations

import re
from pathlib import Path

from . import clock, frontmatter
from .store import Store, SwarmError

ROLES = ("conductor", "integrator", "worker", "reviewer", "docs", "janitor", "security")
VENDORS = ("claude", "codex", "cursor", "hermes")
TIERS = ("premium", "mid", "cheap")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
STALE_MINUTES = 30


def _path(store: Store, agent_id: str) -> Path:
    return store.path("agents", f"{agent_id}.md")


def load(store: Store, agent_id: str) -> dict | None:
    path = _path(store, agent_id)
    if not path.exists():
        return None
    return frontmatter.parse(path.read_text())[0]


def all_agents(store: Store) -> list[dict]:
    return [frontmatter.parse(p.read_text())[0] for p in sorted(store.path("agents").glob("*.md"))]


def register(
    store: Store, *, agent_id: str, machine: str, vendor: str, role: str, model: str, effort: str, tiers: list[str]
) -> None:
    if not ID_RE.match(agent_id):
        raise SwarmError(f"bad agent id {agent_id!r}; use <vendor>-<machine>-<role><n>")
    if vendor not in VENDORS:
        raise SwarmError(f"vendor must be one of {', '.join(VENDORS)}")
    if role not in ROLES:
        raise SwarmError(f"role must be one of {', '.join(ROLES)}")
    if not set(tiers) <= set(TIERS):
        raise SwarmError(f"tiers must be drawn from {', '.join(TIERS)}")
    if agent_id != store.agent and store.role != "conductor":
        raise SwarmError("agents register themselves; only the conductor registers others")

    def mutate() -> bool:
        _path(store, agent_id).parent.mkdir(parents=True, exist_ok=True)
        meta = {
            "id": agent_id, "machine": machine, "vendor": vendor, "role": role, "model": model,
            "effort": effort, "tiers": tiers, "status": "active",
            "last_heartbeat": clock.fmt(clock.now()), "throttled_until": "",
        }
        _path(store, agent_id).write_text(frontmatter.dump(meta, ""))
        return True

    store.transact(f"register {agent_id}", mutate)


def touch(store: Store, *, status: str | None = None, throttled_until: str | None = None) -> bool:
    """Refresh the caller's heartbeat. Call inside a transaction."""
    meta = load(store, store.agent)
    if meta is None:
        return False
    meta["last_heartbeat"] = clock.fmt(clock.now())
    if status is not None:
        meta["status"] = status
    if throttled_until is not None:
        meta["throttled_until"] = throttled_until
    _path(store, store.agent).write_text(frontmatter.dump(meta, ""))
    return True


def is_stale(meta: dict) -> bool:
    beat = meta.get("last_heartbeat")
    return not beat or clock.now() - clock.parse(beat) > clock.minutes(STALE_MINUTES)
