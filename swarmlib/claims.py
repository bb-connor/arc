"""Path claims with leases. A claims/<ID>.json file existing is the lock."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from . import agents, clock, items, msgs, paths
from .store import Store, SwarmError

DEFAULT_TTL_MINUTES = 45
GRACE_MINUTES = 2  # tolerated clock skew between machines


def _path(store: Store, item_id: str) -> Path:
    return store.path("claims", f"{item_id}.json")


def read(store: Store, item_id: str) -> dict | None:
    path = _path(store, item_id)
    return json.loads(path.read_text()) if path.exists() else None


def write(store: Store, claim: dict) -> None:
    path = _path(store, claim["item"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(claim, indent=2, sort_keys=True) + "\n")


def remove(store: Store, item_id: str) -> None:
    _path(store, item_id).unlink(missing_ok=True)


def all_claims(store: Store) -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted(store.path("claims").glob("*.json"))]


def is_expired(claim: dict, now: datetime) -> bool:
    return now > clock.parse(claim["expires"]) + clock.minutes(GRACE_MINUTES)


def active(store: Store, now: datetime) -> list[dict]:
    return [c for c in all_claims(store) if not is_expired(c, now)]


def _lease(item_id: str, owner: str, wanted: list[str], share: bool, ttl: int, now: datetime) -> dict:
    return {
        "item": item_id, "agent": owner, "paths": wanted, "shared": share, "ttl_minutes": ttl,
        "acquired": clock.fmt(now), "expires": clock.fmt(now + clock.minutes(ttl)),
    }


def claim(
    store: Store, item_id: str, globs: list[str], *, share: bool = False, steal: bool = False,
    ttl: int = DEFAULT_TTL_MINUTES, owner: str | None = None,
) -> None:
    owner = owner or store.agent
    if owner != store.agent and store.role != "conductor":
        raise SwarmError("only the conductor claims on behalf of another agent")
    if store.role == "integrator":
        raise SwarmError("the integrator fixes integration breaks in place but never claims implementation items")

    def mutate() -> bool:
        now = clock.now()
        item = items.load(store, item_id)
        existing = read(store, item_id)
        previous = None
        if existing is not None:
            if not is_expired(existing, now):
                raise SwarmError(f"{item_id} is claimed by {existing['agent']} until {existing['expires']}")
            if not steal:
                raise SwarmError(f"{item_id} has an expired claim by {existing['agent']}; use --steal")
            previous = existing["agent"]
        elif item.status != "open":
            raise SwarmError(f"{item_id} is {item.status}, not open")
        unmet = items.deps_unmet(store, item)
        if unmet:
            raise SwarmError(f"{item_id} waits on: {', '.join(unmet)}")
        wanted = list(globs) or list(item.meta["paths"])
        if not wanted:
            raise SwarmError(f"{item_id} lists no paths; pass --paths")
        if not share:
            clashes = [
                f"{w} vs {h} ({other['item']} by {other['agent']})"
                for other in active(store, now) if other["item"] != item_id
                for w, h in paths.find_overlaps(wanted, other["paths"])
            ]
            if clashes:
                raise SwarmError("paths overlap active claims: " + "; ".join(clashes))
        write(store, _lease(item_id, owner, wanted, share, ttl, now))
        item.meta["owner"] = owner
        if item.status == "open":
            item.meta["status"] = "claimed"
        if not item.meta["attempts"]["started"]:
            item.meta["attempts"]["started"] = clock.fmt(now)
        item.log(store.agent, f"claimed for {owner}" + (f", taking over from {previous}" if previous else ""))
        items.save(store, item)
        if previous and store.path("agents", f"{previous}.md").exists():
            msgs.write(store, previous, "fyi", item_id, f"claim on {item_id} taken over",
                       f"Your expired claim on {item_id} now belongs to {owner}.")
        return True

    store.transact(f"claim {item_id}", mutate)


def renew_mine(store: Store) -> None:
    """Extend the caller's leases and heartbeat. Runs inside every write."""
    now = clock.now()
    agents.touch(store)
    for lease in all_claims(store):
        if lease["agent"] == store.agent:
            lease["expires"] = clock.fmt(now + clock.minutes(lease.get("ttl_minutes", DEFAULT_TTL_MINUTES)))
            write(store, lease)


def heartbeat(store: Store, *, status: str | None = None, throttled_until: str | None = None) -> None:
    def mutate() -> bool:
        renew_mine(store)
        agents.touch(store, status=status, throttled_until=throttled_until)
        return True

    store.transact("heartbeat", mutate)


def release(store: Store, item_id: str) -> None:
    def mutate() -> bool:
        lease = read(store, item_id)
        if lease is None:
            return False
        if lease["agent"] != store.agent and store.role != "conductor":
            raise SwarmError(f"{item_id} is claimed by {lease['agent']}, not you")
        remove(store, item_id)
        item = items.load(store, item_id)
        item.log(store.agent, "released claim")
        items.save(store, item)
        return True

    store.transact(f"release {item_id}", mutate)


def reassign(store: Store, item_id: str, new_owner: str, *, ttl: int = DEFAULT_TTL_MINUTES) -> None:
    if store.role != "conductor":
        raise SwarmError("only the conductor reassigns")

    def mutate() -> bool:
        now = clock.now()
        item = items.load(store, item_id)
        previous = item.meta["owner"]
        lease = read(store, item_id)
        wanted = lease["paths"] if lease else list(item.meta["paths"])
        write(store, _lease(item_id, new_owner, wanted, bool(lease and lease["shared"]), ttl, now))
        item.meta["owner"] = new_owner
        if item.status == "open":
            item.meta["status"] = "claimed"
        if not item.meta["attempts"]["started"]:
            item.meta["attempts"]["started"] = clock.fmt(now)
        item.log(store.agent, f"reassigned {previous or 'nobody'} -> {new_owner}")
        items.save(store, item)
        for who in (previous, new_owner):
            if who and store.path("agents", f"{who}.md").exists():
                msgs.write(store, who, "handoff", item_id, f"{item_id} reassigned to {new_owner}",
                           f"The conductor moved {item_id} from {previous or 'nobody'} to {new_owner}.")
        return True

    store.transact(f"reassign {item_id}", mutate)
