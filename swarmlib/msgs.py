"""Append-only inboxes under msgs/<recipient>/. Read state stays local."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from . import agents, clock, frontmatter
from .store import Store, SwarmError

KINDS = ("request", "handoff", "verdict", "blocker", "fyi")
BROADCAST = ("all", "human")


def _valid_recipient(store: Store, to: str) -> bool:
    return to in BROADCAST or to in agents.ROLES or store.path("agents", f"{to}.md").exists()


def write(store: Store, to: str, kind: str, item_id: str, subject: str, body: str) -> Path:
    """Create one message file. Call inside a transaction."""
    if kind not in KINDS:
        raise SwarmError(f"unknown message kind {kind!r}; use one of {', '.join(KINDS)}")
    if not _valid_recipient(store, to):
        raise SwarmError(f"unknown recipient {to!r}")
    folder = store.path("msgs", to)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{clock.stamp()}-{store.agent}-{uuid.uuid4().hex[:6]}.md"
    meta = {
        "from": store.agent, "to": to, "kind": kind, "item": item_id,
        "subject": subject, "sent": clock.fmt(clock.now()),
    }
    path.write_text(frontmatter.dump(meta, body.rstrip("\n") + "\n"))
    return path


def send(store: Store, to: str, kind: str, item_id: str, subject: str, body: str) -> None:
    store.transact(f"msg {to}: {subject[:40]}", lambda: bool(write(store, to, kind, item_id, subject, body)))


def _state_file(store: Store) -> Path:
    base = Path(os.environ.get("SWARM_STATE_DIR", str(Path.home() / ".swarm-state"))).expanduser()
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{store.agent}.seen.json"


def _seen(store: Store) -> set[str]:
    path = _state_file(store)
    return set(json.loads(path.read_text())) if path.exists() else set()


def mark_seen(store: Store, keys: list[str]) -> None:
    path = _state_file(store)
    path.write_text(json.dumps(sorted(_seen(store) | set(keys))))


def inbox(store: Store, *, include_seen: bool = False, mark: bool = True, sync: bool = True) -> list[dict]:
    if sync:
        store.sync()
    folders = [store.agent, "all"] + ([store.role] if store.role else [])
    seen = _seen(store)
    found = []
    for folder in folders:
        for path in sorted(store.path("msgs", folder).glob("*.md")):
            key = f"{folder}/{path.name}"
            if key in seen and not include_seen:
                continue
            meta, body = frontmatter.parse(path.read_text())
            if meta["from"] == store.agent:
                continue
            found.append({**meta, "key": key, "body": body})
    found.sort(key=lambda message: message["sent"])
    if mark:
        mark_seen(store, [message["key"] for message in found])
    return found
