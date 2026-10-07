"""Work items: items/<ID>.md with front matter and Brief/Acceptance/Log sections."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path

from . import clock, frontmatter
from .agents import TIERS
from .store import Store, SwarmError

STATUSES = (
    "open", "claimed", "in-progress", "review", "ready", "integrated", "done",
    "blocked", "disputed", "deferred", "wontfix",
)
SEVERITIES = ("P0", "P1", "P2", "P3")
FINISHED = ("integrated", "done")
CLOSED = ("integrated", "done", "wontfix", "deferred")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

DEFAULTS: dict = {
    "id": "", "title": "", "severity": "P2", "wave": 1, "tier": "mid",
    "status": "open", "owner": "", "assignee": "", "depends_on": [], "paths": [],
    "branch": "", "commits": [], "author_vendor": "", "estimate_hours": 4,
    "review": {"verdict": "", "reviewer": "", "round": 0},
    "attempts": {"started": "", "ci_failures": 0},
    "evidence": [],
}

# (from, to) -> roles that may make the move; "owner" is the item's current owner.
# The conductor may make any move.
TRANSITIONS: dict[tuple[str, str], frozenset[str]] = {
    ("claimed", "in-progress"): frozenset({"owner"}),
    ("in-progress", "review"): frozenset({"owner"}),
    ("review", "ready"): frozenset({"reviewer"}),
    ("review", "in-progress"): frozenset({"reviewer"}),
    ("review", "blocked"): frozenset({"reviewer"}),
    ("review", "disputed"): frozenset({"owner", "reviewer"}),
    ("ready", "integrated"): frozenset({"integrator"}),
    ("ready", "in-progress"): frozenset({"integrator"}),
    ("integrated", "in-progress"): frozenset({"integrator"}),
    ("integrated", "done"): frozenset({"integrator"}),
    ("claimed", "blocked"): frozenset({"owner", "janitor"}),
    ("in-progress", "blocked"): frozenset({"owner", "janitor"}),
}


@dataclass
class Item:
    meta: dict
    body: str

    @property
    def id(self) -> str:
        return self.meta["id"]

    @property
    def status(self) -> str:
        return self.meta["status"]

    def log(self, agent: str, text: str) -> None:
        if not self.body.endswith("\n"):
            self.body += "\n"
        if "## Log\n" not in self.body:
            self.body += "\n## Log\n"
        self.body += f"- {clock.fmt(clock.now())} {agent}: {text}\n"

    def add_section(self, heading: str, text: str) -> None:
        """Insert a section directly above the Log."""
        section = f"## {heading}\n\n{text.strip()}\n\n"
        marker = "## Log\n"
        if marker in self.body:
            head, tail = self.body.split(marker, 1)
            self.body = f"{head}{section}{marker}{tail}"
        else:
            self.body += f"\n{section}"


def _path(store: Store, item_id: str) -> Path:
    return store.path("items", f"{item_id}.md")


def exists(store: Store, item_id: str) -> bool:
    return _path(store, item_id).exists()


def load(store: Store, item_id: str) -> Item:
    path = _path(store, item_id)
    if not path.exists():
        raise SwarmError(f"no such item: {item_id}")
    try:
        meta, body = frontmatter.parse(path.read_text())
    except frontmatter.FrontMatterError as err:
        raise SwarmError(f"items/{item_id}.md is malformed: {err}") from err
    merged = copy.deepcopy(DEFAULTS)
    merged.update(meta)
    return Item(merged, body)


def save(store: Store, item: Item) -> None:
    path = _path(store, item.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(frontmatter.dump(item.meta, item.body))


def all_items(store: Store) -> tuple[list[Item], list[str]]:
    """Every parseable item, plus the file names that failed to parse."""
    good, bad = [], []
    for path in sorted(store.path("items").glob("*.md")):
        try:
            good.append(load(store, path.stem))
        except SwarmError:
            bad.append(path.name)
    return good, bad


def create(
    store: Store, *, item_id: str, title: str, severity: str, wave: int, tier: str,
    paths: list[str], depends_on: list[str], estimate_hours: float, assignee: str, brief: str,
) -> Item:
    if not ID_RE.match(item_id):
        raise SwarmError(f"bad item id {item_id!r}")
    if severity not in SEVERITIES:
        raise SwarmError(f"severity must be one of {', '.join(SEVERITIES)}")
    if tier not in TIERS:
        raise SwarmError(f"tier must be one of {', '.join(TIERS)}")
    if "## Brief" not in brief or "## Acceptance" not in brief:
        raise SwarmError("brief must contain '## Brief' and '## Acceptance' sections")
    meta = copy.deepcopy(DEFAULTS)
    meta.update(
        id=item_id, title=title, severity=severity, wave=wave, tier=tier, paths=paths,
        depends_on=depends_on, estimate_hours=estimate_hours, assignee=assignee,
    )
    item = Item(meta, brief.rstrip("\n") + "\n")
    item.log(store.agent, "created")
    return item


def new(store: Store, **fields) -> None:
    if store.role != "conductor":
        raise SwarmError("only the conductor creates items")

    def mutate() -> bool:
        if exists(store, fields["item_id"]):
            raise SwarmError(f"item {fields['item_id']} already exists")
        save(store, create(store, **fields))
        return True

    store.transact(f"new {fields['item_id']}", mutate)


def deps_unmet(store: Store, item: Item) -> list[str]:
    unmet = []
    for dep in item.meta["depends_on"]:
        if not exists(store, dep):
            unmet.append(f"{dep} (missing)")
            continue
        status = load(store, dep).status
        if status not in FINISHED:
            unmet.append(f"{dep} ({status})")
    return unmet


def check_transition(store: Store, item: Item, new_status: str) -> None:
    if new_status not in STATUSES:
        raise SwarmError(f"unknown status {new_status!r}")
    if store.role == "conductor":
        return
    allowed = TRANSITIONS.get((item.status, new_status))
    if allowed is None:
        raise SwarmError(f"{item.id}: {item.status} -> {new_status} is not a permitted move")
    actor = {store.role} | ({"owner"} if item.meta["owner"] == store.agent else set())
    if not allowed & actor:
        raise SwarmError(f"{item.id}: {store.agent} ({store.role or 'no role'}) may not move {item.status} -> {new_status}")
