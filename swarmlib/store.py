"""Git-backed coordination store with optimistic concurrency.

Every write fetches the remote `swarm` branch, applies an idempotent
mutation, commits and pushes. A rejected (non-fast-forward) push means
someone else won the race: reset to the new head and apply again.
"""

from __future__ import annotations

import json
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import clock, frontmatter, gitio, secrets

BRANCH = "swarm"
MAX_ATTEMPTS = 8
CONFIG_DEFAULTS = {
    "active_waves": [1],
    "base_branch": "integration/beta-next",
    "ci_max_in_flight": 10,
    "train_pr": 0,
}


class SwarmError(RuntimeError):
    """A refusal the CLI reports to the caller (exit status 2)."""


class Halted(SwarmError):
    """The swarm, this role, or this agent is halted."""


@dataclass
class Store:
    root: Path
    agent: str
    role: str = ""
    vendor: str = ""
    remote: str = "origin"
    hooks: list[Callable[[], None]] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "Store":
        root = Path(os.environ.get("SWARM_HOME", str(Path.home() / "swarm"))).expanduser()
        return cls(
            root=root,
            agent=os.environ.get("SWARM_AGENT", ""),
            role=os.environ.get("SWARM_ROLE", ""),
            vendor=os.environ.get("SWARM_VENDOR", ""),
        )

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def git(self, *args: str, check: bool = True):
        return gitio.run(self.root, *gitio.auth_args(), *args, check=check)

    def sync(self) -> None:
        """Discard local state and move to the remote head."""
        self.git("fetch", "--quiet", self.remote, BRANCH)
        self.git("reset", "--quiet", "--hard", "FETCH_HEAD")
        self.git("clean", "-fdq")

    def config(self) -> dict:
        path = self.path("config.json")
        data = json.loads(path.read_text()) if path.exists() else {}
        return {**CONFIG_DEFAULTS, **data}

    def halt_reason(self) -> str | None:
        path = self.path("HALT")
        if not path.exists():
            return None
        meta, _ = frontmatter.parse(path.read_text())
        mine = {"all", f"agent:{self.agent}"} | ({f"role:{self.role}"} if self.role else set())
        if mine & set(meta.get("scopes", [])):
            return str(meta.get("reason", "halted"))
        return None

    def transact(self, message: str, mutate: Callable[[], bool], *, ignore_halt: bool = False) -> bool:
        """Apply `mutate` to a fresh copy of the remote head and push it."""
        if not self.agent:
            raise SwarmError("SWARM_AGENT is not set")
        for attempt in range(MAX_ATTEMPTS):
            self.sync()
            if not ignore_halt:
                reason = self.halt_reason()
                if reason is not None:
                    raise Halted(f"swarm is halted: {reason}")
            if not mutate():
                return False
            for hook in self.hooks:
                hook()
            self.git("add", "-A")
            staged = self.git("diff", "--cached", "--name-only").stdout.split()
            if not staged:
                return False
            self._refuse_secrets(staged)
            email = os.environ.get("SWARM_EMAIL", f"{self.agent}@swarm.invalid")
            self.git(
                "-c", f"user.name={self.agent}", "-c", f"user.email={email}",
                "commit", "--quiet", "--no-verify", "-m", f"[swarm] {self.agent}: {message}",
            )
            pushed = self.git("push", "--quiet", self.remote, f"HEAD:refs/heads/{BRANCH}", check=False)
            if pushed.returncode == 0:
                return True
            time.sleep(random.uniform(0.05, 0.3) * (attempt + 1))
        raise SwarmError(f"gave up after {MAX_ATTEMPTS} contended pushes: {message}")

    def _refuse_secrets(self, staged: list[str]) -> None:
        findings = []
        for name in staged:
            path = self.path(name)
            if path.is_file():
                text = path.read_text(errors="replace")
                findings += [f"{name}:{line}: {kind}" for kind, line in secrets.scan(text)]
        if findings:
            raise SwarmError("refusing to push credential-shaped content:\n  " + "\n  ".join(findings))


def halt(store: Store, scope: str, reason: str) -> None:
    if store.role != "conductor":
        raise SwarmError("only the conductor (or Connor, with SWARM_ROLE=conductor) can halt")
    if scope != "all" and not scope.startswith(("role:", "agent:")):
        raise SwarmError("scope must be 'all', 'role:<role>' or 'agent:<id>'")

    def mutate() -> bool:
        path = store.path("HALT")
        meta = frontmatter.parse(path.read_text())[0] if path.exists() else {"scopes": []}
        if scope in meta["scopes"]:
            return False
        meta.update(scopes=meta["scopes"] + [scope], reason=reason, by=store.agent, at=clock.fmt(clock.now()))
        path.write_text(frontmatter.dump(meta, ""))
        return True

    store.transact(f"halt {scope}", mutate, ignore_halt=True)


def resume(store: Store, scope: str | None) -> None:
    if store.role != "conductor":
        raise SwarmError("only the conductor (or Connor, with SWARM_ROLE=conductor) can resume")

    def mutate() -> bool:
        path = store.path("HALT")
        if not path.exists():
            return False
        meta, _ = frontmatter.parse(path.read_text())
        remaining = [] if scope is None else [s for s in meta["scopes"] if s != scope]
        if remaining:
            meta["scopes"] = remaining
            path.write_text(frontmatter.dump(meta, ""))
        else:
            path.unlink()
        return True

    store.transact(f"resume {scope or 'all'}", mutate, ignore_halt=True)


def set_config(store: Store, key: str, raw_value: str) -> None:
    if store.role != "conductor":
        raise SwarmError("only the conductor changes config.json")
    if key not in CONFIG_DEFAULTS:
        raise SwarmError(f"unknown config key {key!r}; known: {', '.join(CONFIG_DEFAULTS)}")
    value = json.loads(raw_value)

    def mutate() -> bool:
        path = store.path("config.json")
        data = json.loads(path.read_text()) if path.exists() else {}
        data[key] = value
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        return True

    store.transact(f"config {key}", mutate)


RECORD_KINDS = {"decision": "decisions", "digest": "digests"}


def record(store: Store, kind: str, name: str, text: str) -> str:
    """Write a conductor decision (auto-numbered) or digest. Returns its path in the store."""
    if store.role != "conductor":
        raise SwarmError("only the conductor records decisions and digests")
    if kind not in RECORD_KINDS:
        raise SwarmError(f"kind must be one of {', '.join(RECORD_KINDS)}")
    if not name or not all(c.isalnum() or c in "-." for c in name):
        raise SwarmError("name may contain only letters, digits, '-' and '.'")
    written: list[str] = []

    def mutate() -> bool:
        folder = store.path(RECORD_KINDS[kind])
        folder.mkdir(parents=True, exist_ok=True)
        if kind == "decision":
            numbers = [int(p.name[:4]) for p in folder.glob("[0-9][0-9][0-9][0-9]-*.md")]
            filename = f"{max(numbers, default=0) + 1:04d}-{name}.md"
        else:
            filename = f"{name}.md"
        target = folder / filename
        if target.exists():
            raise SwarmError(f"{RECORD_KINDS[kind]}/{filename} already exists")
        target.write_text(text.rstrip("\n") + "\n")
        written[:] = [f"{RECORD_KINDS[kind]}/{filename}"]
        return True

    store.transact(f"record {kind} {name}", mutate)
    return written[0]
