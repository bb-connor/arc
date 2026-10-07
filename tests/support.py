"""Shared fixtures: a bare origin with a seeded swarm branch, agent clones, and a fake arc repo."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from swarmlib.store import Store

SEED_DIRS = ("agents", "items", "claims", "msgs", "decisions", "digests")
BRIEF = "## Brief\n\nDo the thing.\n\n## Acceptance\n\n- It is done.\n"


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "--quiet", "-m", message)
    return git(repo, "rev-parse", "HEAD")


class SwarmCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="swarm-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patcher = mock.patch.dict(os.environ, {
            "SWARM_STATE_DIR": str(self.tmp / "state"),
            "SWARM_BUILD_DIR": str(self.tmp / "build"),
            "SWARM_LOG_DIR": str(self.tmp / "logs"),
            "SWARM_FAKE_NOW": "2026-10-06T12:00:00Z",
            "GH_TOKEN": "",
        })
        patcher.start()
        self.addCleanup(patcher.stop)
        self.origin = self.tmp / "origin.git"
        git(self.tmp, "init", "--quiet", "--bare", "--initial-branch=swarm", str(self.origin))
        seed = self.tmp / "seed"
        git(self.tmp, "init", "--quiet", "--initial-branch=swarm", str(seed))
        for name in SEED_DIRS:
            (seed / name).mkdir()
            (seed / name / ".keep").write_text("")
        commit_all(seed, "seed")
        git(seed, "push", "--quiet", str(self.origin), "swarm")

    def clone(self, agent: str, role: str = "worker", vendor: str = "codex") -> Store:
        path = self.tmp / "clones" / agent
        git(self.tmp, "clone", "--quiet", "--single-branch", "--branch", "swarm", str(self.origin), str(path))
        return Store(root=path, agent=agent, role=role, vendor=vendor)

    def at(self, when: str) -> None:
        os.environ["SWARM_FAKE_NOW"] = when

    def add_item(self, conductor: Store, item_id: str, **overrides) -> None:
        from swarmlib import items  # imported late: items arrives after the store task

        fields = dict(
            item_id=item_id, title=f"Fix {item_id}", severity="P2", wave=1, tier="mid",
            paths=[f"crates/{item_id.lower()}/**"], depends_on=[], estimate_hours=4, assignee="", brief=BRIEF,
        )
        fields.update(overrides)
        items.new(conductor, **fields)

    def make_arc(self) -> tuple[Path, Path]:
        """A bare 'arc' remote with main and integration/beta-next, plus a local clone."""
        arc = self.tmp / "arc.git"
        git(self.tmp, "init", "--quiet", "--bare", "--initial-branch=main", str(arc))
        work = self.tmp / "arc-seed"
        git(self.tmp, "init", "--quiet", "--initial-branch=main", str(work))
        (work / "README.md").write_text("arc\n")
        commit_all(work, "init")
        git(work, "push", "--quiet", str(arc), "main", "main:integration/beta-next")
        repo = self.tmp / "repo"
        git(self.tmp, "clone", "--quiet", str(arc), str(repo))
        os.environ["SWARM_GIT_URL"] = str(arc)
        return arc, repo
