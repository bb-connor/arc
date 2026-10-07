"""Lane worktrees: one per item, cut from the integration branch, with swarm hooks."""

from __future__ import annotations

import os
import re
from pathlib import Path

from . import gitio, items
from .store import Store, SwarmError

SLUG_RE = re.compile(r"[^a-z0-9]+")


def repo_url() -> str:
    return os.environ.get("SWARM_GIT_URL", "https://github.com/bb-connor/arc.git")


def slug(title: str) -> str:
    return SLUG_RE.sub("-", title.lower()).strip("-")[:40].rstrip("-") or "item"


def lane_branch(item: items.Item) -> str:
    return item.meta["branch"] or f"lane/{item.id}-{slug(item.meta['title'])}"


def _fetch(repo: Path, branch: str) -> bool:
    proc = gitio.run(repo, *gitio.auth_args(), "fetch", "--quiet", repo_url(),
                     f"+refs/heads/{branch}:refs/remotes/swarm/{branch}", check=False)
    return proc.returncode == 0


def _configure(store: Store, repo: Path, target: Path, item_id: str) -> None:
    gitio.run(repo, "config", "extensions.worktreeConfig", "true")
    gitio.run(target, "config", "--worktree", "core.hooksPath", str(store.path("hooks")))
    gitio.run(target, "config", "--worktree", "swarm.item", item_id)
    gitio.run(target, "config", "--worktree", "user.name", store.agent)
    gitio.run(target, "config", "--worktree", "user.email", os.environ.get("SWARM_EMAIL", f"{store.agent}@swarm.invalid"))


def create(store: Store, item_id: str, *, repo: Path, lanes: Path, base_branch: str, review: bool = False) -> Path:
    store.sync()
    item = items.load(store, item_id)
    if not review and item.meta["owner"] != store.agent and store.role != "conductor":
        raise SwarmError(f"{item_id} belongs to {item.meta['owner'] or 'nobody'}")
    branch = lane_branch(item)
    target = (lanes / "review" / item_id) if review else (lanes / item_id)
    if target.exists():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    if not _fetch(repo, base_branch):
        raise SwarmError(f"cannot fetch {base_branch} from {repo_url()}")
    remote_lane = _fetch(repo, branch)
    if review:
        if not remote_lane:
            raise SwarmError(f"{branch} is not on the remote yet")
        gitio.run(repo, "worktree", "add", "--detach", str(target), f"refs/remotes/swarm/{branch}")
    elif gitio.run(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}", check=False).returncode == 0:
        gitio.run(repo, "worktree", "add", str(target), branch)
    elif remote_lane:
        gitio.run(repo, "worktree", "add", "-b", branch, str(target), f"refs/remotes/swarm/{branch}")
    else:
        gitio.run(repo, "worktree", "add", "-b", branch, str(target), f"refs/remotes/swarm/{base_branch}")
    _configure(store, repo, target, item_id)
    if not review and not item.meta["branch"]:
        def mutate() -> bool:
            fresh = items.load(store, item_id)
            fresh.meta["branch"] = branch
            fresh.log(store.agent, f"worktree on {branch}")
            items.save(store, fresh)
            return True

        store.transact(f"branch {item_id}", mutate)
    return target
