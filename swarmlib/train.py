"""Check trains: verify many submitted lanes with one build and attribute failures by changed paths."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import gitio

PACKAGE_NAME = re.compile(r'^\s*name\s*=\s*"([^"]+)"')


@dataclass
class Lane:
    item_id: str
    branch: str
    owner: str
    head: str = ""
    changed: list[str] = field(default_factory=list)
    merged: bool = False
    conflict: list[str] = field(default_factory=list)


def package_name(manifest: Path) -> str | None:
    """The [package] name in a Cargo.toml, or None for a workspace-only manifest."""
    in_package = False
    for line in manifest.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_package = stripped == "[package]"
            continue
        if in_package:
            match = PACKAGE_NAME.match(line)
            if match:
                return match.group(1)
    return None


def crate_of(root: Path, rel_path: str) -> str | None:
    """Name of the nearest enclosing package for a workspace-relative path."""
    current = (root / rel_path).parent
    root = root.resolve()
    while True:
        manifest = current / "Cargo.toml"
        if manifest.is_file():
            name = package_name(manifest)
            if name:
                return name
        if current.resolve() == root or current == current.parent:
            return None
        current = current.parent


def lane_crates(root: Path, lane: Lane) -> set[str]:
    return {crate for crate in (crate_of(root, path) for path in lane.changed) if crate}


def diagnostics(output: str, root: Path) -> list[tuple[str, str]]:
    """(workspace-relative file, rendered text) for every error in cargo --message-format=json output."""
    found = []
    prefix = str(root).rstrip("/") + "/"
    for line in output.splitlines():
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = record.get("message") if record.get("reason") == "compiler-message" else None
        if not message or message.get("level") != "error":
            continue
        spans = message.get("spans") or []
        primary = [s["file_name"] for s in spans if s.get("is_primary")] or [s["file_name"] for s in spans]
        text = (message.get("rendered") or message.get("message") or "").strip()
        for file_name in primary[:1] or ["(no span)"]:
            found.append((file_name[len(prefix):] if file_name.startswith(prefix) else file_name, text))
    return found


def attribute(
    lanes: list[Lane], root: Path, diags: list[tuple[str, str]], crate_failures: dict[str, str],
) -> tuple[dict[str, list[str]], list[str]]:
    """Blame by changed file first, then by touched crate. Anything else is unattributed."""
    merged = [lane for lane in lanes if lane.merged]
    crates = {lane.item_id: lane_crates(root, lane) for lane in merged}
    per_lane: dict[str, list[str]] = {}
    loose: list[str] = []

    def blame(owners: list[Lane], text: str) -> None:
        if not owners:
            loose.append(text)
        for lane in owners:
            per_lane.setdefault(lane.item_id, []).append(text)

    for file_name, text in diags:
        owners = [lane for lane in merged if file_name in lane.changed]
        if not owners:
            crate = crate_of(root, file_name)
            owners = [lane for lane in merged if crate and crate in crates[lane.item_id]]
        blame(owners, text)
    for crate, text in crate_failures.items():
        blame([lane for lane in merged if crate in crates[lane.item_id]], text)
    return per_lane, loose


def compose(repo: Path, workdir: Path, base: str, lanes: list[Lane], *, repo_url: str, identity: str) -> str:
    """Detached worktree at the base tip with each lane merged in order. Returns the base commit."""
    gitio.run(repo, *gitio.auth_args(), "fetch", "--quiet", repo_url, f"+refs/heads/{base}:refs/remotes/swarm/{base}")
    base_sha = gitio.out(repo, "rev-parse", f"refs/remotes/swarm/{base}")
    gitio.run(repo, "worktree", "add", "--quiet", "--detach", str(workdir), base_sha)
    gitio.run(repo, "config", "extensions.worktreeConfig", "true")
    gitio.run(workdir, "config", "--worktree", "user.name", identity)
    gitio.run(workdir, "config", "--worktree", "user.email", f"{identity}@swarm.invalid")
    for lane in lanes:
        fetched = gitio.run(repo, *gitio.auth_args(), "fetch", "--quiet", repo_url,
                            f"+refs/heads/{lane.branch}:refs/remotes/swarm/{lane.branch}", check=False)
        if fetched.returncode != 0:
            lane.conflict = ["(branch not on remote)"]
            continue
        lane.head = gitio.out(repo, "rev-parse", f"refs/remotes/swarm/{lane.branch}")
        lane.changed = gitio.out(workdir, "diff", "--name-only", f"{base_sha}...{lane.head}").split()
        merged = gitio.run(workdir, "merge", "--no-ff", "--no-edit", "-m", f"train: {lane.item_id}", lane.head, check=False)
        if merged.returncode == 0:
            lane.merged = True
            continue
        lane.conflict = gitio.out(workdir, "diff", "--name-only", "--diff-filter=U").split() or ["(merge failed)"]
        gitio.run(workdir, "merge", "--abort", check=False)
    return base_sha
