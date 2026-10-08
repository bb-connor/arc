"""Check trains: verify many submitted lanes with one build and attribute failures by changed paths."""

from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import build, ci, claims, clock, gitio, items, msgs
from .store import Store, SwarmError

PACKAGE_NAME = re.compile(r'^\s*name\s*=\s*"([^"]+)"')
TRAIN_ROLES = ("integrator", "conductor")
SEVERITY_ORDER = {s: i for i, s in enumerate(items.SEVERITIES)}
EXCERPT_CHARS = 4000

Runner = Callable[[list[str], Path, Path], tuple[int, str]]  # (command, cwd, log path) -> (exit code, output)


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


@dataclass
class TrainResult:
    train_id: str
    base: str = ""
    landed: str = ""
    green: list[str] = field(default_factory=list)
    red: list[str] = field(default_factory=list)
    conflicted: list[str] = field(default_factory=list)
    loose: list[str] = field(default_factory=list)
    note: str = ""


def remote_command(host: str, *, agent: str, role: str, vendor: str, args: list[str]) -> list[str]:
    """ssh argv that reruns `swarm check-train` on the train host as the same agent."""
    exports = " ".join(f"{k}={shlex.quote(v)}" for k, v in
                       (("SWARM_AGENT", agent), ("SWARM_ROLE", role), ("SWARM_VENDOR", vendor)))
    rest = " ".join(shlex.quote(arg) for arg in args)
    script = f"set -a; . ~/.swarm/env; set +a; export {exports}; exec ~/.local/bin/swarm check-train --local {rest}"
    return ["ssh", "-o", "BatchMode=yes", host, script.rstrip()]


def slot_runner(command: list[str], cwd: Path, log: Path) -> tuple[int, str]:
    """Run one train command in an integrator build slot, capturing its output."""
    code = build.run(command, item="train", build_class="integrator", cwd=cwd, log_path=log)
    return code, log.read_text(errors="replace")


def train_commands(crates: list[str]) -> list[tuple[str, list[str]]]:
    commands = [("check", ["cargo", "check", "--workspace", "--all-targets", "--message-format=json"])]
    if crates:
        packages = [arg for crate in crates for arg in ("-p", crate)]
        commands.append(("clippy", ["cargo", "clippy", "--all-targets", "--message-format=json", *packages,
                                    "--", "-D", "warnings"]))
        commands += [(f"test:{crate}", ["cargo", "test", "-p", crate]) for crate in crates]
    return commands


def candidates(store: Store, max_lanes: int) -> list[items.Item]:
    everything, _ = items.all_items(store)
    chosen = [i for i in everything if i.status in ("submitted", "ready") and i.meta["branch"]]
    chosen.sort(key=lambda i: (SEVERITY_ORDER.get(i.meta["severity"], 9), i.meta["wave"], i.id))
    return chosen[:max_lanes]


def _excerpt(texts: list[str]) -> str:
    joined = "\n\n".join(texts)
    return joined if len(joined) <= EXCERPT_CHARS else joined[:EXCERPT_CHARS] + "\n..."


def _tail(output: str, lines: int = 40) -> str:
    return "\n".join(output.splitlines()[-lines:])


def _move(store: Store, item: items.Item, new_status: str, note: str) -> None:
    items.check_transition(store, item, new_status)
    old = item.status
    item.meta["status"] = new_status
    item.log(store.agent, f"status {old} -> {new_status}: {note}")
    if new_status in items.CLOSED:
        claims.remove(store, item.id)


def _record(store: Store, result: TrainResult, lanes: list[Lane], per_lane: dict[str, list[str]], logs: Path) -> None:
    def mutate() -> bool:
        now = clock.fmt(clock.now())
        for lane in lanes:
            item = items.load(store, lane.item_id)
            if item.status not in ("submitted", "ready"):
                continue  # moved while the train ran; leave it alone
            evidence = {"kind": "check-train", "train": result.train_id, "base": result.base[:12], "at": now,
                        "logs": str(logs)}
            if not lane.merged or lane.item_id in per_lane:
                if lane.merged:
                    evidence["result"], text = "red", _excerpt(per_lane[lane.item_id])
                else:
                    evidence["result"] = "conflict"
                    text = "Does not merge onto the train base or earlier lanes:\n" + "\n".join(f"- {p}" for p in lane.conflict)
                item.add_section(f"Check train {result.train_id}", text)
                _move(store, item, "in-progress", f"check train {result.train_id}: {evidence['result']}")
                if store.path("agents", f"{lane.owner}.md").exists():
                    msgs.write(store, lane.owner, "verdict", item.id, f"{item.id} failed check train {result.train_id}",
                               text[:1500])
            elif result.loose:
                evidence["result"] = "unattributed"
                item.log(store.agent, f"check train {result.train_id}: failures could not be attributed; no change")
            elif result.landed:
                evidence["result"] = "landed"
                _move(store, item, "integrated", f"landed in train {result.train_id} at {result.landed[:12]}")
            else:
                evidence["result"] = "green"
                if item.status == "submitted":
                    _move(store, item, "ready", f"green in check train {result.train_id}")
                else:
                    item.log(store.agent, f"green again in check train {result.train_id}")
            item.meta["evidence"].append(evidence)
            items.save(store, item)
        if result.loose:
            msgs.write(store, "conductor", "blocker", "", f"check train {result.train_id} could not attribute failures",
                       "\n".join(result.loose)[:3000])
        return True

    store.transact(f"check train {result.train_id}", mutate)


def run_train(
    store: Store, *, repo: Path, lanes_dir: Path, repo_url: str, runner: Runner = slot_runner, land: bool = False,
    ci_runner: ci.Runner | None = None, max_lanes: int | None = None,
) -> TrainResult:
    """Compose every submitted or ready lane onto the base, verify once, attribute, and optionally land."""
    if store.role not in TRAIN_ROLES:
        raise SwarmError("only the integrator or the conductor runs check trains")
    if land and store.role != "integrator":
        raise SwarmError("only the integrator lands a train; run without --land to check")
    store.sync()
    config = store.config()
    base = config["base_branch"]
    chosen = candidates(store, max_lanes or config["train_max_lanes"])
    result = TrainResult(train_id=f"T{clock.stamp()}")
    if not chosen:
        result.note = "nothing submitted"
        return result
    lanes = [Lane(i.id, i.meta["branch"], i.meta["owner"]) for i in chosen]
    workdir = lanes_dir / f"train-{result.train_id}"
    logs = Path(os.environ.get("SWARM_LOG_DIR", str(Path.home() / ".swarm-logs"))).expanduser() / "trains" / result.train_id
    lanes_dir.mkdir(parents=True, exist_ok=True)
    try:
        result.base = compose(repo, workdir, base, lanes, repo_url=repo_url, identity=store.agent)
        gitio.run(workdir, "config", "--worktree", "core.hooksPath", str(store.path("hooks")))
        merged = [lane for lane in lanes if lane.merged]
        crates = sorted(set().union(*(lane_crates(workdir, lane) for lane in merged))) if merged else []
        diags: list[tuple[str, str]] = []
        crate_failures: dict[str, str] = {}
        for name, command in train_commands(crates) if merged else []:
            log = logs / f"{name.replace(':', '-')}.log"
            code, output = runner(command, workdir, log)
            if name.startswith("test:"):
                if code != 0:
                    crate_failures[name[5:]] = _tail(output)
                continue
            found = diagnostics(output, workdir)
            diags += found
            if code != 0 and not found:
                result.loose.append(f"{name} failed with no diagnostics; see {log}")
        per_lane, loose = attribute(lanes, workdir, diags, crate_failures)
        result.loose += loose
        result.red = sorted(per_lane)
        result.green = [lane.item_id for lane in merged if lane.item_id not in per_lane]
        result.conflicted = [lane.item_id for lane in lanes if not lane.merged]
        if land and result.green and not result.red and not result.loose:
            if ci_runner is not None and ci.busy(ci_runner, base):
                result.note = "CI is running on the base branch; landing deferred"
            else:
                pushed = gitio.run(workdir, *gitio.auth_args(), "push", "--quiet", repo_url, f"HEAD:refs/heads/{base}",
                                   check=False)
                if pushed.returncode == 0:
                    result.landed = gitio.out(workdir, "rev-parse", "HEAD")
                else:
                    result.note = f"push refused (base moved?): {pushed.stderr.strip()[:200]}"
        _record(store, result, lanes, per_lane, logs)
    finally:
        gitio.run(repo, "worktree", "remove", "--force", str(workdir), check=False)
    return result
