"""Check trains: verify many submitted lanes with one build and attribute failures by changed paths."""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import shlex
import shutil
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator

from . import build, ci, claims, clock, gitio, items, msgs
from .store import Store, SwarmError

FAILED_TEST = re.compile(r"^test .+ \.\.\. FAILED$|^test result: FAILED", re.M)
TRAIN_WORKTREE = "train"  # one per host, reused so target/ stays warm between trains
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


@dataclass
class Workspace:
    """Workspace members by directory and their in-workspace dependencies, from `cargo metadata --no-deps`."""

    dirs: dict[str, str] = field(default_factory=dict)  # member directory relative to the root -> package name
    deps: dict[str, set[str]] = field(default_factory=dict)  # package -> workspace packages it depends on

    @classmethod
    def parse(cls, output: str, root: Path) -> Workspace:
        records = []
        for line in output.splitlines():
            if line.startswith("{"):
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        record = next((r for r in records if isinstance(r, dict) and "packages" in r), None)
        if record is None:
            raise SwarmError("cargo metadata printed no package list")
        base = root.resolve()
        names = {package["name"] for package in record["packages"]}
        ws = cls()
        for package in record["packages"]:
            try:
                rel = Path(package["manifest_path"]).parent.resolve().relative_to(base).as_posix()
            except ValueError:
                continue  # a member outside the checkout cannot own a changed path
            ws.dirs["" if rel == "." else rel] = package["name"]
            ws.deps[package["name"]] = {dep["name"] for dep in package["dependencies"]
                                        if dep.get("path") and dep["name"] in names}
        return ws

    def crate_of(self, rel_path: str) -> str | None:
        """The workspace member that owns a path, or None (non-member packages included)."""
        parts = PurePosixPath(rel_path).parts[:-1]
        for depth in range(len(parts), -1, -1):
            name = self.dirs.get("/".join(parts[:depth]))
            if name:
                return name
        return None

    def lane_crates(self, lane: Lane) -> set[str]:
        return {crate for crate in (self.crate_of(path) for path in lane.changed) if crate}

    def upstream(self, crate: str) -> set[str]:
        """Every workspace crate `crate` depends on, directly or through other members."""
        seen: set[str] = set()
        todo = list(self.deps.get(crate, ()))
        while todo:
            name = todo.pop()
            if name not in seen:
                seen.add(name)
                todo += self.deps.get(name, ())
        return seen


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
    lanes: list[Lane], ws: Workspace, diags: list[tuple[str, str]], crate_failures: dict[str, str],
) -> tuple[dict[str, list[str]], list[str]]:
    """Blame by changed file, then by crate: the lanes that touched it when no lane touched a crate it depends
    on, or the single lane that touched its dependencies. Anything ambiguous is unattributed, naming suspects."""
    merged = [lane for lane in lanes if lane.merged]
    touched = {lane.item_id: ws.lane_crates(lane) for lane in merged}
    per_lane: dict[str, list[str]] = {}
    loose: list[str] = []

    def by_crate(crate: str | None, text: str) -> tuple[list[Lane], str]:
        if not crate:
            return [], text
        direct = [lane for lane in merged if crate in touched[lane.item_id]]
        upstream = ws.upstream(crate)
        via_deps = [lane for lane in merged if lane not in direct and touched[lane.item_id] & upstream]
        if direct and not via_deps:
            return direct, text
        if len(via_deps) == 1 and not direct:
            return via_deps, text
        suspects = sorted(lane.item_id for lane in direct + via_deps)
        return [], f"{text}\n(suspects: {', '.join(suspects)})" if suspects else text

    def blame(owners: list[Lane], text: str) -> None:
        if not owners:
            loose.append(text)
        for lane in owners:
            per_lane.setdefault(lane.item_id, []).append(text)

    for file_name, text in diags:
        owners = [lane for lane in merged if file_name in lane.changed]
        blame(*((owners, text) if owners else by_crate(ws.crate_of(file_name), text)))
    for crate, text in crate_failures.items():
        blame(*by_crate(crate, text))
    return per_lane, loose


def compose(repo: Path, workdir: Path, base: str, lanes: list[Lane], *, repo_url: str, identity: str) -> str:
    """Detached worktree at the base tip with each lane merged in order. Returns the base commit."""
    gitio.run(repo, *gitio.auth_args(), "fetch", "--quiet", repo_url, f"+refs/heads/{base}:refs/remotes/swarm/{base}")
    base_sha = gitio.out(repo, "rev-parse", f"refs/remotes/swarm/{base}")
    checkout(repo, workdir, base_sha)
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
        merged = gitio.run(workdir, "merge", "--no-ff", "--no-edit", "-m", f"chore(train): merge {lane.item_id}", lane.head,
                           check=False)
        if merged.returncode == 0:
            lane.merged = True
            continue
        lane.conflict = gitio.out(workdir, "diff", "--name-only", "--diff-filter=U").split() or ["(merge failed)"]
        gitio.run(workdir, "merge", "--abort", check=False)
    return base_sha


def checkout(repo: Path, workdir: Path, base_sha: str) -> None:
    """Reuse the host's train worktree, cleaned back to `base_sha` but keeping target/, or create it."""
    gitio.run(repo, "worktree", "prune")
    if workdir.exists() and not (workdir / ".git").exists():
        shutil.rmtree(workdir)  # not a worktree any more; it is ours to rebuild
    if not workdir.exists():
        gitio.run(repo, "worktree", "add", "--quiet", "--detach", str(workdir), base_sha)
        return
    gitio.run(workdir, "merge", "--abort", check=False)
    gitio.run(workdir, "reset", "--quiet", "--hard")
    gitio.run(workdir, "clean", "-ffdxq", "-e", "/target")
    gitio.run(workdir, "checkout", "--quiet", "--detach", base_sha)


@contextmanager
def host_lock(lanes_dir: Path) -> Iterator[None]:
    """One train at a time per host: they share the train worktree and its target/."""
    lanes_dir.mkdir(parents=True, exist_ok=True)
    with open(lanes_dir / "train.lock", "a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SwarmError("another check train is running on this host; run again when it finishes") from None
        yield


def new_train_id() -> str:
    return f"T{clock.stamp()}-{secrets.token_hex(3)}"


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
        commands += [(f"test:{crate}", ["cargo", "test", "-p", crate, "--no-fail-fast", "--message-format=json"])
                     for crate in crates]
    return commands


def candidates(store: Store, max_lanes: int) -> list[items.Item]:
    """Submitted or ready lanes. Whole-PR review items also carry a branch and sit in ready, but are not lanes."""
    everything, _ = items.all_items(store)
    chosen = [i for i in everything if i.status in ("submitted", "ready") and i.meta["branch"].startswith("lane/")]
    chosen.sort(key=lambda i: (SEVERITY_ORDER.get(i.meta["severity"], 9), i.meta["wave"], i.id))
    return chosen[:max_lanes]


def _excerpt(texts: list[str]) -> str:
    joined = "\n\n".join(texts)
    return joined if len(joined) <= EXCERPT_CHARS else joined[:EXCERPT_CHARS] + "\n..."


def _tail(output: str, lines: int = 40) -> str:
    return "\n".join([line for line in output.splitlines() if not line.startswith("{")][-lines:])


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
                text += ("\n\nThe integrator may fix this in place; you will get a message if it does. "
                         "`swarm submit` refuses to overwrite commits you do not have.")
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
    ci_runner: ci.Runner | None = None, max_lanes: int | None = None, allow_red: bool = False,
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
    result = TrainResult(train_id=new_train_id())
    if not chosen:
        result.note = "nothing submitted"
        return result
    lanes = [Lane(i.id, i.meta["branch"], i.meta["owner"]) for i in chosen]
    workdir = lanes_dir / TRAIN_WORKTREE
    logs = Path(os.environ.get("SWARM_LOG_DIR", str(Path.home() / ".swarm-logs"))).expanduser() / "trains" / result.train_id
    with host_lock(lanes_dir):
        result.base = compose(repo, workdir, base, lanes, repo_url=repo_url, identity=store.agent)
        gitio.run(workdir, "config", "--worktree", "core.hooksPath", str(store.path("hooks")))
        merged = [lane for lane in lanes if lane.merged]
        ws = Workspace()
        if merged:
            log = logs / "metadata.log"
            code, output = runner(["cargo", "metadata", "--no-deps", "--format-version", "1"], workdir, log)
            try:
                ws = Workspace.parse(output, workdir)
            except SwarmError:
                result.loose.append(f"cargo metadata failed (exit {code}); a manifest may be broken; see {log}")
                merged = []
        crates = sorted(set().union(*(ws.lane_crates(lane) for lane in merged))) if merged else []
        diags: list[tuple[str, str]] = []
        crate_failures: dict[str, str] = {}
        for name, command in train_commands(crates) if merged else []:
            log = logs / f"{name.replace(':', '-')}.log"
            code, output = runner(command, workdir, log)
            found = diagnostics(output, workdir)
            diags += found
            if name.startswith("test:") and code != 0 and FAILED_TEST.search(output):
                crate_failures[name[5:]] = _tail(output)
            elif code != 0 and not found:
                result.loose.append(f"{name} failed with no compiler error or failing test; see {log}")
        per_lane, loose = attribute(lanes, ws, diags, crate_failures)
        result.loose += loose
        result.red = sorted(per_lane)
        result.green = [lane.item_id for lane in merged if lane.item_id not in per_lane]
        result.conflicted = [lane.item_id for lane in lanes if not lane.merged]
        if land and result.green and not result.red and not result.loose:
            if ci_runner is not None and ci.busy(ci_runner, base):
                result.note = "CI is running on the base branch; landing deferred"
            elif ci_runner is not None and not allow_red and ci.red(ci_runner, base):
                result.note = ("CI is red on the base branch; fix or revert the break first, or pass --allow-red "
                               "when this train carries the fix")
            else:
                pushed = gitio.run(workdir, *gitio.auth_args(), "push", "--quiet", repo_url, f"HEAD:refs/heads/{base}",
                                   check=False)
                if pushed.returncode == 0:
                    result.landed = gitio.out(workdir, "rev-parse", "HEAD")
                else:
                    result.note = f"push refused (base moved?): {pushed.stderr.strip()[:200]}"
        _record(store, result, lanes, per_lane, logs)
    return result
