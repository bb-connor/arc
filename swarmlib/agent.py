"""swarm-agent: run one registered agent (worker, docs, reviewer, janitor, conductor, integrator)."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import agents, board, ci, claims, clock, gitio, items, lifecycle, msgs, reviews, worktree
from .store import Halted, Store, SwarmError

RATE_LIMIT_RE = re.compile(
    r"(?i)rate.?limit|usage limit|quota exceeded|too many requests|\b429\b|limit reached|try again (?:at|in)"
)
THROTTLE_MINUTES = 30
ITEM_ROLES = ("worker", "docs")
SESSION_ROLES = ("conductor", "integrator")
REPLY_LIMIT = 6000


@dataclass
class Execution:
    returncode: int
    output: str


Executor = Callable[[list[str], Path, Path], Execution]


def execute(command: list[str], cwd: Path, log_path: Path, timeout: float = 4 * 3600) -> Execution:
    """Run an agent CLI, streaming its output to a log file you can tail."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as log:
        try:
            code = subprocess.run(
                command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=timeout
            ).returncode
        except subprocess.TimeoutExpired:
            code = 124
    return Execution(code, log_path.read_text(errors="replace"))


def logs_root() -> Path:
    return Path(os.environ.get("SWARM_LOG_DIR", str(Path.home() / ".swarm-logs"))).expanduser()


def state_dir() -> Path:
    path = Path(os.environ.get("SWARM_STATE_DIR", str(Path.home() / ".swarm-state"))).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def vendor_command(
    meta: dict, prompt: str, cwd: Path, *, resume_id: str = "", settings: Path | None = None,
    usage_file: Path | None = None,
) -> list[str]:
    vendor, model, effort = meta["vendor"], meta["model"], meta.get("effort", "")
    if vendor == "claude":
        command = ["claude", "-p", prompt, "--model", model, "--permission-mode", "bypassPermissions",
                   "--output-format", "json"]
        if settings is not None:
            command += ["--settings", str(settings)]
        if resume_id:
            command += ["--resume", resume_id]
        return command
    if vendor == "codex":
        command = ["codex", "exec", "--json", "-m", model, "--sandbox", "danger-full-access",
                   "--skip-git-repo-check", "-C", str(cwd)]
        if effort:
            command += ["-c", f"model_reasoning_effort={effort}"]
        if resume_id:
            command += ["resume", resume_id]
        return command + [prompt]
    if vendor == "cursor":
        return ["cursor-agent", "-p", prompt, "--model", model, "--force", "--output-format", "text",
                "--workspace", str(cwd)]
    if vendor == "hermes":
        command = ["hermes", "-z", prompt, "-m", model, "--provider", "openrouter", "--in", str(cwd), "--yolo"]
        if usage_file is not None:
            command += ["--usage-file", str(usage_file)]
        return command
    raise SwarmError(f"unknown vendor {vendor!r}")


def session_id_from(vendor: str, output: str) -> str:
    for line in reversed(output.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        found = event.get("session_id") or event.get("thread_id")
        if vendor == "codex" and not found and isinstance(event.get("msg"), dict):
            found = event["msg"].get("session_id")
        if found:
            return str(found)
    return ""


def rate_limited(result: Execution) -> bool:
    return result.returncode != 0 and bool(RATE_LIMIT_RE.search(result.output[-2000:]))


def render(template: Path, **fields: str) -> str:
    try:
        return template.read_text().format_map(fields)
    except KeyError as err:
        raise SwarmError(f"{template.name} needs field {err}") from err


def throttle(store: Store) -> str:
    until = clock.fmt(clock.now() + clock.minutes(THROTTLE_MINUTES))
    claims.heartbeat(store, status="throttled", throttled_until=until)
    return "throttled"


@dataclass
class Context:
    store: Store
    meta: dict
    executor: Executor = execute
    make_worktree: Callable[[str, bool], Path] | None = None
    waiter: Callable[..., list[str]] = lifecycle.wait
    runner: ci.Runner = ci.default_runner
    prompts_dir: Path | None = None
    janitor_clock: dict = field(default_factory=dict)

    @property
    def prompts(self) -> Path:
        return self.prompts_dir or self.store.path("prompts")

    @property
    def settings(self) -> Path:
        return self.store.path("agent-config", "claude-settings.json")

    @property
    def logs(self) -> Path:
        return logs_root() / self.meta["id"]

    def worktree_for(self, item_id: str, review: bool = False) -> Path:
        if self.make_worktree is not None:
            return self.make_worktree(item_id, review)
        return worktree.create(
            self.store, item_id,
            repo=Path(os.environ.get("SWARM_REPO", "~/backbay/arc")).expanduser(),
            lanes=Path(os.environ.get("SWARM_LANES", "~/lanes/swarm")).expanduser(),
            base_branch=self.store.config()["base_branch"], review=review,
        )


def worker_iteration(ctx: Context) -> str:
    store, meta = ctx.store, ctx.meta
    picked = lifecycle.next_item(store, meta.get("tiers") or ["mid"])
    if not picked:
        return "idle"
    lane = ctx.worktree_for(picked)
    store.sync()
    item = items.load(store, picked)
    if item.status == "claimed":
        lifecycle.status(store, picked, "in-progress", "work started")
    prompt = render(
        ctx.prompts / f"{meta['role']}.md", agent=meta["id"], role=meta["role"], item_id=picked,
        worktree=str(lane), branch=worktree.lane_branch(item), base=store.config()["base_branch"],
        paths=", ".join(item.meta["paths"]) or "none listed", brief=lifecycle.brief(store, picked),
    )
    log = ctx.logs / f"{picked}-{clock.stamp()}.log"
    result = ctx.executor(vendor_command(meta, prompt, lane, settings=ctx.settings), lane, log)
    if rate_limited(result):
        return throttle(store)
    store.sync()
    after = items.load(store, picked)
    if after.status == "in-progress" and after.meta["owner"] == meta["id"]:
        lifecycle.status(store, picked, "blocked", f"agent exited ({result.returncode}) without submitting; log {log}")
        return "blocked"
    return "done"


def reviewer_iteration(ctx: Context) -> str:
    store, meta = ctx.store, ctx.meta
    picked = lifecycle.next_review(store)
    if not picked:
        return "idle"
    view = ctx.worktree_for(picked, True)
    store.sync()
    item = items.load(store, picked)
    prompt = render(
        ctx.prompts / "reviewer.md", agent=meta["id"], item_id=picked, worktree=str(view),
        branch=item.meta["branch"], base=store.config()["base_branch"], brief=lifecycle.brief(store, picked),
    )
    log = ctx.logs / f"review-{picked}-{clock.stamp()}.log"
    result = ctx.executor(vendor_command(meta, prompt, view, settings=ctx.settings), view, log)
    if rate_limited(result):
        return throttle(store)
    store.sync()
    after = items.load(store, picked)
    if after.status == "review" and after.meta["review"]["reviewer"] == meta["id"]:
        def mutate() -> bool:
            fresh = items.load(store, picked)
            if fresh.status != "review" or fresh.meta["review"]["reviewer"] != meta["id"]:
                return False
            fresh.meta["review"]["reviewer"] = ""
            fresh.log(store.agent, f"released review without a verdict (exit {result.returncode}); log {log}")
            items.save(store, fresh)
            msgs.write(store, "conductor", "blocker", picked, f"review of {picked} ended without a verdict", str(log))
            return True

        store.transact(f"unreview {picked}", mutate)
        return "no-verdict"
    return "done"


def _lead_janitor(store: Store) -> str:
    janitors = sorted(a["id"] for a in agents.all_agents(store) if a["role"] == "janitor" and a["status"] == "active")
    return janitors[0] if janitors else ""


def janitor_iteration(ctx: Context) -> list[str]:
    store, meta, done = ctx.store, ctx.meta, []
    now = time.monotonic()
    if now - ctx.janitor_clock.get("board", -1e9) >= 600:
        lifecycle.sweep(store)
        board.write(store)
        ctx.janitor_clock["board"] = now
        done.append("board")
    pr = store.config()["train_pr"]
    if pr and now - ctx.janitor_clock.get("reviews", -1e9) >= 3600:
        reviews.import_reviews(store, ctx.runner, int(pr))
        ctx.janitor_clock["reviews"] = now
        done.append("reviews")
    lead = _lead_janitor(store) == meta["id"]
    for message in msgs.inbox(store):
        if message["kind"] != "request" or (message["to"] != meta["id"] and not lead):
            continue
        cwd = Path(os.environ.get("SWARM_REPO", "~/backbay/arc")).expanduser()
        prompt = render(ctx.prompts / "janitor.md", agent=meta["id"], sender=message["from"],
                        subject=message["subject"], item_id=message["item"] or "-", request=message["body"])
        stamp = clock.stamp()
        result = ctx.executor(
            vendor_command(meta, prompt, cwd, usage_file=ctx.logs / f"usage-{stamp}.json"), cwd,
            ctx.logs / f"request-{stamp}.log",
        )
        reply = result.output[-REPLY_LIMIT:].strip() or f"(no output, exit {result.returncode})"
        msgs.send(store, message["from"], "fyi", message["item"], f"re: {message['subject']}", reply)
        done.append(f"answered {message['key']}")
    return done


def session_iteration(ctx: Context, *, wait_timeout: float = 1200) -> str:
    store, meta = ctx.store, ctx.meta
    events = ctx.waiter(store, timeout=wait_timeout)
    sid_path = state_dir() / f"{meta['id']}.session"
    sid = sid_path.read_text().strip() if sid_path.exists() else ""
    if sid:
        prompt = render(ctx.prompts / "event.md", events="\n".join(f"- {e}" for e in events) or "- periodic check, no new events")
    else:
        prompt = render(ctx.prompts / f"{meta['role']}.md", agent=meta["id"], base=store.config()["base_branch"])
    cwd = Path(os.environ.get("SWARM_SESSION_DIR", str(store.root))).expanduser()
    result = ctx.executor(
        vendor_command(meta, prompt, cwd, resume_id=sid, settings=ctx.settings), cwd,
        ctx.logs / f"session-{clock.stamp()}.log",
    )
    if rate_limited(result):
        return throttle(store)
    new_sid = session_id_from(meta["vendor"], result.output)
    if new_sid:
        sid_path.write_text(new_sid)
    elif sid and result.returncode != 0:
        sid_path.unlink(missing_ok=True)  # resume failed: start fresh from the charter next turn
    msgs.inbox(store, mark=True)  # the turn saw these events; do not replay them
    claims.heartbeat(store)
    return "turn" if result.returncode == 0 else "failed"


def tmux_has(session: str) -> bool:
    return subprocess.run(["tmux", "has-session", "-t", session], capture_output=True).returncode == 0


def launch(store: Store, agent_id: str) -> None:
    meta = agents.load(store, agent_id)
    if meta is None:
        raise SwarmError(f"{agent_id} is not registered")
    env_file = Path(os.environ.get("SWARM_ENV_FILE", "~/.swarm/env")).expanduser()
    agent_env = env_file.parent / "agents" / f"{agent_id}.env"  # optional per-agent overrides
    exports = " ".join(f"{k}={shlex.quote(v)}" for k, v in
                       (("SWARM_AGENT", agent_id), ("SWARM_ROLE", meta["role"]), ("SWARM_VENDOR", meta["vendor"])))
    inner = (
        f"set -a; . {shlex.quote(str(env_file))}; "
        f"if [ -f {shlex.quote(str(agent_env))} ]; then . {shlex.quote(str(agent_env))}; fi; set +a; "
        f"export {exports}; exec swarm-agent run {shlex.quote(agent_id)}"
    )
    subprocess.run(["tmux", "new-session", "-d", "-s", f"swarm-{agent_id}", "bash", "-lc", inner], check=True)


def watchdog_iteration(
    store: Store, machine: str, notified: dict, *, has: Callable[[str], bool] = tmux_has,
    start: Callable[[Store, str], None] = launch,
) -> list[str]:
    store.sync()
    actions = []
    for meta in agents.all_agents(store):
        if meta["machine"] != machine or meta["status"] == "stopped":
            continue
        if not has(f"swarm-{meta['id']}"):
            start(store, meta["id"])
            actions.append(f"launched {meta['id']}")
        elif agents.is_stale(meta) and time.monotonic() - notified.get(meta["id"], -1e9) > 3600:
            msgs.send(store, meta["id"], "fyi", "", "heartbeat stale",
                      "Your runner is alive but has not checked in for 30+ minutes. Finish or block your item.")
            msgs.send(store, "conductor", "blocker", "", f"{meta['id']} silent",
                      f"{meta['id']} on {machine}: tmux session alive, heartbeat {meta['last_heartbeat']}.")
            notified[meta["id"]] = time.monotonic()
            actions.append(f"flagged {meta['id']}")
    return actions


def run(agent_id: str) -> int:
    store = Store.from_env()
    if store.agent != agent_id:
        raise SwarmError(f"SWARM_AGENT is {store.agent!r}; expected {agent_id!r}")
    store.hooks.append(lambda: claims.renew_mine(store))
    ctx: Context | None = None
    failures = 0
    while True:
        try:
            store.sync()
            if store.halt_reason() is not None:
                time.sleep(60)
                continue
            meta = agents.load(store, agent_id)
            if meta is None:
                raise SwarmError(f"{agent_id} is not registered")
            if meta["status"] == "stopped":
                time.sleep(300)
                continue
            until = meta.get("throttled_until")
            if until and clock.parse(until) > clock.now():
                time.sleep(300)
                continue
            if meta["status"] == "throttled":
                claims.heartbeat(store, status="active", throttled_until="")
            if ctx is None:
                ctx = Context(store=store, meta=meta)
            ctx.meta = meta
            role = meta["role"]
            if role in ITEM_ROLES:
                outcome = worker_iteration(ctx)
            elif role == "reviewer":
                outcome = reviewer_iteration(ctx)
            elif role == "janitor":
                outcome = "busy" if janitor_iteration(ctx) else "idle"
            elif role in SESSION_ROLES:
                outcome = session_iteration(ctx)
            else:
                raise SwarmError(f"swarm-agent does not run role {role!r}")
            print(f"{clock.fmt(clock.now())} {agent_id}: {outcome}", flush=True)
            if outcome == "idle":
                lifecycle.wait(store, timeout=60 if role == "janitor" else 540)
            elif outcome == "failed":
                failures += 1
                time.sleep(min(30 * 2 ** failures, 1800))
                continue
            failures = 0
        except Halted:
            time.sleep(60)
        except (SwarmError, gitio.GitError, ci.CIError, OSError) as err:
            failures += 1
            print(f"{clock.fmt(clock.now())} {agent_id}: error: {err}", file=sys.stderr, flush=True)
            time.sleep(min(30 * 2 ** failures, 1800))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="swarm-agent")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("run", "launch", "stop"):
        sub.add_parser(name).add_argument("agent")
    watch = sub.add_parser("watchdog")
    watch.add_argument("--machine", default=os.environ.get("SWARM_MACHINE", socket.gethostname().split(".")[0]))
    watch.add_argument("--interval", type=float, default=120)
    args = p.parse_args(argv)
    store = Store.from_env()
    try:
        if args.command == "run":
            return run(args.agent)
        if args.command == "launch":
            store.sync()
            launch(store, args.agent)
            return 0
        if args.command == "stop":
            return subprocess.run(["tmux", "kill-session", "-t", f"swarm-{args.agent}"]).returncode
        notified: dict = {}
        while True:
            for action in watchdog_iteration(store, args.machine, notified):
                print(f"{clock.fmt(clock.now())} watchdog: {action}", flush=True)
            time.sleep(args.interval)
    except (SwarmError, gitio.GitError) as err:
        print(f"swarm-agent: {err}", file=sys.stderr)
        return 2
