"""Read-only live view of every machine in the swarm: hosts, build slots, agent sessions and the store.

Each host answers `swarm watch --snapshot` with JSON built from what is already on disk (Claude Code
transcripts, Codex rollouts, the build scheduler's slot records, mailbox files) and `ps`. The viewer
gathers those over ssh and renders them. Nothing here writes anywhere.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from . import build, claims, clock, frontmatter, items, secrets
from .store import Store

VENDORS = ("claude", "codex", "cursor-agent", "hermes")
TAIL_BYTES = 262_144
ACTION_CHARS = 160
ENCRYPTED = re.compile(r"^gAAAA[A-Za-z0-9_-]{20,}")
EXEC_CMD = re.compile(r'cmd:\s*"((?:[^"\\]|\\.)*)"')
ETIME = re.compile(r"^(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)$")
ZOOM_ACTIONS = 20

Runner = Callable[[list[str], float], subprocess.CompletedProcess]


@dataclass
class Session:
    vendor: str
    id: str
    label: str = ""
    cwd: str = ""
    model: str = ""
    parent: str = ""
    age_s: float = 0.0
    note: str = ""
    actions: list[str] = field(default_factory=list)


def tail_lines(path: Path, max_bytes: int = TAIL_BYTES) -> list[str]:
    """Complete lines from the last `max_bytes` of a file (transcripts can be hundreds of MB)."""
    size = path.stat().st_size
    with open(path, "rb") as handle:
        handle.seek(max(0, size - max_bytes))
        data = handle.read()
    lines = data.decode("utf-8", errors="replace").split("\n")
    if size > max_bytes:
        lines = lines[1:]  # the first piece is the tail end of a line we did not read
    return [line for line in lines if line.strip()]


def _records(lines: list[str]) -> list[dict]:
    found = []
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            found.append(record)
    return found


def _first_line(text: str) -> str:
    return next((line.strip() for line in str(text).splitlines() if line.strip()), "")


def _hhmm(stamp: str) -> str:
    match = re.search(r"T(\d\d:\d\d)", stamp or "")
    return match.group(1) if match else "--:--"


def _action(stamp: str, text: str) -> str:
    return f"{_hhmm(stamp)} {text}"[:ACTION_CHARS]


def _tool_summary(name: str, params: dict) -> str:
    for key in ("description", "file_path", "pattern", "url", "query", "skill", "command", "prompt"):
        value = params.get(key)
        if isinstance(value, str) and value.strip():
            return _first_line(value)
    value = next((v for v in params.values() if isinstance(v, str) and v.strip()), "")
    return _first_line(value)


def claude_session(path: Path, keep: int) -> Session | None:
    records = _records(tail_lines(path))
    if not records:
        return None
    sub = path.parent.name == "subagents"
    session = Session("claude", path.stem.removeprefix("agent-") if sub else path.stem)
    if sub:
        session.parent = path.parent.parent.name
        meta = path.with_name(f"{path.stem}.meta.json")
        if meta.exists():
            try:
                info = json.loads(meta.read_text())
                session.label, session.model = info.get("description", ""), info.get("model", "")
            except json.JSONDecodeError:
                pass
    actions = []
    for record in records:
        kind = record.get("type")
        session.cwd = record.get("cwd") or session.cwd
        if kind == "ai-title" and not sub:
            session.label = record.get("aiTitle") or session.label
        elif kind == "system" and "pendingBackgroundAgentCount" in record:
            count = record["pendingBackgroundAgentCount"]
            session.note = f"{count} background agents" if count else ""
        elif kind == "assistant":
            message = record.get("message") or {}
            if not sub or not session.model:
                session.model = message.get("model") or session.model
            for block in message.get("content") or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    summary = _tool_summary(block.get("name", ""), block.get("input") or {})
                    actions.append(_action(record.get("timestamp", ""), f"{block.get('name')}: {summary}"))
                elif block.get("type") == "text" and _first_line(block.get("text", "")):
                    actions.append(_action(record.get("timestamp", ""), f"says: {_first_line(block['text'])}"))
    session.label = session.label or session.id
    session.actions = actions[-keep:]
    return session


def _codex_call(payload: dict) -> str:
    name = payload.get("name", "")
    if payload.get("type") == "custom_tool_call":
        raw = payload.get("input", "")
        match = EXEC_CMD.search(raw)
        text = json.loads(f'"{match.group(1)}"') if match else raw
        return f"{name}: {_first_line(text)}"
    try:
        params = json.loads(payload.get("arguments") or "{}")
    except json.JSONDecodeError:
        params = {}
    if not isinstance(params, dict):
        return name
    if "target" in params:
        message = str(params.get("message", ""))
        shown = "(encrypted)" if ENCRYPTED.match(message) else _first_line(message)
        return f"{name} -> {params['target']}: {shown}"
    command = params.get("cmd") or params.get("command")
    if isinstance(command, list):
        command = " ".join(shlex.quote(part) for part in command)
    return f"{name}: {_first_line(command) if command else _tool_summary(name, params)}"


def _content_text(content) -> str:
    parts = [c for c in content or [] if isinstance(c, dict)]
    texts = [c.get("text", "") for c in parts]
    if any(c.get("type") == "encrypted_content" for c in parts):  # Codex inter-agent payloads: only the header is plain
        match = re.search(r"^Message Type:\s*(\S+)", "\n".join(texts), re.M)
        return f"{match.group(1).replace('_', ' ').lower() if match else 'message'} (encrypted)"
    text = _first_line(" ".join(texts))
    return "(encrypted)" if ENCRYPTED.match(text) else text


def codex_session(path: Path, keep: int) -> Session | None:
    with open(path, "rb") as handle:
        head = _records([handle.readline().decode("utf-8", errors="replace")])
    meta = head[0].get("payload", {}) if head and head[0].get("type") == "session_meta" else {}
    session = Session("codex", meta.get("id") or path.stem, cwd=meta.get("cwd", ""),
                      parent=meta.get("parent_thread_id", ""))
    nickname, agent_path = meta.get("agent_nickname", ""), meta.get("agent_path", "")
    session.label = " ".join(part for part in (nickname, agent_path) if part) or "root"
    actions = []
    for record in _records(tail_lines(path)):
        payload, at = record.get("payload") or {}, record.get("timestamp", "")
        kind, sub = record.get("type"), payload.get("type")
        if kind == "turn_context":
            session.model, session.cwd = payload.get("model") or session.model, payload.get("cwd") or session.cwd
        elif kind == "response_item" and sub in ("function_call", "custom_tool_call"):
            actions.append(_action(at, _codex_call(payload)))
        elif kind == "response_item" and sub == "agent_message":
            actions.append(_action(at, f"{payload.get('author')} -> {payload.get('recipient')}: "
                                       f"{_content_text(payload.get('content'))}"))
        elif kind == "response_item" and sub == "message" and payload.get("role") == "assistant":
            actions.append(_action(at, f"says: {_content_text(payload.get('content'))}"))
        elif kind == "event_msg" and sub == "task_complete":
            actions.append(_action(at, f"turn done: {_first_line(payload.get('last_agent_message') or '')}".rstrip(": ")))
        elif kind == "event_msg" and sub == "token_count":
            primary = ((payload.get("rate_limits") or {}).get("primary")) or {}
            if "used_percent" in primary:
                session.note = f"rate limit {primary['used_percent']:.0f}% of {primary.get('window_minutes', '?')}m"
    session.actions = actions[-keep:]
    return session


def _transcripts(home: Path) -> list[tuple[str, Path]]:
    found = []
    projects = home / ".claude" / "projects"
    if projects.is_dir():
        found += [("claude", p) for p in projects.glob("*/*.jsonl")]
        found += [("claude", p) for p in projects.glob("*/*/subagents/*.jsonl")]
    sessions = home / ".codex" / "sessions"
    if sessions.is_dir():
        for folder, _dirs, files in os.walk(sessions):
            found += [("codex", Path(folder) / name) for name in files if name.endswith(".jsonl")]
    return found


def recent_sessions(home: Path, *, minutes: float, keep: int) -> list[Session]:
    """Sessions whose transcript changed in the last `minutes`, most recent first."""
    now = time.time()
    fresh = []
    for vendor, path in _transcripts(home):
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if now - mtime <= minutes * 60:
            fresh.append((mtime, vendor, path))
    sessions = []
    for mtime, vendor, path in sorted(fresh, reverse=True):
        try:
            session = (claude_session if vendor == "claude" else codex_session)(path, keep)
        except OSError:
            continue
        if session:
            session.age_s = round(now - mtime, 1)
            sessions.append(session)
    return sessions


def _seconds(etime: str) -> int:
    match = ETIME.match(etime.strip())
    if not match:
        return 0
    days, hours, mins, secs = (int(g or 0) for g in match.groups())
    return ((days * 24 + hours) * 60 + mins) * 60 + secs


def parse_ps(text: str) -> list[dict]:
    """Agent CLI processes from `ps ax -o pid=,etime=,args=` output."""
    found = []
    for line in text.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        argv = parts[2].split()
        names = [os.path.basename(argv[0])] + ([os.path.basename(argv[1])] if len(argv) > 1 and
                                                os.path.basename(argv[0]) == "node" else [])
        vendor = next((name for name in names if name in VENDORS), "")
        if vendor:
            found.append({"vendor": vendor, "pid": int(parts[0]), "elapsed_s": _seconds(parts[1]),
                          "args": parts[2][:ACTION_CHARS]})
    return found


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _age(started: str) -> float:
    try:
        return max(0.0, (clock.now() - clock.parse(started)).total_seconds())
    except (TypeError, ValueError):
        return 0.0


def slot_status(folder: Path) -> dict:
    """Who holds each build slot and who is queued, from the scheduler's records (live processes only)."""
    status = {"count": build.slot_count(), "jobs": int(build.setting("SWARM_BUILD_JOBS", "5")),
              "holders": [], "waiting": []}
    if not folder.is_dir():
        return status
    for path in sorted(folder.glob("slot-*.lock")):
        try:
            record = json.loads(path.read_text() or "null")
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(record, dict) and _alive(int(record.get("pid", 0))):
            slot = int(path.stem.split("-", 1)[1])
            status["holders"].append({**record, "slot": slot, "age_s": _age(record.get("started", ""))})
    for path in sorted(folder.glob("wait-*.json")):
        try:
            record = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(record, dict) and _alive(int(record.get("pid", 0))):
            status["waiting"].append({**record, "age_s": _age(record.get("started", ""))})
    status["holders"].sort(key=lambda h: h["slot"])
    return status


def mailboxes(paths: list[Path], keep: int = 2) -> list[dict]:
    """The latest `## ` entries of markdown mailbox files, heading plus first line."""
    boxes = []
    for path in paths:
        if not path.is_file():
            continue
        lines = tail_lines(path, 65_536)
        entries = []
        for index, line in enumerate(lines):
            if line.startswith("## "):
                first = next((l.strip() for l in lines[index + 1:] if l.strip() and not l.startswith("## ")), "")
                entries.append(f"{line[3:].strip()}: {first}"[:ACTION_CHARS])
        boxes.append({"file": path.name, "entries": entries[-keep:]})
    return boxes


def host_stats(home: Path) -> dict:
    stats: dict = {"cpus": os.cpu_count(), "load": [round(x, 1) for x in os.getloadavg()],
                   "disk_free_gb": round(shutil.disk_usage(home).free / 2**30, 1), "mem_free_gb": None}
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        match = re.search(r"^MemAvailable:\s+(\d+) kB", meminfo.read_text(), re.M)
        if match:
            stats["mem_free_gb"] = round(int(match.group(1)) / 2**20, 1)
    return stats


def _run_text(command: list[str]) -> str:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def snapshot(*, home: Path, minutes: float, keep: int) -> dict:
    boxes = [Path(p).expanduser() for p in os.environ.get("SWARM_WATCH_MAILBOXES", "").split(":") if p]
    tmux = [name for name in _run_text(["tmux", "ls", "-F", "#S"]).split() if name.startswith("swarm-")]
    data = {
        "host": "local", "hostname": socket.gethostname(), "taken": clock.fmt(clock.now()),
        "stats": host_stats(home), "slots": slot_status(build.slot_dir(create=False)),
        "processes": parse_ps(_run_text(["ps", "ax", "-o", "pid=,etime=,args="])),
        "tmux": tmux, "mailboxes": mailboxes(boxes),
        "sessions": [asdict(s) for s in recent_sessions(home, minutes=minutes, keep=keep)],
    }
    return secrets.redact_obj(data)


def remote_snapshot_command(host: str, *, minutes: float, keep: int) -> list[str]:
    script = (f"set -a; . ~/.swarm/env; set +a; exec ~/.local/bin/swarm watch --snapshot "
              f"--minutes {minutes:g} --keep {keep}")
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", host, script]


def _ssh(command: list[str], timeout: float) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", f"no answer within {timeout:.0f}s")


def gather(hosts: list[str], *, local: Callable[[], dict], runner: Runner = _ssh, minutes: float, keep: int,
           timeout: float = 20) -> list[dict]:
    """One snapshot per host, in parallel; an unreachable host yields {"host", "error"}."""

    def one(host: str) -> dict:
        if host == "local":
            return {**local(), "host": "local"}
        proc = runner(remote_snapshot_command(host, minutes=minutes, keep=keep), timeout)
        if proc.returncode != 0:
            return {"host": host, "error": _first_line(proc.stderr) or f"exit {proc.returncode}"}
        try:
            return {**json.loads(proc.stdout), "host": host}
        except json.JSONDecodeError:
            return {"host": host, "error": "snapshot was not JSON (is swarm current there?)"}

    with ThreadPoolExecutor(max_workers=max(1, len(hosts))) as pool:
        return list(pool.map(one, hosts))


def store_summary(store: Store) -> dict:
    store.sync()
    everything, _ = items.all_items(store)
    counts: dict[str, int] = {}
    for item in everything:
        if item.status not in items.CLOSED:
            counts[item.status] = counts.get(item.status, 0) + 1
    leases = [{"item": c["item"], "owner": c["agent"], "age_s": _age(c.get("acquired", ""))}
              for c in claims.active(store, clock.now())]
    sent = []
    for path in store.path("msgs").glob("*/*.md"):
        try:
            meta, _body = frontmatter.parse(path.read_text())
        except (OSError, ValueError):
            continue
        sent.append({"from": meta.get("from", ""), "to": meta.get("to", ""), "subject": meta.get("subject", ""),
                     "sent": meta.get("sent", ""), "age_s": _age(meta.get("sent", ""))})
    sent.sort(key=lambda m: m["sent"], reverse=True)
    return {"items": dict(sorted(counts.items())), "claims": leases, "messages": sent[:6]}


def ago(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h{seconds % 3600 // 60:02d}m"
    return f"{seconds // 86400}d{seconds % 86400 // 3600}h"


def _matches(session: dict, agent: str) -> bool:
    haystack = " ".join(str(session.get(k, "")) for k in ("vendor", "id", "label", "cwd", "model")).lower()
    return agent.lower() in haystack


def _session_lines(session: dict, indent: str, actions: int, *, child: bool = False) -> list[str]:
    head = "  ".join(part for part in ("sub" if child else session["vendor"], session["label"],
                                        session.get("model", ""), f"{ago(session['age_s'])} ago",
                                        session.get("note", "")) if part)
    return [f"{indent}{head}"] + [f"{indent}    {line}" for line in session.get("actions", [])[-actions:]]


def _host_lines(snap: dict, *, agent: str, actions: int) -> list[str]:
    if "error" in snap:
        return [f"== {snap['host']}  unreachable: {snap['error']}"]
    stats = snap.get("stats", {})
    load = (stats.get("load") or ["?"])[0]
    mem = f"  mem {stats['mem_free_gb']:.0f} GB free" if stats.get("mem_free_gb") is not None else ""
    lines = [f"== {snap['host']} ({snap.get('hostname', '?')})  load {load}/{stats.get('cpus', '?')}{mem}"
             f"  disk {stats.get('disk_free_gb', 0):.0f} GB free"]
    slots = snap.get("slots", {})
    if not agent:
        busy = slots.get("holders", [])
        lines.append(f"builds  {len(busy)}/{slots.get('count', '?')} slots busy x {slots.get('jobs', '?')} jobs"
                     f"  queue {len(slots.get('waiting', []))}")
        for holder in busy:  # builds started over ssh carry no agent or item; their directory names the lane
            what = holder.get("item") or os.path.basename(str(holder.get("cwd", "")).rstrip("/")) or "-"
            lines.append(f"  slot {holder['slot']}  {holder.get('class', '')}  {holder.get('agent', '') or '-'}  "
                         f"{what}  {ago(holder.get('age_s', 0))}  {holder.get('command', '')}")
        for waiter in slots.get("waiting", []):
            lines.append(f"  queued  {waiter.get('class', '')}  {waiter.get('agent', '') or '-'}  "
                         f"{waiter.get('item', '') or '-'}  {ago(waiter.get('age_s', 0))}  {waiter.get('command', '')}")
        counts: dict[str, int] = {}
        for proc in snap.get("processes", []):
            counts[proc["vendor"]] = counts.get(proc["vendor"], 0) + 1
        procs = ", ".join(f"{vendor} {count}" for vendor, count in sorted(counts.items())) or "none"
        tmux = f"  swarm-agent sessions: {', '.join(snap['tmux'])}" if snap.get("tmux") else ""
        lines.append(f"procs   {procs}{tmux}")
        for box in snap.get("mailboxes", []):
            lines += [f"mail    {box['file']}  {entry}" for entry in box["entries"]]
    sessions = snap.get("sessions", [])
    shown = [s for s in sessions if _matches(s, agent)] if agent else sessions
    ids = {s["id"] for s in shown}
    children: dict[str, list[dict]] = {}
    for session in shown:
        if session.get("parent") in ids:
            children.setdefault(session["parent"], []).append(session)
    lines.append(f"sessions ({len(shown)} active)")
    for session in shown:
        if session.get("parent") in ids:
            continue
        lines += _session_lines(session, "  ", actions)
        for child in children.get(session["id"], []):
            lines += _session_lines(child, "      ", min(actions, 2) if not agent else actions, child=True)
    return lines


def render(snapshots: list[dict], summary: dict | None, *, now: datetime, width: int, agent: str = "",
           actions: int = 3, minutes: float = 30) -> str:
    actions = ZOOM_ACTIONS if agent else actions
    scope = f"  zoom: {agent}" if agent else ""
    lines = [f"swarm watch  {clock.fmt(now)}  sessions active in the last {minutes:g}m{scope}"]
    for snap in snapshots:
        lines.append("")
        lines += _host_lines(snap, agent=agent, actions=actions)
    if summary is not None and not agent:
        lines += ["", "== swarm store",
                  "items  " + (", ".join(f"{k} {v}" for k, v in summary["items"].items()) or "none open")]
        if summary["claims"]:
            lines.append("claims " + "; ".join(f"{c['item']} {c['owner']} {ago(c['age_s'])}" for c in summary["claims"]))
        lines += [f"msg    {m['from']} -> {m['to']}: {m['subject']} ({ago(m['age_s'])} ago)" for m in summary["messages"]]
    return "\n".join(secrets.redact(line)[:width] for line in lines)
