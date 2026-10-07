"""Build slots: bounded, low-priority, cached cargo runs on the shared hosts."""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from . import clock


def slot_dir() -> Path:
    path = Path(os.environ.get("SWARM_BUILD_DIR", str(Path.home() / ".swarm-build"))).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def slot_count() -> int:
    return max(1, int(os.environ.get("SWARM_BUILD_SLOTS", "2")))


def acquire(count: int, *, poll: float = 5.0, timeout: float | None = None) -> tuple[int, int, float]:
    """Block until one of `count` slots is free. Returns (fd, slot, seconds waited)."""
    started = time.monotonic()
    while True:
        for slot in range(count):
            fd = os.open(slot_dir() / f"slot-{slot}.lock", os.O_RDWR | os.O_CREAT, 0o644)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd, slot, time.monotonic() - started
            except BlockingIOError:
                os.close(fd)
        if timeout is not None and time.monotonic() - started >= timeout:
            raise TimeoutError(f"no build slot free after {timeout:.0f}s")
        time.sleep(poll)


def release(fd: int) -> None:
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def scope_prefix() -> list[str]:
    """systemd user scope with low CPU weight and a memory ceiling, when available."""
    if os.environ.get("SWARM_BUILD_CGROUP", "1") == "0" or not shutil.which("systemd-run"):
        return []
    return [
        "systemd-run", "--user", "--scope", "--quiet",
        "-p", f"CPUWeight={os.environ.get('SWARM_BUILD_CPU_WEIGHT', '20')}",
        "-p", f"MemoryMax={os.environ.get('SWARM_BUILD_MEMORY_MAX', '14G')}",
        "--",
    ]


def build_env(base: dict[str, str]) -> dict[str, str]:
    env = dict(base)
    if shutil.which("sccache"):
        env.setdefault("RUSTC_WRAPPER", "sccache")
        env.setdefault("SCCACHE_CACHE_SIZE", "60G")
    env["CARGO_INCREMENTAL"] = "0"
    return env


def record_wait(slot: int, waited: float, item: str) -> None:
    with open(slot_dir() / "waits.log", "a") as log:
        log.write(json.dumps({"at": clock.fmt(clock.now()), "slot": slot, "waited_s": round(waited, 1), "item": item}) + "\n")


def run(command: list[str], *, item: str = "") -> int:
    if not command:
        raise ValueError("swarm build needs a command after --")
    fd, slot, waited = acquire(slot_count())
    record_wait(slot, waited, item)
    try:
        return subprocess.call(scope_prefix() + command, env=build_env(dict(os.environ)))
    finally:
        release(fd)
