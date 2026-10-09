"""Build scheduler: bounded, prioritized, low-impact cargo runs on shared hosts.

Slot 0 is reserved for the integrator class so integration never queues behind
coder checks. Every slot caps cargo's job count, coder builds run at a low CPU
weight, and nothing starts below the disk floor.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import clock

CLASSES = ("integrator", "coder")
INTEGRATOR_ROLES = ("integrator", "conductor", "security")
CARGO_TAG = "Signature: 8a477f597d28d172789f06886806bc55"
PRUNABLE = ("deps", "build", ".fingerprint", "incremental")


class BuildRefused(RuntimeError):
    """The scheduler will not start (or prune) this build; the message says why."""


def host_settings() -> dict[str, str]:
    """KEY=VALUE defaults from ~/.swarm/build.env (or $SWARM_BUILD_ENV); the environment wins."""
    path = Path(os.environ.get("SWARM_BUILD_ENV", str(Path.home() / ".swarm" / "build.env"))).expanduser()
    if not path.is_file():
        return {}
    pairs = (line.split("=", 1) for line in path.read_text().splitlines() if "=" in line and not line.lstrip().startswith("#"))
    return {key.strip(): value.strip() for key, value in pairs}


def setting(name: str, default: str) -> str:
    return os.environ.get(name) or host_settings().get(name) or default


def slot_dir() -> Path:
    path = Path(os.environ.get("SWARM_BUILD_DIR", str(Path.home() / ".swarm-build"))).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def slot_count() -> int:
    return max(1, int(setting("SWARM_BUILD_SLOTS", "2")))


def class_for_role(role: str) -> str:
    return "integrator" if role in INTEGRATOR_ROLES else "coder"


def slots_for(build_class: str, count: int) -> list[int]:
    """Integrators may use any slot; coders never take slot 0 when there is more than one."""
    if build_class == "integrator" or count == 1:
        return list(range(count))
    return list(range(1, count))


def acquire(slots: int | list[int], *, poll: float = 5.0, timeout: float | None = None) -> tuple[int, int, float]:
    """Block until one of `slots` is free. Returns (fd, slot, seconds waited)."""
    candidates = list(range(slots)) if isinstance(slots, int) else list(slots)
    started = time.monotonic()
    while True:
        for slot in candidates:
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


def scope_prefix(build_class: str = "coder") -> list[str]:
    """systemd user scope with a class CPU weight and a memory ceiling, when available."""
    if setting("SWARM_BUILD_CGROUP", "1") == "0" or not shutil.which("systemd-run"):
        return []
    default_weight = "100" if build_class == "integrator" else "20"
    weight = setting(f"SWARM_BUILD_CPU_WEIGHT_{build_class.upper()}", default_weight)
    return [
        "systemd-run", "--user", "--scope", "--quiet",
        "-p", f"CPUWeight={weight}",
        "-p", f"MemoryMax={setting('SWARM_BUILD_MEMORY_MAX', '14G')}",
        "--",
    ]


CREDENTIAL = re.compile(r"TOKEN|SECRET|API_KEY|PASSWORD", re.I)


def build_env(base: dict[str, str]) -> dict[str, str]:
    """Build settings, without credentials: dependency build scripts and proc macros run in this environment."""
    env = {key: value for key, value in base.items() if not CREDENTIAL.search(key)}
    if setting("SWARM_SCCACHE", "1") != "0" and shutil.which("sccache"):
        env.setdefault("RUSTC_WRAPPER", "sccache")
        env.setdefault("SCCACHE_CACHE_SIZE", "60G")
    env["CARGO_INCREMENTAL"] = "0"
    cap = int(setting("SWARM_BUILD_JOBS", "5"))
    requested = int(env.get("CARGO_BUILD_JOBS") or cap)
    env["CARGO_BUILD_JOBS"] = str(max(1, min(requested, cap)))
    return env


def check_disk(path: Path) -> None:
    floor = float(setting("SWARM_BUILD_DISK_FLOOR_GB", "25"))
    free = shutil.disk_usage(path).free / 2**30
    if free < floor:
        raise BuildRefused(f"{free:.1f} GB free, floor {floor:g} GB: prune a target or wait before building")


def record_wait(slot: int, waited: float, item: str, build_class: str = "coder") -> None:
    entry = {"at": clock.fmt(clock.now()), "slot": slot, "waited_s": round(waited, 1), "item": item, "class": build_class}
    with open(slot_dir() / "waits.log", "a") as log:
        log.write(json.dumps(entry) + "\n")


def run(
    command: list[str], *, item: str = "", build_class: str = "coder", cwd: Path | None = None,
    log_path: Path | None = None,
) -> int:
    """Run `command` in a slot. With `log_path`, stdout and stderr go to that file."""
    if not command:
        raise ValueError("swarm build needs a command after --")
    if build_class not in CLASSES:
        raise BuildRefused(f"build class must be one of {', '.join(CLASSES)}")
    check_disk(cwd or Path.cwd())
    fd, slot, waited = acquire(slots_for(build_class, slot_count()))
    record_wait(slot, waited, item, build_class)
    try:
        full = scope_prefix(build_class) + command
        env = build_env(dict(os.environ))
        if log_path is None:
            return subprocess.call(full, cwd=cwd, env=env)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "w") as log:
            return subprocess.call(full, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    finally:
        release(fd)


def prune_target(target: Path, *, older_than_hours: float, dry_run: bool = False) -> tuple[int, int, list[str]]:
    """Delete build artifacts not accessed within the window.

    Takes cargo's own `<profile>/.cargo-lock` while pruning a profile, so a running
    build is never pruned under (that profile is skipped and reported instead).
    Returns (files removed, bytes removed, profiles skipped because in use).
    """
    tag = target / "CACHEDIR.TAG"
    tagged = tag.is_file() and CARGO_TAG in tag.read_text(errors="replace")
    if not target.is_dir() or not (tagged or (target / ".rustc_info.json").is_file()):
        raise BuildRefused(f"{target} is not a cargo target directory (no CACHEDIR.TAG or .rustc_info.json)")
    cutoff = time.time() - older_than_hours * 3600
    removed = freed = 0
    busy: list[str] = []
    for profile in sorted(p for p in target.iterdir() if p.is_dir() and not p.is_symlink()):
        if not any((profile / name).is_dir() for name in PRUNABLE):
            continue
        lock_path = profile / ".cargo-lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                busy.append(profile.name)
                continue
            for name in PRUNABLE:
                root = profile / name
                if not root.is_dir() or root.is_symlink():
                    continue
                for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
                    for filename in filenames:
                        path = Path(dirpath) / filename
                        stat = path.lstat()
                        if max(stat.st_atime, stat.st_mtime) >= cutoff:
                            continue
                        removed += 1
                        freed += stat.st_size
                        if not dry_run:
                            path.unlink()
        finally:
            os.close(fd)
    return removed, freed, busy
