"""GitHub Actions lane tests through `gh`. The runner is injectable for tests."""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from typing import Callable

Runner = Callable[[list[str]], subprocess.CompletedProcess]
WORKFLOW = "lane-test.yml"
ACTIVE = {"queued", "in_progress", "waiting", "pending", "requested"}


class CIError(RuntimeError):
    pass


def repo_slug() -> str:
    return os.environ.get("SWARM_REPO_SLUG", "bb-connor/arc")


def default_runner(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True)


def gh(runner: Runner, *args: str) -> str:
    proc = runner(["gh", *args])
    if proc.returncode != 0:
        raise CIError(f"gh {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def in_flight(runner: Runner) -> int:
    runs = json.loads(gh(runner, "run", "list", "--repo", repo_slug(), "--workflow", WORKFLOW,
                         "--json", "status", "--limit", "100"))
    return sum(1 for run in runs if run["status"] in ACTIVE)


def wait_for_capacity(runner: Runner, cap: int, *, poll: float = 30, sleep: Callable[[float], None] = time.sleep) -> None:
    while in_flight(runner) >= cap:
        sleep(poll)


def dispatch(runner: Runner, *, item: str, target_ref: str, packages: list[str], test_filter: str, features: str) -> str:
    nonce = uuid.uuid4().hex[:10]
    gh(
        runner, "workflow", "run", WORKFLOW, "--repo", repo_slug(), "--ref", "main",
        "-f", f"target_ref={target_ref}", "-f", f"item={item}", "-f", f"packages={' '.join(packages)}",
        "-f", f"filter={test_filter}", "-f", f"features={features}", "-f", f"nonce={nonce}",
    )
    return nonce


def find_run(runner: Runner, nonce: str, *, timeout: float = 180, poll: float = 5,
             sleep: Callable[[float], None] = time.sleep) -> tuple[int, str]:
    waited = 0.0
    while waited <= timeout:
        runs = json.loads(gh(runner, "run", "list", "--repo", repo_slug(), "--workflow", WORKFLOW,
                             "--json", "databaseId,displayTitle,url", "--limit", "50"))
        for run in runs:
            if nonce in run["displayTitle"]:
                return int(run["databaseId"]), run["url"]
        sleep(poll)
        waited += poll
    raise CIError(f"no lane-test run with nonce {nonce} appeared within {timeout:.0f}s")


def watch(runner: Runner, run_id: int) -> bool:
    proc = runner(["gh", "run", "watch", str(run_id), "--repo", repo_slug(), "--exit-status", "--interval", "30"])
    return proc.returncode == 0


def busy(runner: Runner, branch: str, workflow: str = "CI") -> bool:
    """True while a run of `workflow` is active for `branch` (integrator push gate)."""
    runs = json.loads(gh(runner, "run", "list", "--repo", repo_slug(), "--workflow", workflow,
                         "--branch", branch, "--json", "status", "--limit", "20"))
    return any(run["status"] in ACTIVE for run in runs)


def green_rate(runner: Runner, branch: str, workflow: str = "CI") -> float | None:
    runs = json.loads(gh(runner, "run", "list", "--repo", repo_slug(), "--workflow", workflow,
                         "--branch", branch, "--json", "status,conclusion", "--limit", "20"))
    finished = [run for run in runs if run["status"] == "completed" and run["conclusion"] != "cancelled"]
    if not finished:
        return None
    return sum(run["conclusion"] == "success" for run in finished) / len(finished)
