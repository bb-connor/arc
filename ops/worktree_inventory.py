#!/usr/bin/env python3
"""List git worktrees with a cleanup recommendation. Read-only unless --apply is given.

  ops/worktree_inventory.py --repo ~/backbay/arc --keep '~/lanes/integration*' > plan.tsv
  # delete the lines you do not approve, then:
  ops/worktree_inventory.py --repo ~/backbay/arc --apply plan.tsv
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarmlib import gitio  # noqa: E402

STALE_DAYS = 7
TARGET_STALE_DAYS = 14
TARGET_MIN_GB = 1.0


@dataclass
class Worktree:
    path: str
    branch: str
    head: str
    age_days: float
    dirty: int
    pushed: bool
    target_gb: float


def classify(wt: Worktree, keep: list[str], main_path: str) -> tuple[str, str]:
    if wt.path == main_path or any(fnmatch.fnmatch(wt.path, os.path.expanduser(p)) for p in keep):
        return "keep", "protected"
    if wt.dirty or not wt.pushed:
        reason = f"{wt.dirty} uncommitted files" if wt.dirty else "unpushed commits"
        if wt.age_days >= TARGET_STALE_DAYS and wt.target_gb >= TARGET_MIN_GB:
            return "drop-target", f"{reason}; only build output removed"
        return "keep", reason
    if wt.age_days >= STALE_DAYS:
        return "remove", f"clean, pushed, {wt.age_days:.0f}d since last commit"
    return "keep", "recent"


def _git(repo: str, *args: str) -> str:
    return gitio.run(Path(repo), *args).stdout


def _dir_gb(path: Path) -> float:
    if not path.is_dir():
        return 0.0
    proc = subprocess.run(["du", "-sk", str(path)], capture_output=True, text=True)
    return int(proc.stdout.split()[0]) / 1024 / 1024 if proc.returncode == 0 and proc.stdout else 0.0


def remote_heads(repo: Path, url: str | None) -> set[str]:
    if not url:
        return set()
    proc = gitio.run(repo, *gitio.auth_args(), "ls-remote", url, "refs/heads/*", check=False)
    return {line.split()[0] for line in proc.stdout.splitlines() if line.strip()} if proc.returncode == 0 else set()


def collect(repo: Path, url: str | None) -> list[Worktree]:
    heads = remote_heads(repo, url)
    found, entry = [], {}
    for line in _git(str(repo), "worktree", "list", "--porcelain").splitlines() + [""]:
        if line:
            key, _, value = line.partition(" ")
            entry[key] = value
            continue
        if "worktree" in entry and "bare" not in entry and Path(entry["worktree"]).is_dir():
            path = os.path.realpath(entry["worktree"])
            head = entry.get("HEAD", "")
            stamp = int(_git(path, "log", "-1", "--format=%ct").strip() or "0")
            dirty = len([x for x in _git(path, "status", "--porcelain").splitlines() if x.strip()])
            contained = _git(path, "for-each-ref", "--contains", head, "refs/remotes").strip()
            found.append(Worktree(
                path=path, branch=entry.get("branch", "detached").removeprefix("refs/heads/"), head=head,
                age_days=(time.time() - stamp) / 86400, dirty=dirty, pushed=head in heads or bool(contained),
                target_gb=_dir_gb(Path(path) / "target"),
            ))
        entry = {}
    return found


def apply(repo: Path, plan: Path, url: str | None) -> int:
    current = {wt.path: wt for wt in collect(repo, url)}
    main_path = os.path.realpath(_git(str(repo), "rev-parse", "--show-toplevel").strip())
    failures = 0
    for line in plan.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        action, _, _, _, raw_path, *_ = line.split("\t")
        path = os.path.realpath(raw_path)
        wt = current.get(path)
        if wt is None or classify(wt, [], main_path)[0] != action:
            print(f"skip {path}: state changed since the inventory", file=sys.stderr)
            continue
        if action == "remove":
            proc = gitio.run(repo, "worktree", "remove", path, check=False)
            print(f"{'removed' if proc.returncode == 0 else 'FAILED'} {path} {proc.stderr.strip()}")
            failures += proc.returncode != 0
        elif action == "drop-target":
            shutil.rmtree(Path(path) / "target")
            print(f"dropped {path}/target")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", required=True, type=lambda s: Path(s).expanduser())
    p.add_argument("--keep", action="append", default=[], help="glob of worktree paths never to touch")
    p.add_argument("--url", default=os.environ.get("SWARM_GIT_URL", "https://github.com/bb-connor/arc.git"))
    p.add_argument("--apply", type=Path, help="approved TSV produced by a previous run")
    args = p.parse_args(argv)
    if args.apply:
        return apply(args.repo, args.apply, args.url)
    main_path = os.path.realpath(_git(str(args.repo), "rev-parse", "--show-toplevel").strip())
    rows = [(classify(wt, args.keep, main_path), wt) for wt in collect(args.repo, args.url)]
    print("# action\treason\ttarget_gb\tage_days\tpath\tbranch")
    for (action, reason), wt in sorted(rows, key=lambda r: (r[0][0], -r[1].target_gb)):
        print(f"{action}\t{reason}\t{wt.target_gb:.1f}\t{wt.age_days:.0f}\t{wt.path}\t{wt.branch}")
    freed = sum(wt.target_gb for (action, _), wt in rows if action in ("remove", "drop-target"))
    print(f"# at least {freed:.1f} GB of build output reclaimable", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
