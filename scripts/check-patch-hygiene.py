#!/usr/bin/env python3
"""Check the committed change introduced by a GitHub pull request or push."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path


def commit_sha(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ValueError("event commit identity must be a full lowercase SHA-1")
    if value == "0" * 40:
        raise ValueError("event commit identity must not be zero")
    if git("rev-parse", "--verify", f"{value}^{{commit}}") != value:
        raise ValueError("event commit is not available in this checkout")
    return value


def git(*args: str, input_text: str | None = None) -> str:
    return subprocess.check_output(["git", *args], text=True, input=input_text).strip()


def main() -> int:
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        kind = os.environ["GITHUB_EVENT_NAME"]
        checkout = commit_sha(os.environ["GITHUB_SHA"])
        if git("rev-parse", "HEAD") != checkout:
            raise ValueError("checkout HEAD differs from the GitHub event SHA")

        if kind == "pull_request":
            base = commit_sha(event["pull_request"]["base"]["sha"])
            head = commit_sha(event["pull_request"]["head"]["sha"])
            # Checkout normally holds GitHub's synthetic merge commit. Never
            # silently inspect a head unrelated to that checkout.
            subprocess.run(
                ["git", "merge-base", "--is-ancestor", head, checkout], check=True
            )
            bases = git("merge-base", "--all", base, head).splitlines()
            if len(bases) != 1:
                raise ValueError("pull request must have one unambiguous merge base")
            start = bases[0]
        elif kind == "push":
            head = commit_sha(event["after"])
            if head != checkout:
                raise ValueError("push head differs from the checked out event SHA")
            if event["before"] == "0" * 40:
                # A new branch has no prior commit. Check every added file.
                start = git("hash-object", "-w", "-t", "tree", "--stdin", input_text="")
            else:
                start = commit_sha(event["before"])
        else:
            raise ValueError(f"unsupported patch hygiene event: {kind}")

        print(f"Checking committed {kind} patch {start}..{head}", flush=True)
        return subprocess.run(
            [
                "git",
                "diff",
                "--check",
                "--no-ext-diff",
                "--no-textconv",
                start,
                head,
                "--",
            ],
            check=False,
        ).returncode
    except (
        KeyError,
        TypeError,
        ValueError,
        OSError,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"patch hygiene refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
