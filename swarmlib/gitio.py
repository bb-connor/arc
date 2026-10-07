"""Thin subprocess wrapper around git."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

AUTH_HELPER = '!f() { test "$1" = get || exit 0; echo username=x-access-token; echo "password=$GH_TOKEN"; }; f'


class GitError(RuntimeError):
    pass


def auth_args() -> list[str]:
    """Credential helper that answers HTTPS prompts from $GH_TOKEN, if set."""
    if not os.environ.get("GH_TOKEN"):
        return []
    return ["-c", "credential.helper=", "-c", f"credential.helper={AUTH_HELPER}"]


def run(repo: Path | None, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if check and proc.returncode != 0:
        shown = [a for a in args if not a.startswith("credential.helper")]
        raise GitError(f"git {' '.join(shown)}: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def out(repo: Path | None, *args: str) -> str:
    return run(repo, *args).stdout.strip()
