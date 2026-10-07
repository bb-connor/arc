"""Exercise actual Git effects, including hooks that ignore --no-verify."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from chio_adapter_base.security import harden_git_argv

HOOKS = ("pre-commit", "prepare-commit-msg", "commit-msg", "post-commit", "reference-transaction")


def prepare_repository(root: Path) -> dict[str, str]:
    env = {
        "PATH": os.defpath,
        "HOME": str(root),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "Chio hook test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Chio hook test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    }
    subprocess.run(["git", "init", "-q", str(root)], env=env, check=True, timeout=10)
    hooks = root / "owned-hooks"
    hooks.mkdir()
    for name in HOOKS:
        hook = hooks / name
        hook.write_text(f"#!/bin/sh\nprintf ran >> {name}.observed\n")
        hook.chmod(0o700)
    subprocess.run(
        ["git", "config", "core.hooksPath", str(hooks)],
        cwd=root,
        env=env,
        check=True,
        timeout=10,
    )
    return env


def test_no_verify_positive_control_still_executes_hooks(tmp_path: Path) -> None:
    env = prepare_repository(tmp_path)
    subprocess.run(
        ["git", "commit", "--no-verify", "--allow-empty", "-m", "test: control"],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        timeout=10,
    )
    for name in ("prepare-commit-msg", "post-commit", "reference-transaction"):
        assert (tmp_path / f"{name}.observed").exists(), name


@pytest.mark.parametrize("shape", ["plain", "no_verify", "config", "config_many", "config_env"])
def test_hardened_commit_creates_commit_without_executing_hooks(tmp_path: Path, shape: str) -> None:
    env = prepare_repository(tmp_path)
    hooks = str(tmp_path / "owned-hooks")
    prefix = {
        "plain": [],
        "no_verify": [],
        "config": ["-c", f"core.hooksPath={hooks}"],
        "config_many": ["-c", "core.hooksPath=/dev/null", "-c", f"core.hooksPath={hooks}"],
        "config_env": ["--config-env=core.hooksPath=HOOK_TEST_PATH"],
    }[shape]
    env["HOOK_TEST_PATH"] = hooks
    argv = ["git", *prefix, "commit", "--allow-empty", "-m", "test: hardened commit"]
    if shape == "no_verify":
        argv.append("--no-verify")
    hardened = harden_git_argv(argv)
    assert harden_git_argv(hardened) == hardened
    subprocess.run(hardened, cwd=tmp_path, env=env, check=True, capture_output=True, timeout=10)
    commit = subprocess.run(
        ["git", "log", "-1", "--format=%s"],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert commit.stdout.strip() == "test: hardened commit"
    for name in HOOKS:
        assert not (tmp_path / f"{name}.observed").exists(), name
