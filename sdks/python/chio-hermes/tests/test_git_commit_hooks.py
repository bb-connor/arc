"""Both Git entrypoints must suppress hooks during a real commit."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from chio_hermes import executors


@pytest.mark.asyncio
@pytest.mark.parametrize("entrypoint", ["commit", "git_run"])
async def test_commit_entrypoints_do_not_execute_repository_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    subprocess.run(["git", "init", "-q", str(tmp_path)], env=env, check=True, timeout=10)
    for key, value in [
        ("user.name", "Chio test"),
        ("user.email", "test@example.invalid"),
        ("commit.gpgsign", "false"),
    ]:
        subprocess.run(["git", "config", key, value], cwd=tmp_path, env=env, check=True, timeout=10)
    hooks = tmp_path / ".git/hooks"
    for name in ["prepare-commit-msg", "post-commit", "reference-transaction"]:
        path = hooks / name
        path.write_text(f"#!/bin/sh\nprintf ran >> {name}.observed\n")
        path.chmod(0o700)
    (tmp_path / "change.txt").write_text("owned test change\n")
    subprocess.run(["git", "add", "change.txt"], cwd=tmp_path, env=env, check=True, timeout=10)
    if entrypoint == "commit":
        result = await executors.git_commit_executor(
            message="test: isolated hook regression", cwd=tmp_path
        )
    else:
        result = await executors.git_run_executor(
            command="commit -m 'test: isolated hook regression'", cwd=tmp_path
        )
    assert result["returncode"] == 0, result
    for name in ["prepare-commit-msg", "post-commit", "reference-transaction"]:
        assert not (tmp_path / f"{name}.observed").exists(), name
    result = subprocess.run(
        ["git", "log", "-1", "--format=%s"],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.stdout.strip() == "test: isolated hook regression"
