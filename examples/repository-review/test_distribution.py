"""Installed launchers exclude ambient Python code and prove offline pip behavior."""

import argparse
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


def module(name):
    spec = importlib.util.spec_from_file_location(
        "distribution_" + name, Path(__file__).parent / "distribution" / (name + ".py")
    )
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


@pytest.mark.parametrize("operation", ["prepare", "run", "worker"])
def test_application_excludes_user_site_sitecustomize(tmp_path, monkeypatch, operation):
    launcher = module("review")
    home = tmp_path / "home"
    version = subprocess.check_output(
        [
            "/usr/bin/python3",
            "-I",
            "-c",
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
        ],
        text=True,
    ).strip()
    site = home / f".local/lib/python{version}/site-packages"
    site.mkdir(parents=True)
    marker = tmp_path / "injected"
    for name in ("sitecustomize.py", "usercustomize.py"):
        (site / name).write_text(
            f"from pathlib import Path; Path({str(marker)!r}).write_text('executed')\n"
        )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("PYTHONNOUSERSITE", raising=False)
    subprocess.run(
        ["/usr/bin/python3", "-c", "pass"], env=launcher.environment(), check=True
    )
    assert marker.read_text() == "executed"
    marker.unlink()
    kit = tmp_path / "kit"
    (kit / "application").mkdir(parents=True)
    (kit / "application/adaptive_review.py").write_text(
        "import json, sys; print(json.dumps({'isolated': sys.flags.isolated}))\n"
    )
    (kit / "manifest.json").write_text("{}")
    monkeypatch.setattr(launcher, "HERE", kit)
    state = tmp_path / "state"

    def environment(path):
        (path / "bin").mkdir(parents=True)
        (path / "bin/python").symlink_to("/usr/bin/python3")

    monkeypatch.setattr(
        launcher.venv.EnvBuilder, "create", lambda self, path: environment(path)
    )
    monkeypatch.setattr(launcher, "installed", lambda _: {"packages": {}, "files": {}})
    monkeypatch.setattr(launcher, "validate", lambda _: None)
    monkeypatch.setattr(launcher, "manifest", lambda: {"packages": {}})
    command = launcher.command
    outputs = []

    def invoke(args, **kwargs):
        if "pip" in args:
            return b""
        result = command(args, **kwargs)
        outputs.append(json.loads(result))
        return result

    monkeypatch.setattr(launcher, "command", invoke)
    if operation == "worker":
        from adaptive import configuration

        monkeypatch.setattr(configuration, "HERE", kit / "application")
        monkeypatch.setattr(configuration.sys, "executable", "/usr/bin/python3")
        worker = configuration.plan({"max_reviews": 1, "max_parallel": 1}, state)[
            "workers"
        ][0]
        state.mkdir(mode=0o700)
        invoke(worker["command"], cwd=state, log=state / "application.log")
    elif operation == "prepare":
        args = argparse.Namespace(
            state=state,
            repo=tmp_path,
            base="HEAD~1",
            head="HEAD",
            model_factory="inventory",
            max_reviews=2,
            max_parallel=1,
            max_rounds=2,
            max_calls=30,
        )
        launcher.prepare(args, {"packages": {}})
    else:
        state.mkdir(mode=0o700)
        environment(state / "venv")
        monkeypatch.setattr(
            launcher.sys, "argv", ["review.py", "run", "--state", str(state)]
        )
        launcher.main()
    assert not marker.exists(), (
        "ambient sitecustomize executed in installed application"
    )
    assert outputs == [{"isolated": 1}]


@pytest.mark.parametrize("offline", [True, False])
def test_offline_oracle_detects_actual_pip_no_index_boundary(tmp_path, offline):
    qualifier = module("qualify")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("")
    log = tmp_path / "pip.log"
    command = [
        "/usr/bin/python3",
        "-I",
        "-m",
        "pip",
        "--isolated",
        "install",
        "--dry-run",
        "--target",
        str(tmp_path / "install"),
        "--disable-pip-version-check",
        "--log",
        str(log),
        "-r",
        str(requirements),
    ]
    if offline:
        command.append("--no-index")
    # Empty requirements cause no network access in either case. pip's own
    # index-discovery diagnostic still distinguishes the missing boundary.
    subprocess.run(command, capture_output=True, text=True, check=True)
    if offline:
        qualifier.verify_offline_install(log)
    else:
        with pytest.raises(AssertionError, match="did not disable index discovery"):
            qualifier.verify_offline_install(log)


def test_documented_virtual_environment_is_ignored():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        ["git", "check-ignore", "examples/repository-review/.venv/bin/python"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "examples/repository-review/.venv/bin/python"
