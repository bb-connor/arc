"""Capture verified release-build inputs for the controlled upstream comparison."""

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

from chio_mini_swe.operator import protected_executable
from chio_mini_swe.session_security import environment_identity

RELEASE = {
    "OPT_LEVEL": "3",
    "DEBUG": "0",
    "DEBUG_ASSERTIONS": "false",
    "OVERFLOW_CHECKS": "false",
    "CODEGEN_UNITS": "1",
    "LTO": "fat",
    "STRIP": "symbols",
    "PANIC": "unwind",
}
BUILD_ENVIRONMENT = {
    **{"CARGO_PROFILE_RELEASE_" + key: value for key, value in RELEASE.items()},
    "CARGO_INCREMENTAL": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
}
PACKAGES = {"chio_mini_swe": "chio-mini-swe", "chio_process": "chio-process"}
SOURCE_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    "sdks/python/chio-mini-swe/uv.lock",
    "sdks/python/chio-mini-swe/pyproject.toml",
    "sdks/python/chio-process/pyproject.toml",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(*arguments):
    result = subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    require(len(result.stdout) <= 4 * 1024 * 1024, "Provenance command output exceeds its limit")
    return result.stdout.strip()


def build_environment(environment):
    for name, expected in BUILD_ENVIRONMENT.items():
        require(environment.get(name) == expected, "Unexpected build environment: " + name)
    forbidden = {
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_TARGET",
    }
    for name, value in environment.items():
        if name in forbidden or (name.startswith("CARGO_TARGET_") and name.endswith("_RUSTFLAGS")):
            require(not value, "Unexpected compiler override: " + name)
        if name.startswith("CARGO_PROFILE_"):
            require(name in BUILD_ENVIRONMENT, "Unexpected Cargo profile override: " + name)
    return {
        **{name: environment[name] for name in BUILD_ENVIRONMENT},
        **{name: environment.get(name, "") for name in sorted(forbidden)},
        **{
            name: environment.get(name, "")
            for name in ("CARGO_BUILD_JOBS", "CARGO_TARGET_DIR", "RUSTUP_TOOLCHAIN")
        },
    }


def checkout_identity(root, environment):
    require(run("git", "rev-parse", "--show-toplevel") == str(root), "Run from the checkout root")
    require(
        not run("git", "status", "--porcelain=v1", "--untracked-files=all"), "Checkout is dirty"
    )
    require(not run("git", "ls-files", "--deleted"), "Checkout has missing tracked sources")
    require(
        not any(line.startswith("S ") for line in run("git", "ls-files", "-t").splitlines()),
        "A complete checkout is required",
    )
    commit = run("git", "rev-parse", "HEAD")
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "Invalid checkout SHA")
    require(commit == environment.get("GITHUB_SHA"), "Checkout SHA differs from workflow SHA")
    return {"commit": commit, "tree": run("git", "rev-parse", "HEAD^{tree}"), "clean": True}


def cargo_artifact(path, root, binary):
    require(path.stat().st_size <= 64 * 1024 * 1024, "Cargo messages exceed their byte limit")
    candidates = []
    finished = []
    with path.open() as stream:
        for line in stream:
            message = json.loads(line)
            if message.get("reason") == "build-finished":
                finished.append(message.get("success"))
            if message.get("reason") != "compiler-artifact":
                continue
            target = message.get("target", {})
            if target.get("name") == "chio" and target.get("kind") == ["bin"]:
                candidates.append(message)
    require(finished == [True] and len(candidates) == 1, "Expected one successful Chio build")
    artifact = candidates[0]
    require(
        Path(artifact["manifest_path"]).resolve() == root / "crates/products/chio-cli/Cargo.toml",
        "Cargo artifact belongs to another package",
    )
    profile = artifact["profile"]
    require(
        profile.get("opt_level") == "3"
        and profile.get("debug_assertions") is False
        and profile.get("overflow_checks") is False
        and profile.get("test") is False
        and profile.get("debuginfo") in (None, 0),
        "Cargo artifact is not the expected release build",
    )
    built = Path(artifact["executable"])
    require(
        built.is_file() and digest(built) == digest(binary), "CLI differs from the Cargo artifact"
    )
    return {
        "package_id": artifact["package_id"],
        "target": artifact["target"],
        "profile": profile,
        "features": artifact["features"],
        "fresh": artifact["fresh"],
        "cargo_messages_sha256": digest(path),
    }


def source_hashes(root):
    paths = sorted(root.rglob("*.py"))
    require(0 < len(paths) <= 256, "Invalid Python source inventory")
    return {str(path.relative_to(root)): digest(path) for path in paths}


def installed_sources(root, wheels):
    installation = environment_identity()
    identities = {}
    expected_wheels = set()
    for module, distribution in PACKAGES.items():
        specification = importlib.util.find_spec(module)
        require(
            specification is not None and specification.origin is not None,
            "Missing installed package: " + module,
        )
        installed = Path(specification.origin).resolve().parent
        require(installed.is_relative_to(Path(sys.prefix).resolve()), "Package is not installed")
        expected = source_hashes(root / "sdks/python" / distribution / "src" / module)
        require(source_hashes(installed) == expected, "Installed source differs: " + module)
        metadata = tomllib.loads(
            (root / "sdks/python" / distribution / "pyproject.toml").read_text()
        )
        version = metadata["project"]["version"]
        require(
            importlib.metadata.version(distribution) == version, "Installed package version differs"
        )
        wheel_name = f"{module}-{version}-py3-none-any.whl"
        expected_wheels.add(wheel_name)
        wheel = wheels / wheel_name
        with zipfile.ZipFile(wheel) as archive:
            entries = [
                name
                for name in archive.namelist()
                if name.startswith(module + "/") and name.endswith(".py")
            ]
            require(len(entries) == len(set(entries)), "Wheel contains duplicate Python sources")
            wheel_sources = {
                name.removeprefix(module + "/"): hashlib.sha256(archive.read(name)).hexdigest()
                for name in entries
            }
        require(wheel_sources == expected, "Wheel source differs: " + module)
        identities[module] = {
            "version": version,
            "sources_sha256": expected,
            "wheel": wheel_name,
            "wheel_sha256": digest(wheel),
        }
    require(
        {path.name for path in wheels.glob("*.whl")} == expected_wheels,
        "Unexpected wheel inventory",
    )
    require(importlib.metadata.version("mini-swe-agent") == "2.4.6", "Unexpected upstream version")
    return {
        "packages": identities,
        "environment": installation,
        "dependencies": sorted(
            (
                {"name": entry.metadata["Name"], "version": entry.version}
                for entry in importlib.metadata.distributions()
            ),
            key=lambda entry: entry["name"].lower(),
        ),
    }


def workflow_identity(environment):
    names = (
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_WORKFLOW_SHA",
        "GITHUB_SHA",
        "GITHUB_REF",
        "GITHUB_REPOSITORY",
        "GITHUB_EVENT_NAME",
    )
    result = {name: environment.get(name, "") for name in names}
    require(result["GITHUB_EVENT_NAME"] == "workflow_dispatch", "Expected manual qualification")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(result[name].isdigit() and int(result[name]) > 0, "Missing workflow run identity")
    for name in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA"):
        require(re.fullmatch(r"[0-9a-f]{40}", result[name]) is not None, "Missing workflow SHA")
    require(all(result.values()), "Incomplete workflow identity")
    return result


def capture(messages, binary, wheels, root):
    environment = build_environment(os.environ)
    source = checkout_identity(root, os.environ)
    protected_executable(binary)
    artifact = cargo_artifact(messages, root, binary)
    toolchain = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    rustc = run("rustc", "-vV")
    require(
        re.search(r"^release: " + re.escape(toolchain) + r"$", rustc, re.MULTILINE) is not None,
        "Compiler differs from the pinned toolchain",
    )
    result = {
        "schema": "chio.mini-swe.optimized-build.v1",
        "source": source,
        "workflow": workflow_identity(os.environ),
        "build_environment": environment,
        "build_command": [
            "cargo",
            "build",
            "--release",
            "--locked",
            "-p",
            "chio-cli",
            "--bin",
            "chio",
            "--message-format=json-render-diagnostics",
        ],
        "cargo_artifact": artifact,
        "rustc": rustc,
        "cargo": run("cargo", "-vV"),
        "source_files_sha256": {name: digest(root / name) for name in SOURCE_FILES},
        "binary": {"sha256": digest(binary), "bytes": binary.stat().st_size},
        "python": {
            "version": sys.version,
            "executable": str(Path(sys.executable).resolve()),
            "installation": installed_sources(root, wheels),
        },
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "cpu": json.loads(run("lscpu", "--json")),
            "os": {
                name: platform.freedesktop_os_release().get(name, "")
                for name in ("ID", "VERSION_ID", "PRETTY_NAME")
            },
            "docker": json.loads(
                run(
                    "/usr/bin/docker",
                    "--host",
                    "unix:///var/run/docker.sock",
                    "version",
                    "--format",
                    "{{json .}}",
                )
            ),
        },
    }
    require(checkout_identity(root, os.environ) == source, "Checkout changed during capture")
    require(digest(binary) == result["binary"]["sha256"], "CLI changed during capture")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-messages", type=Path, required=True)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--wheels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = capture(
        args.cargo_messages, args.chio.resolve(strict=True), args.wheels, Path.cwd().resolve()
    )
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
