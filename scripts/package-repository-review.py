#!/usr/bin/env python3
"""Build a platform-specific offline review kit from locked dependencies and SDK wheels."""

import argparse
import email
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "examples/repository-review"
LOCAL_PACKAGES = (
    "chio-sdk-python",
    "chio-adapter-base",
    "chio-process",
    "chio-langgraph",
)


def command(args, *, cwd=ROOT):
    result = subprocess.run(
        list(map(str, args)),
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode:
        raise RuntimeError(f"{Path(str(args[0])).name} failed:\n{result.stderr}")
    return result.stdout


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def wheel_metadata(path):
    with zipfile.ZipFile(path) as archive:
        names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(names) != 1:
            raise ValueError("wheel must have one distribution metadata record")
        metadata = email.message_from_bytes(archive.read(names[0]))
    return metadata["Name"].lower().replace("_", "-"), metadata["Version"]


def build(binary, output):
    if sys.platform != "linux" or sys.version_info < (3, 11):
        raise ValueError("build the kit on Linux with Python 3.11 or later")
    if output.is_relative_to(ROOT):
        raise ValueError("place the kit outside the source checkout")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    packages = output / "packages"
    packages.mkdir()
    (output / "bin").mkdir()
    shutil.copy2(binary, output / "bin/chio")
    application = output / "application"
    application.mkdir()
    for path in APP.glob("*.py"):
        if not path.name.startswith("test_"):
            shutil.copyfile(path, application / path.name)
    shutil.copytree(
        APP / "adaptive",
        application / "adaptive",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    for name in (
        "README.md",
        "ARCHITECTURE.md",
        "ADAPTIVE.md",
        "pyproject.toml",
        "uv.lock",
    ):
        shutil.copyfile(APP / name, application / name)
    for name in ("review.py", "qualify.py", "README.md"):
        shutil.copyfile(APP / "distribution" / name, output / name)
    # The app lock includes runtime checkpointing but excludes test/lint tools.
    command(
        [
            "uv",
            "export",
            "--project",
            APP,
            "--locked",
            "--no-dev",
            "--no-emit-local",
            "--no-header",
            "--no-annotate",
            "--output-file",
            output / "third-party.txt",
        ]
    )
    command(
        [
            sys.executable,
            "-m",
            "pip",
            "--isolated",
            "download",
            "--no-deps",
            "--require-hashes",
            "--only-binary=:all:",
            "--disable-pip-version-check",
            "--dest",
            packages,
            "-r",
            output / "third-party.txt",
        ]
    )
    for name in LOCAL_PACKAGES:
        command(
            [
                "uv",
                "build",
                "--wheel",
                ROOT / "sdks/python" / name,
                "--out-dir",
                packages,
            ]
        )
    versions, local_requirements = {}, []
    for path in sorted(packages.glob("*.whl")):
        name, version = wheel_metadata(path)
        if name in versions:
            raise ValueError(f"more than one wheel was selected for {name}")
        versions[name] = version
        if name in LOCAL_PACKAGES:
            local_requirements.append(
                f"{name}=={version} --hash=sha256:{digest(path)}\n"
            )
    if len(local_requirements) != len(LOCAL_PACKAGES):
        raise ValueError("missing local SDK wheel")
    (output / "requirements.txt").write_text(
        (output / "third-party.txt").read_text() + "\n" + "".join(local_requirements)
    )
    # Supplier trust and native build provenance are separate from these local
    # drift-detection hashes. The binary is copied, not rebuilt or signed here.
    manifest = {
        "schema": "chio.repository.review-kit.v1",
        "kind": "development-preview",
        "system": platform.system(),
        "machine": platform.machine(),
        "python": list(sys.version_info[:2]),
        "packages": versions,
        "source_checkout": {
            "revision": command(["git", "rev-parse", "HEAD"]).strip(),
            "dirty": bool(command(["git", "status", "--porcelain"])),
        },
        "files": {
            str(path.relative_to(output)): digest(path)
            for path in sorted(output.rglob("*"))
            if path.is_file()
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(
        json.dumps(
            {
                "built": str(output),
                "wheel_count": len(versions),
                "source_checkout": manifest["source_checkout"],
            }
        )
    )


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.chio.resolve(strict=True), args.output.resolve())


if __name__ == "__main__":
    main()
