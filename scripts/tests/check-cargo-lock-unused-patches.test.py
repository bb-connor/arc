#!/usr/bin/env python3
"""Self-test for scripts/check-cargo-lock-unused-patches.py."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(
    os.environ.get(
        "CHECK_CARGO_LOCK_UNUSED_PATCHES",
        Path(__file__).resolve().parent.parent / "check-cargo-lock-unused-patches.py",
    )
)

CLEAN = """version = 4

[[package]]
name = "demo"
version = "0.1.0"
"""
UNUSED = CLEAN + """
[[patch.unused]]
name = "seccompiler"
version = "0.5.0"
"""

failures: list[str] = []


def run(files: dict[str, str], untracked: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        if files:
            subprocess.run(["git", "-C", str(root), "add", "--", *files], check=True)
        for relative, text in (untracked or {}).items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )


def expect(name: str, result: subprocess.CompletedProcess[str], exit_code: int, mentions: str = "") -> None:
    if result.returncode != exit_code:
        failures.append(f"{name}: expected exit {exit_code}, got {result.returncode}\n{result.stdout}{result.stderr}")
    elif mentions and mentions not in result.stderr + result.stdout:
        failures.append(f"{name}: expected {mentions!r} in\n{result.stdout}{result.stderr}")


expect("clean root lockfile", run({"Cargo.lock": CLEAN}), 0, "in 1 committed lockfiles")
expect("unused patch in the root lockfile", run({"Cargo.lock": UNUSED}), 1, "Cargo.lock: unused patch seccompiler 0.5.0")
expect(
    "unused patch in a nested workspace lockfile",
    run({"Cargo.lock": CLEAN, "deploy/docker/proof-room-workspace/Cargo.lock": UNUSED}),
    1,
    "deploy/docker/proof-room-workspace/Cargo.lock: unused patch seccompiler 0.5.0",
)
expect(
    "every unused entry is reported",
    run({"Cargo.lock": UNUSED + '\n[[patch.unused]]\nname = "enumflags2_derive"\nversion = "0.7.12"\n'}),
    1,
    "unused patch enumflags2_derive 0.7.12",
)
expect(
    "vendored upstream lockfile is not a workspace",
    run({"Cargo.lock": CLEAN, "third_party/nono-upstream-chio/Cargo.lock": UNUSED}),
    0,
    "in 1 committed lockfiles",
)
expect(
    "untracked lockfile is not committed",
    run({"Cargo.lock": CLEAN}, untracked={"fuzz/Cargo.lock": UNUSED}),
    0,
)
expect("malformed lockfile", run({"Cargo.lock": "[[patch.unused]\n"}), 1, "cannot read lockfile")
expect("no committed lockfile", run({"README.md": "x\n"}), 2)

if failures:
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
print("check-cargo-lock-unused-patches.test.py: all assertions passed")
