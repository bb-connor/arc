#!/usr/bin/env python3
"""Self-test for scripts/check-wrapper-capture-scope.py."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(
    os.environ.get(
        "CHECK_WRAPPER_CAPTURE_SCOPE",
        Path(__file__).resolve().parent.parent / "check-wrapper-capture-scope.py",
    )
)
CORE = "crates/core/chio-core-types/Cargo.toml"
GOOD_FEATURES = '[features]\ndefault = ["std"]\nstd = []\nwrapper-capture = ["std"]\n'
HOOK = 'mod wrapper_capture;\n#[cfg(feature = "wrapper-capture")]\nfn f() {}\n'

failures: list[str] = []


def expect(name: str, files: dict[str, str], exit_code: int, mentions: str = "") -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        result = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode != exit_code:
        failures.append(f"{name}: expected exit {exit_code}, got {result.returncode}\n{result.stdout}{result.stderr}")
    elif mentions and mentions not in result.stderr:
        failures.append(f"{name}: expected {mentions!r} in\n{result.stderr}")


BASE = {CORE: GOOD_FEATURES, "crates/core/chio-core-types/src/crypto/wrapper.rs": HOOK}

expect("confined feature", BASE, 0)
expect("missing feature", {CORE: '[features]\ndefault = ["std"]\nstd = []\n'}, 1, 'must be exactly ["std"]')
expect("feature with extra implications", {CORE: GOOD_FEATURES.replace('["std"]\n', '["std", "pq"]\n')}, 1, 'must be exactly ["std"]')
expect(
    "default feature",
    {CORE: '[features]\ndefault = ["std", "wrapper-capture"]\nstd = []\nwrapper-capture = ["std"]\n'},
    1,
    "must not be a default feature",
)
expect("forwarded by another feature", {CORE: GOOD_FEATURES + 'harness = ["wrapper-capture"]\n'}, 1, "feature harness implies")
expect(
    "enabled by a dependent manifest",
    {**BASE, "crates/kernel/demo/Cargo.toml": '[dependencies]\nchio-core-types = { features = ["wrapper-capture"] }\n'},
    1,
    "crates/kernel/demo/Cargo.toml: names wrapper-capture",
)
expect(
    "enabled by a workflow",
    {**BASE, ".github/workflows/release.yml": "run: cargo build --features chio-core-types/wrapper-capture\n"},
    1,
    ".github/workflows/release.yml",
)
expect(
    "cfg outside the hook",
    {**BASE, "crates/core/chio-core-types/src/receipt.rs": '#[cfg(feature = "wrapper-capture")]\nfn g() {}\n'},
    1,
    "crates/core/chio-core-types/src/receipt.rs",
)

if failures:
    print("\n\n".join(failures), file=sys.stderr)
    sys.exit(1)
print("check-wrapper-capture-scope self-test: ok")
