#!/usr/bin/env python3
"""Self-test for scripts/check-error-urn-registry.py."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "check-error-urn-registry.py"

REGISTRY = """schema: "chio.error-urn-registry.v1"
codes:
  - urn: "urn:chio:error:kernel:known"
    domain: kernel
  - urn: "urn:chio:error:transport:family-alpha"
    domain: transport
"""


def run(files: dict[str, str]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "spec/errors").mkdir(parents=True)
        (root / "spec/errors/registry.yaml").write_text(REGISTRY, encoding="utf-8")
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )


def expect(name: str, files: dict[str, str], passes: bool, mentions: str = "") -> None:
    result = run(files)
    if (result.returncode == 0) != passes:
        raise SystemExit(f"{name}: exit {result.returncode}\n{result.stdout}{result.stderr}")
    if mentions and mentions not in result.stderr:
        raise SystemExit(f"{name}: expected {mentions!r} in\n{result.stderr}")


LIB = "crates/kernel/demo/src/lib.rs"

expect("registered literal", {LIB: 'const A: &str = "urn:chio:error:kernel:known";\n'}, True)
expect(
    "unregistered literal",
    {LIB: 'fn f() -> &str { "urn:chio:error:kernel:unknown" }\n'},
    False,
    "urn:chio:error:kernel:unknown: crates/kernel/demo/src/lib.rs:1",
)
expect(
    "unregistered literal in a nested module",
    {"crates/kernel/demo/src/a/b.rs": '\n"urn:chio:error:kernel:other"\n'},
    False,
    "crates/kernel/demo/src/a/b.rs:2",
)
expect(
    "registered family stem",
    {LIB: 'format!("urn:chio:error:transport:family-{rule}")\n'},
    True,
)
expect(
    "unregistered family stem",
    {LIB: 'format!("urn:chio:error:transport:missing-{rule}")\n'},
    False,
    "urn:chio:error:transport:missing-",
)
for test_only in (
    "crates/kernel/demo/src/tests.rs",
    "crates/kernel/demo/src/store_tests.rs",
    "crates/kernel/demo/src/tests/case.rs",
    "crates/kernel/demo/src/hosted_tests/case.rs",
    "crates/kernel/demo/src/_generated/codes.rs",
    "crates/kernel/demo/tests/integration.rs",
):
    expect(f"skipped {test_only}", {test_only: '"urn:chio:error:kernel:unknown"\n'}, True)

print("check-error-urn-registry.test.py: all assertions passed")
