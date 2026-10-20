#!/usr/bin/env python3
"""Self-test for scripts/check-offline-verifier-deps.py."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_offline_verifier_deps", ROOT / "scripts/check-offline-verifier-deps.py"
)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

DENY_TOML = """
[licenses]
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception"]

[[licenses.clarify]]
name = "clarified"
version = "1.0.0"
expression = "MIT"
license-files = []
"""


def package(name: str, license_expression: str | None) -> dict:
    return {
        "id": f"{name}-id",
        "name": name,
        "version": "1.0.0",
        "license": license_expression,
    }


def metadata(extra: list[tuple[dict, str | None]]) -> dict:
    root = package("chio-bundle-verify", "Apache-2.0")
    serde = package("serde", "MIT OR Apache-2.0")
    packages = [root, serde] + [entry for entry, _ in extra]
    root_deps = [{"pkg": serde["id"], "dep_kinds": [{"kind": None, "target": None}]}]
    root_deps += [
        {"pkg": entry["id"], "dep_kinds": [{"kind": kind, "target": None}]}
        for entry, kind in extra
    ]
    nodes = [{"id": root["id"], "deps": root_deps}]
    nodes += [{"id": entry["id"], "deps": []} for entry in packages[1:]]
    return {"packages": packages, "resolve": {"nodes": nodes}}


class OfflineVerifierDepsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-offline-deps-")
        self.addCleanup(self.temp.cleanup)
        self.deny = Path(self.temp.name) / "deny.toml"
        self.deny.write_text(DENY_TOML, encoding="utf-8")

    def test_clean_closure_passes(self) -> None:
        self.assertEqual(GATE.check(metadata([]), self.deny), [])

    def test_tokio_in_the_normal_closure_fails(self) -> None:
        errors = GATE.check(metadata([(package("tokio", "MIT"), None)]), self.deny)
        self.assertTrue(any("tokio" in error for error in errors), errors)

    def test_dev_only_dependency_is_outside_the_closure(self) -> None:
        errors = GATE.check(metadata([(package("tokio", "MIT"), "dev")]), self.deny)
        self.assertEqual(errors, [])

    def test_mpl_package_fails(self) -> None:
        errors = GATE.check(metadata([(package("uniffi", "MPL-2.0"), None)]), self.deny)
        self.assertTrue(any("MPL-2.0" in error for error in errors), errors)

    def test_or_expression_needs_one_allowed_branch(self) -> None:
        errors = GATE.check(
            metadata([(package("dual", "MPL-2.0 OR MIT"), None)]), self.deny
        )
        self.assertEqual(errors, [])
        errors = GATE.check(
            metadata([(package("both", "MPL-2.0 AND MIT"), None)]), self.deny
        )
        self.assertTrue(errors)

    def test_with_exception_and_clarified_license(self) -> None:
        errors = GATE.check(
            metadata(
                [
                    (package("rustix", "Apache-2.0 WITH LLVM-exception OR MIT"), None),
                    (package("clarified", None), None),
                ]
            ),
            self.deny,
        )
        self.assertEqual(errors, [])

    def test_missing_license_fails(self) -> None:
        errors = GATE.check(metadata([(package("unlicensed", None), None)]), self.deny)
        self.assertTrue(any("declares no license" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
