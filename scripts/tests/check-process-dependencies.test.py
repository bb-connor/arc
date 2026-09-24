#!/usr/bin/env python3
"""Exercise the dependency gate on Cargo-shaped output, including parse failures."""

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "dependencies", ROOT / "scripts/check-process-dependencies.py"
)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
BASE = (
    "\n".join(
        f"{name} v0.1.0 (/checkout/{name})"
        for name in (
            "chio-kernel",
            "chio-process",
            "chio-cli",
            "chio-kernel-core",
            "chio-core-types",
            "chio-custody-hw",
        )
    )
    + "\n"
)


class DependencyGateTests(unittest.TestCase):
    def gate(self, output):
        # Cargo is the external boundary; parsing and the final gate remain real.
        with (
            patch.object(sys, "argv", ["check-process-dependencies.py"]),
            patch.object(CHECKER.subprocess, "check_output", return_value=output),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            return CHECKER.main()

    def test_webauthn_issuer_is_forbidden(self):
        self.assertEqual(self.gate(BASE + "webauthn-rs v0.5.0\n"), 1)

    def test_openssl_binding_is_forbidden(self):
        self.assertEqual(self.gate(BASE + "openssl-sys v0.9.0\n"), 1)

    def test_openssl_probe_and_cargo_duplicate_markers_are_allowed(self):
        self.assertEqual(
            self.gate(BASE + "openssl-probe v0.2.0\nchio-core-types v0.1.0 (*)\n"), 0
        )

    def test_empty_output_fails(self):
        self.assertEqual(self.gate(""), 1)

    def test_partial_malformed_output_fails(self):
        for malformed in [
            "unparsed package",
            "openssl-sys invalid-version",
            "openssl-sys vgarbage",
            "webauthn-rs v0.5.0 unexpected-suffix",
        ]:
            with self.subTest(malformed=malformed):
                self.assertEqual(self.gate(BASE + malformed + "\n"), 1)

    def test_missing_custody_member_fails(self):
        self.assertEqual(
            self.gate(
                BASE.replace("chio-custody-hw v0.1.0 (/checkout/chio-custody-hw)\n", "")
            ),
            1,
        )

    def test_pure_classifier_retains_exact_packages_and_rejects_partial_parses(self):
        result = CHECKER.classify_dependency_tree(
            "chio-process", BASE + "openssl-probe v0.2.0-beta.1+build.2\n"
        )
        self.assertEqual(result["package_count"], 7)
        self.assertEqual(result["forbidden_issuer_dependencies"], [])
        self.assertEqual(result["missing_kernel_dependencies"], [])
        self.assertIn("openssl-probe v0.2.0-beta.1+build.2", result["packages"])
        for suffix in [
            "\n",
            "garbage\n",
            "package v1.02.3\n",
            "package v1.2.3-01\n",
            "package v1.2.3+\n",
        ]:
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                CHECKER.classify_dependency_tree("chio-process", BASE + suffix)


if __name__ == "__main__":
    unittest.main()
