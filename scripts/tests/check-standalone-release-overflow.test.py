#!/usr/bin/env python3
"""Shipping profile and environment controls through the real overflow gate."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-standalone-release-overflow.py"


class ShippingOverflowContract(unittest.TestCase):
    def run_gate(self, manifest=None, environment=None):
        command = ["python3", str(CHECKER)]
        if manifest is not None:
            command.extend(["--manifest", str(manifest)])
        return subprocess.run(command, capture_output=True, text=True, env=environment, timeout=240)

    def test_every_selected_shipping_profile_traps_budget_underflow(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("traps budget subtraction below zero"), 5)

    def test_missing_standalone_check_refuses_shipping(self):
        with tempfile.TemporaryDirectory(prefix="chio-unchecked-shipping-") as temporary:
            manifest = Path(temporary) / "Cargo.toml"
            manifest.write_text('[profile.release]\nopt-level=3\n')
            result = self.run_gate(manifest)
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not enable overflow checks", result.stderr)

    def test_environment_override_cannot_turn_trapping_into_a_success(self):
        environment = os.environ.copy()
        environment["RUSTFLAGS"] = environment.get("RUSTFLAGS", "") + " -C overflow-checks=off"
        result = self.run_gate(ROOT / "sdks/lambda/chio-lambda-extension/Cargo.toml", environment)
        self.assertEqual(result.returncode, 1)
        self.assertIn("disabled overflow trapping", result.stderr)

    def test_unqualified_package_override_refuses_shipping(self):
        with tempfile.TemporaryDirectory(prefix="chio-overridden-shipping-") as temporary:
            manifest = Path(temporary) / "Cargo.toml"
            manifest.write_text(
                '[profile.release]\noverflow-checks=true\n'
                '[profile.release.package."chio-lambda-extension"]\noverflow-checks=false\n'
            )
            result = self.run_gate(manifest)
        self.assertEqual(result.returncode, 1)
        self.assertIn("qualify profile overrides explicitly", result.stderr)

    def test_actual_docker_shipping_profile_cannot_disable_overflow_checks(self):
        environment = os.environ.copy()
        environment["CARGO_PROFILE_DOCKER_RELEASE_OVERFLOW_CHECKS"] = "false"
        result = self.run_gate(environment=environment)
        self.assertEqual(result.returncode, 1)
        self.assertIn("disabled overflow trapping", result.stderr)

    def test_standalone_cargo_config_is_part_of_the_shipping_boundary(self):
        with tempfile.TemporaryDirectory(prefix="chio-configured-shipping-") as temporary:
            work = Path(temporary)
            manifest = work / "Cargo.toml"
            manifest.write_text(
                '[package]\nname="chio-lambda-extension"\nversion="0.0.0"\n'
                '[profile.release]\noverflow-checks=true\n'
            )
            (work / ".cargo").mkdir()
            (work / ".cargo/config.toml").write_text(
                '[profile.release.package."chio-lambda-extension"]\noverflow-checks=false\n'
            )
            result = self.run_gate(manifest)
        self.assertEqual(result.returncode, 1)
        self.assertIn("qualify profile overrides explicitly", result.stderr)

    def test_legacy_standalone_config_cannot_disable_native_trapping(self):
        with tempfile.TemporaryDirectory(prefix="chio-configured-shipping-") as temporary:
            work = Path(temporary)
            manifest = work / "Cargo.toml"
            manifest.write_text('[profile.release]\noverflow-checks=true\n')
            (work / ".cargo").mkdir()
            (work / ".cargo/config").write_text(
                '[build]\nrustflags=["-C", "overflow-checks=off"]\n'
            )
            result = self.run_gate(manifest)
        self.assertEqual(result.returncode, 1)
        self.assertIn("disabled overflow trapping", result.stderr)

    def test_relative_cargo_home_uses_the_shipping_working_directory(self):
        with tempfile.TemporaryDirectory(prefix="chio-relative-cargo-home-") as temporary:
            work = Path(temporary)
            manifest = work / "Cargo.toml"
            manifest.write_text(
                '[package]\nname="chio-lambda-extension"\nversion="0.1.0"\n'
                '[profile.release]\noverflow-checks=true\n'
            )
            cargo_home = work / "relative-cargo-home"
            cargo_home.mkdir()
            (cargo_home / "config.toml").write_text(
                '[profile.release.package."chio-lambda-extension:0.1.0"]\n'
                'overflow-checks=false\n'
            )
            environment = os.environ.copy()
            environment["CARGO_HOME"] = "relative-cargo-home"
            result = self.run_gate(manifest, environment)
        self.assertEqual(result.returncode, 1)
        self.assertIn("qualify profile overrides explicitly", result.stderr)


if __name__ == "__main__":
    unittest.main()
