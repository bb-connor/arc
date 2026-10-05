#!/usr/bin/env python3
"""Unsafe attachment paths cannot expand the trusted research profile."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ControllerProfileTests(unittest.TestCase):
    def test_profile_generator_exists(self):
        self.assertTrue((ROOT / "scripts/outcome-ledger-profile.py").is_file(),
                        "candidate-specific profile generator is required")

    def module(self):
        spec = importlib.util.spec_from_file_location(
            "controller_profile", ROOT / "scripts/outcome-ledger-profile.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_unsafe_attachment_paths_reject_before_policy_is_written(self):
        module = self.module()
        for path in ["relative/controller", "/tmp/*/controller", "/tmp/evil\n/controller",
                     '/tmp/"controller', "/tmp/a{b}/controller", "/tmp/a\\b/controller",
                     "//tmp/controller", "/tmp/../controller", "/tmp/./controller"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                module.render_profile(path)

    def test_real_parser_accepts_one_enforcing_candidate_profile(self):
        module = self.module()
        policy = module.render_profile("/tmp/chio-qualified/controller")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "controller.profile"
            path.write_text(policy)
            compiled = subprocess.run(["apparmor_parser", "-Q", "-K", str(path)],
                                      capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            names = subprocess.run(["apparmor_parser", "-N", str(path)],
                                   capture_output=True, text=True, check=False)
            self.assertEqual(names.returncode, 0, names.stderr)
            self.assertEqual(len(names.stdout.splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
