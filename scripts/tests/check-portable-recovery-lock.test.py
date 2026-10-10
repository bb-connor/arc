"""An isolated resolver cannot silently introduce unreviewed build dependencies."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "check-portable-recovery-lock.py"
MODULE_SPEC = importlib.util.spec_from_file_location("portable_lock", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
LOCK = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(LOCK)


class PortableLockTests(unittest.TestCase):
    def setUp(self):
        dependency = {"name": "serde", "version": "1.0.228",
                      "source": "registry+https://github.com/rust-lang/crates.io-index",
                      "checksum": "a" * 64}
        local = {"name": "chio-core-types", "version": "0.3.0"}
        self.workspace = {"package": [dependency, local]}
        self.consumer = {"package": [{"name": "chio-recovery-portable-consumer", "version": "0.0.0"},
                                     copy.deepcopy(dependency), copy.deepcopy(local)]}

    def test_same_pinned_dependency_and_local_workspace_packages_are_approved(self):
        original = copy.deepcopy(self.workspace), copy.deepcopy(self.consumer)
        self.assertEqual(LOCK.audit_locks(self.workspace, self.consumer), ())
        self.assertEqual((self.workspace, self.consumer), original)

    def test_remote_identity_includes_version_source_and_checksum(self):
        for field, substitute in [("version", "1.0.229"),
                                  ("source", "registry+https://unapproved.example/index"),
                                  ("checksum", "b" * 64)]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.consumer)
                changed["package"][1][field] = substitute
                self.assertEqual(len(LOCK.audit_locks(self.workspace, changed)), 1)

    def test_missing_registry_checksum_cannot_be_approved(self):
        self.consumer["package"][1].pop("checksum")
        with self.assertRaisesRegex(ValueError, "no checksum"):
            LOCK.audit_locks(self.workspace, self.consumer)

    def test_only_exact_local_consumer_root_is_exempt(self):
        for substitute in [{"name": "new-local-crate", "version": "0.0.0"},
                           {"name": "chio-recovery-portable-consumer", "version": "0.1.0"},
                           {"name": "chio-core-types", "version": "99.0.0"}]:
            with self.subTest(substitute=substitute):
                changed = copy.deepcopy(self.consumer)
                changed["package"].append(substitute)
                self.assertTrue(LOCK.audit_locks(self.workspace, changed))

    def test_duplicate_package_and_missing_fixture_root_refuse(self):
        self.consumer["package"].append(copy.deepcopy(self.consumer["package"][1]))
        self.assertTrue(LOCK.audit_locks(self.workspace, self.consumer))
        self.consumer["package"].pop(0)
        self.assertIn("portable consumer root is missing", LOCK.audit_locks(self.workspace, self.consumer))


if __name__ == "__main__":
    unittest.main()
