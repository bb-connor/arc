"""Regression tests for prerequisite evidence in the aggregate record checker.

Fixtures are disposable copies of a successful record, rebound to the current
checker source solely to test validation logic. They are not qualification runs.
No recorded repository artifacts are changed.
"""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "followthrough", Path(__file__).with_name("verify_followthrough.py")
)
verification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)


class PrerequisiteEvidence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="chio-record-regression-")
        self.addCleanup(self.temporary.cleanup)
        target = Path(self.temporary.name)
        for file in verification.OUT.iterdir():
            if file.is_file():
                shutil.copyfile(file, target / file.name)
        manifest_path = target / "verification.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["sources"] = verification.sources()
        manifest_path.write_text(json.dumps(manifest))
        self.patch = patch.object(verification, "OUT", target)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        # A broken fixture cannot make a negative probe pass accidentally.
        with contextlib.redirect_stdout(io.StringIO()):
            verification.check()

    def rejected_when_changed(self, relative):
        changed = verification.ROOT / relative
        original = Path.read_bytes

        def read(path, *args, **kwargs):
            if path == changed:
                return original(path, *args, **kwargs) + b"\nchanged-prerequisite\n"
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_bytes", read), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
                verification.check()

    def test_prior_model_output_cannot_change_under_a_green_record(self):
        self.rejected_when_changed("docs/research/kernel-work/results/model/explorer.stdout")

    def test_prior_model_manifest_cannot_change_under_a_green_record(self):
        self.rejected_when_changed("docs/research/kernel-work/results/model/verification.json")

    def test_claim_register_cannot_change_under_a_green_record(self):
        self.rejected_when_changed("docs/research/kernel-work/claim-register.json")

    def test_prerequisite_verifier_cannot_change_under_a_green_record(self):
        self.rejected_when_changed("labs/kernel-work-composition/verify.py")


if __name__ == "__main__":
    unittest.main()
