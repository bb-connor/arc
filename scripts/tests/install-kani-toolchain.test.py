#!/usr/bin/env python3
"""Reject unsupported pins and changed compiler patches before executing tools."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class InstallerBoundaryTests(unittest.TestCase):
    def reject_before_tools(self, version, corrupt_patch):
        with tempfile.TemporaryDirectory(prefix="chio-kani-installer-test-") as directory:
            root = Path(directory)
            scripts = root / "scripts"
            patches = scripts / "toolchain-patches"
            patches.mkdir(parents=True)
            installer = scripts / "install-kani-toolchain.sh"
            shutil.copyfile(ROOT / "scripts/install-kani-toolchain.sh", installer)
            patch = patches / "kani-0.68-catch-unwind.patch"
            shutil.copyfile(ROOT / "scripts/toolchain-patches" / patch.name, patch)
            if corrupt_patch:
                patch.write_bytes(patch.read_bytes() + b"changed\n")
            marker = root / "tool-executed"
            tool = root / "cargo"
            tool.write_text('#!/bin/sh\n: > "$CHIO_TEST_TOOL_MARKER"\nexit 97\n')
            tool.chmod(0o700)
            environment = {
                **os.environ,
                "PATH": f"{root}:{os.environ['PATH']}",
                "CHIO_KANI_VERSION": version,
                "CHIO_TEST_TOOL_MARKER": str(marker),
            }
            result = subprocess.run(
                ["bash", str(installer)], env=environment, capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists(), result.stdout + result.stderr)
            return result.stdout + result.stderr

    def test_unsupported_version_is_rejected(self):
        output = self.reject_before_tools("latest", False)
        self.assertIn("requires CHIO_KANI_VERSION=0.68.0", output)

    def test_modified_patch_is_rejected(self):
        output = self.reject_before_tools("0.68.0", True)
        self.assertIn("FAILED", output)


if __name__ == "__main__":
    unittest.main()
