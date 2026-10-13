#!/usr/bin/env python3
"""Execute the thin-main version gate with exact schema and core-wire controls."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
GATE = Path(os.environ.get("CHIO_TRUSTED_MAIN_VERSION_GATE", ROOT / "scripts/check-chio-owned-v1-only.sh"))
AUDITOR = "scripts/audit-security-merge-qualification.py"


class TrustedMainCodegenTests(unittest.TestCase):
    def gate(self, path: str, text: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory(prefix="chio-trusted-main-version-") as raw:
            root = Path(raw)
            for name in ("crates", "spec", "sdks", "scripts", "docs", "formal", "xtask"):
                (root / name).mkdir()
            script = root / "scripts/check-chio-owned-v1-only.sh"
            script.write_bytes(GATE.read_bytes())
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text)
            return subprocess.run(["bash", str(script)], capture_output=True, text=True, check=False)

    def assert_refused(self, result: subprocess.CompletedProcess, path: str) -> None:
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Core capability or receipt v1 contract remnants found:", result.stderr)
        self.assertIn("  %s:" % path, result.stderr)

    def test_exact_internal_authority_schema_in_real_auditor_is_allowed(self) -> None:
        result = self.gate(AUDITOR, (ROOT / AUDITOR).read_text())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_auditor_with_any_other_authority_schema_is_rejected(self) -> None:
        reviewed = '"chio.security-check-authority.v1"'
        text = (ROOT / AUDITOR).read_text()
        self.assertEqual(text.count(reviewed), 1)
        for version in (2, 4):
            with self.subTest(version=version):
                other = '"chio.security-check-authority.v%s"' % version
                self.assert_refused(self.gate(AUDITOR, text.replace(reviewed, other)), AUDITOR)

    def test_neighboring_authority_schema_versions_are_rejected(self) -> None:
        for version in (2, 4, 20, 30):
            with self.subTest(version=version):
                result = self.gate(AUDITOR, 'schema = "chio.security-check-authority.v%s"\n' % version)
                self.assert_refused(result, AUDITOR)

    def test_authority_schema_line_cannot_hide_adjacent_core_wire_remnants(self) -> None:
        for future in ('ReceiptV%s' % 2, 'CapabilityTokenV%s' % 2):
            with self.subTest(future=future):
                result = self.gate(AUDITOR, 'schema = "chio.security-check-authority.v1"; ' + future + '\n')
                self.assert_refused(result, AUDITOR)


if __name__ == "__main__":
    unittest.main()
