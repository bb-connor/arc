#!/usr/bin/env python3
"""Execute the thin-main version gate with exact schema and core-wire controls."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
GATE = Path(os.environ.get("CHIO_TRUSTED_MAIN_VERSION_GATE", ROOT / "scripts/check-chio-owned-v1-only.sh"))
AUDITOR = "scripts/audit-security-merge-qualification.py"


class TrustedMainCodegenTests(unittest.TestCase):
    def gate(self, path: str, text: str, recheck_error: bool = False) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory(prefix="chio-trusted-main-version-") as raw:
            root = Path(raw)
            for name in ("crates", "spec", "sdks", "scripts", "docs", "formal", "xtask"):
                (root / name).mkdir()
            script = root / "scripts/check-chio-owned-v1-only.sh"
            script.write_bytes(GATE.read_bytes())
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text)
            env = os.environ.copy()
            if recheck_error:
                real_rg = shutil.which("rg")
                self.assertIsNotNone(real_rg)
                tools = root / "test-tools"
                tools.mkdir()
                wrapper = tools / "rg"
                wrapper.write_text('#!/usr/bin/env python3\nimport os,sys\n'
                                   'if "-q" in sys.argv[1:]:\n'
                                   '    sys.stderr.write("simulated rg recheck failure\\n");sys.exit(2)\n'
                                   'os.execv(os.environ["REAL_RG"], [os.environ["REAL_RG"], *sys.argv[1:]])\n')
                wrapper.chmod(0o755)
                env.update(REAL_RG=real_rg, PATH=str(tools) + os.pathsep + env["PATH"])
            return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, check=False)

    def assert_refused(self, result: subprocess.CompletedProcess, path: str) -> None:
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Core capability or receipt v1 contract remnants found:", result.stderr)
        self.assertIn("  %s:" % path, result.stderr)

    def test_exact_internal_authority_schema_in_real_auditor_is_allowed(self) -> None:
        result = self.gate(AUDITOR, (ROOT / AUDITOR).read_text())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_auditor_with_any_other_authority_schema_is_rejected(self) -> None:
        reviewed = '"chio.security-check-authority.v3"'
        text = (ROOT / AUDITOR).read_text()
        self.assertEqual(text.count(reviewed), 1)
        for version in (2, 4):
            with self.subTest(version=version):
                other = '"chio.security-check-authority.v%s"' % version
                self.assert_refused(self.gate(AUDITOR, text.replace(reviewed, other)), AUDITOR)

    def test_same_literal_in_another_producer_is_rejected(self) -> None:
        result = self.gate("scripts/unreviewed-auditor.py", 'schema = "chio.security-check-authority.v3"\n')
        self.assert_refused(result, "scripts/unreviewed-auditor.py")

    def test_neighboring_authority_schema_versions_are_rejected(self) -> None:
        for version in (2, 4, 20, 30):
            with self.subTest(version=version):
                result = self.gate(AUDITOR, 'schema = "chio.security-check-authority.v%s"\n' % version)
                self.assert_refused(result, AUDITOR)

    def test_allowed_tag_cannot_hide_adjacent_core_wire_or_normative_claims(self) -> None:
        # Construct negative fixture text here. The actual producer keeps its
        # literal schema identifier unchanged.
        for future in ('ReceiptV%s' % 2, 'CapabilityTokenV%s' % 2, 'Current protocol is v%s' % 2):
            with self.subTest(future=future):
                result = self.gate(AUDITOR, 'schema = "chio.security-check-authority.v3"; ' + future + '\n')
                self.assert_refused(result, AUDITOR)

    def test_recheck_scanner_failure_is_propagated_instead_of_treated_as_clean(self) -> None:
        for extra in ('', '; ReceiptV%s' % 2):
            with self.subTest(extra=extra):
                result = self.gate(AUDITOR, 'schema = "chio.security-check-authority.v3"' + extra + '\n', recheck_error=True)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("ripgrep failed while rechecking the trusted auditor schema line", result.stderr)
                self.assertNotIn("Core capability and receipt surfaces remain v1-only.", result.stdout)


if __name__ == "__main__":
    unittest.main()
