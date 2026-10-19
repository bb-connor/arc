#!/usr/bin/env python3
"""Self-test for scripts/check-release-inputs.sh.

The script pins the SHA-256 of the HITRUST readiness package. The temp tree
rewrites that constant in its copy of the script to the hash of the fixture
package, so the hash-mismatch path is exercised without the real package.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-release-inputs.sh"
PACKAGE = "compliance/hitrust/readiness-package/readiness-package.md"
INDEX = "docs/external-attestation/hitrust-i1/index.md"
PACKAGE_TEXT = "HITRUST i1 readiness package\nreadiness only\n"
INDEX_TEXT = "HITRUST i1 readiness index\n"
DIGEST = hashlib.sha256(PACKAGE_TEXT.encode()).hexdigest()


def releases(digest: str = DIGEST, m08: bool = True, m09: bool = True) -> str:
    out = ""
    if m08:
        out += "m08_internal_readiness_draft: draft\n"
    if m09:
        out += f"m09_hitrust_i1_readiness_package:\n  package_sha256: {digest}\n"
    return out


class ReleaseInputsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-release-inputs-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q", "--initial-branch=main")
        (self.repo / "scripts").mkdir()
        script = SCRIPT.read_text(encoding="utf-8")
        pinned, count = re.subn(r'm09_package_sha256="[0-9a-f]{64}"', f'm09_package_sha256="{DIGEST}"', script)
        self.assertEqual(count, 1)
        (self.repo / "scripts" / SCRIPT.name).write_text(pinned, encoding="utf-8")
        self.track("releases.toml", releases())
        self.track(PACKAGE, PACKAGE_TEXT)
        self.track(INDEX, INDEX_TEXT + "readiness\n")

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    def track(self, rel: str, text: str) -> None:
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.git("add", "--", rel)

    def run_check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "scripts/check-release-inputs.sh"],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_red(self, message: str) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(result.stderr.strip().splitlines()[0], message)

    def test_green(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "release input inventory clean")

    def test_green_untracked_artifacts_are_ignored(self) -> None:
        path = self.repo / "sdks/typescript/chio-ts/dist/index.js"
        path.parent.mkdir(parents=True)
        path.write_text("x", encoding="utf-8")
        self.assertEqual(self.run_check().returncode, 0)

    def test_red_tracked_generated_or_cache_artifacts(self) -> None:
        for rel in (
            "pkg/__pycache__/mod.cpython-312.pyc",
            "pkg/mod.pyc",
            "pkg/mod.pyo",
            "pkg/mod.pyd",
            "sdks/python/chio-py/build/lib/x.py",
            "sdks/python/chio-py/src/chio.egg-info",
            "sdks/python/chio-py/src/chio.egg-info/PKG-INFO",
            "sdks/typescript/chio-ts/dist/index.js",
            "sdks/typescript/chio-ts/node_modules/x/index.js",
            "crates/products/chio-cli/dashboard/dist/app.js",
            "crates/products/chio-cli/dashboard/node_modules/x.js",
            "tests/conformance/results/generated/r.json",
            "tests/conformance/reports/generated/r.md",
        ):
            with self.subTest(rel):
                self.track(rel, "x")
                result = self.run_check()
                self.assertEqual(result.returncode, 1)
                self.assertEqual(
                    result.stderr.strip().splitlines(),
                    ["tracked generated or cache artifacts must not be part of release inputs:", f"  {rel}"],
                )
                self.git("rm", "-q", "--cached", "--", rel)
                (self.repo / rel).unlink()

    def test_red_missing_m08_key(self) -> None:
        self.track("releases.toml", releases(m08=False))
        self.assert_red("release-audit evidence must use the m08_internal_readiness_draft key")

    def test_red_missing_m09_key(self) -> None:
        self.track("releases.toml", releases(m09=False))
        self.assert_red("HITRUST readiness evidence must use the m09_hitrust_i1_readiness_package key")

    def test_red_hash_not_pinned_in_releases(self) -> None:
        self.track("releases.toml", releases(digest="0" * 64))
        self.assert_red("HITRUST readiness package hash is not pinned in releases.toml")

    def test_red_package_hash_mismatch(self) -> None:
        self.track(PACKAGE, PACKAGE_TEXT + "edited\n")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertTrue(
            result.stderr.startswith(f"HITRUST readiness package hash mismatch: expected {DIGEST}, got "),
            result.stderr,
        )

    def test_red_evidence_file_missing(self) -> None:
        (self.repo / INDEX).unlink()
        self.assert_red(f"missing HITRUST readiness evidence file: {INDEX}")

    def test_red_stale_issued_certificate_wording(self) -> None:
        for phrase in ("Certificate received", "HITRUST QA round", "mycsf://x", "issued 2026-05-02", "Assessor identity"):
            with self.subTest(phrase):
                self.track(INDEX, f"readiness\n{phrase}\n")
                result = self.run_check()
                self.assertEqual(result.returncode, 1)
                self.assertIn(
                    f"HITRUST readiness evidence must remain readiness-only; stale issued-certificate wording found in {INDEX}:",
                    result.stderr,
                )
                self.assertIn(phrase.lower(), result.stderr.lower())

    def test_red_index_without_readiness_wording(self) -> None:
        self.track(INDEX, "attested\n")
        self.assert_red(f"HITRUST readiness evidence must state readiness-only wording: {INDEX}")


if __name__ == "__main__":
    unittest.main()
