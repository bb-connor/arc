#!/usr/bin/env python3
"""Exercise real compiler diagnostics, including a new site inside an allow."""

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-aws-lc-lints.py"
SPEC = importlib.util.spec_from_file_location("lint_check", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
SOURCE = '''#![deny(clippy::unwrap_used, clippy::expect_used)]
#[allow(clippy::unwrap_used)]
pub fn compatibility(value: Option<u8>) -> u8 { value.unwrap() }
#[cfg(feature = "legacy-des")]
#[allow(clippy::unwrap_used)]
pub fn legacy(value: Option<u8>) -> u8 { value.unwrap() }
'''


class CompilerBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="chio-lint-controls-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        (cls.root / "src").mkdir()
        (cls.root / "src/lib.rs").write_text(SOURCE)
        (cls.root / "build.rs").write_text(CHECK.FLOOR + "\nfn main() {}\n")
        (cls.root / "Cargo.toml").write_text(
            '[package]\nname="lint-boundary-fixture"\nversion="0.0.0"\nedition="2021"\n'
            '[features]\nlegacy-des=[]\nfips=[]\nalloc=[]\nring-io=[]\nring-sig-verify=[]\n'
        )
        (cls.root / "Cargo.lock").write_text(
            'version = 3\n[[package]]\nname = "lint-boundary-fixture"\nversion = "0.0.0"\n'
        )
        # A /tmp fixture has no repository ancestor, so explicitly retain the
        # candidate's active toolchain instead of silently using rustup's default.
        toolchain = subprocess.check_output(
            ["rustup", "show", "active-toolchain"], cwd=SCRIPT.parent.parent, text=True,
        ).split()[0]
        cls.env = dict(os.environ, CARGO_TARGET_DIR=str(cls.root / "target"),
                       CARGO_TERM_COLOR="never", RUSTUP_TOOLCHAIN=toolchain)

    def setUp(self):
        (self.root / "src/lib.rs").write_text(SOURCE)
        (self.root / "build.rs").write_text(CHECK.FLOOR + "\nfn main() {}\n")
        sites = []
        start = 0
        while (start := SOURCE.find("value.unwrap()", start)) != -1:
            sites.append([start, start + len("value.unwrap()")])
            start += 1
        self.record = {
            "schema": "chio.aws-lc-lint-exceptions.v1", "profiles": CHECK.PROFILES,
            "files": {p: hashlib.sha256((self.root / p).read_bytes()).hexdigest()
                      for p in ("src/lib.rs", "build.rs")},
            "exceptions": [{
                "id": "fixture", "item": "two compatibility functions", "file": "src/lib.rs",
                "lint": "clippy::unwrap_used", "rationale": "test-only intentional panic contract",
                "sites": {"default-legacy": sites, "fips": sites[:1]},
            }],
        }

    def compile(self, *, force_warn=True, legacy=True):
        args = ["cargo", "clippy", "--offline", "--locked", "--lib", "--message-format=json"]
        if legacy:
            args += ["--features", "legacy-des"]
        args += ["--"]
        for lint in CHECK.LINTS:
            args += ["--force-warn" if force_warn else "--deny", lint]
        result = subprocess.run(args, cwd=self.root, env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result, CHECK.diagnostics(result.stdout, self.root)

    def test_reviewed_sites_match_real_compiler_in_both_feature_selections(self):
        CHECK.verify_source(self.root, self.record)
        for profile, legacy in (("default-legacy", True), ("fips", False)):
            result, actual = self.compile(legacy=legacy)
            self.assertEqual(result.returncode, 0, result.stderr)
            CHECK.verify_diagnostics(actual, self.record, profile)

    def test_new_unallowed_site_fails_normal_clippy(self):
        (self.root / "src/lib.rs").write_text(SOURCE + '\npub fn added(v: Option<u8>) -> u8 { v.unwrap() }\n')
        result, _ = self.compile(force_warn=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("clippy::unwrap_used", result.stdout)

    def test_new_site_inside_existing_allow_is_rejected_even_when_compiler_succeeds(self):
        (self.root / "src/lib.rs").write_text(SOURCE.replace(
            '{ value.unwrap() }', '{ let _ = value.unwrap(); value.unwrap() }', 1))
        result, actual = self.compile()
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaisesRegex(CHECK.LintPolicyError, "lint sites differ"):
            CHECK.verify_diagnostics(actual, self.record, "default-legacy")

    def test_legacy_only_added_site_is_measured(self):
        (self.root / "src/lib.rs").write_text(SOURCE.replace(
            'pub fn legacy(value: Option<u8>) -> u8 { value.unwrap() }',
            'pub fn legacy(value: Option<u8>) -> u8 { let _ = value.unwrap(); value.unwrap() }'))
        result, actual = self.compile(legacy=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        CHECK.verify_diagnostics(actual, self.record, "fips")
        result, actual = self.compile()
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaisesRegex(CHECK.LintPolicyError, "lint sites differ"):
            CHECK.verify_diagnostics(actual, self.record, "default-legacy")

    def test_removed_deny_and_broadened_allow_are_rejected(self):
        for source in (SOURCE.replace(CHECK.FLOOR, ""),
                       SOURCE.replace('#[allow(clippy::unwrap_used)]',
                                      '#![allow(clippy::unwrap_used)]', 1)):
            with self.subTest(source=source):
                (self.root / "src/lib.rs").write_text(source)
                with self.assertRaises(CHECK.LintPolicyError):
                    CHECK.verify_source(self.root, self.record)

    def test_build_script_cannot_drop_its_deny_floor(self):
        (self.root / "build.rs").write_text('fn main() {}\n')
        with self.assertRaisesRegex(CHECK.LintPolicyError, "deny floor missing"):
            CHECK.verify_source(self.root, self.record)

    def test_missing_measurement_and_duplicate_dispositions_are_rejected(self):
        for mutation in ("missing-sites", "duplicate"):
            record = copy.deepcopy(self.record)
            if mutation == "missing-sites":
                record["exceptions"][0]["sites"] = {}
            else:
                record["exceptions"] *= 2
            with self.subTest(mutation=mutation), self.assertRaises(CHECK.LintPolicyError):
                CHECK.verify_source(self.root, record)


if __name__ == "__main__":
    unittest.main()
