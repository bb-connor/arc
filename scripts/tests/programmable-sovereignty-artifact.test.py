#!/usr/bin/env python3
"""Exercise historical artifact validation with real retained data and Git objects."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path("scripts/generate-programmable-sovereignty-artifact.py")
SPEC = importlib.util.spec_from_file_location("sovereignty_artifact", ROOT / SCRIPT)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
PAPER = Path(CHECKER.PAPER_PREFIX)
PIN = PAPER / "supplementary/source-commit.txt"
ASSEMBLY_PIN = PAPER / "supplementary/artifact-commit.txt"
MANIFEST = PAPER / "supplementary/artifact-manifest.json"


class HistoricalArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory(prefix="chio-historical-fixture-")
        cls.addClassCleanup(cls.fixture.cleanup)
        cls.base = Path(cls.fixture.name)
        shutil.copytree(ROOT / PAPER, cls.base / PAPER)
        for relative in [*CHECKER.snapshot_paths(), "rust-toolchain.toml"]:
            destination = cls.base / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        shutil.copytree(ROOT / "formal/lean4", cls.base / "formal/lean4",
                        dirs_exist_ok=True, ignore=shutil.ignore_patterns(".lake"))
        subprocess.run(["git", "init", "-q", str(cls.base)], check=True)
        objects = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "--git-path", "objects"],
            text=True,
        ).strip()
        object_path = (ROOT / objects).resolve()
        (cls.base / ".git/objects/info/alternates").write_text(f"{object_path}\n")
        cls.current_commit = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True,
        ).strip()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="chio-historical-test-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        shutil.copytree(self.base, self.repo, dirs_exist_ok=True)

    def run_checker(self, *args):
        return subprocess.run(
            [sys.executable, str(self.repo / SCRIPT), *args],
            cwd=self.repo, capture_output=True, text=True, check=False,
        )

    def require_rejection(self, diagnostic, *args):
        result = self.run_checker("--check-historical", *args)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(diagnostic, result.stderr)

    def paper_hashes(self):
        return {
            path.relative_to(self.repo): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (self.repo / PAPER).rglob("*") if path.is_file()
        }

    def test_historical_check_uses_original_sources_and_preserves_all_outputs(self):
        for relative in CHECKER.snapshot_paths():
            if CHECKER.is_pinned_input(relative) and Path(relative) != SCRIPT:
                (self.repo / relative).write_text("changed current source\n")
        (self.repo / "formal/lean4/Chio/Chio/NewCurrentModel.lean").write_text(
            "this new model is not part of the historical artifact\n"
        )
        before = self.paper_hashes()
        result = self.run_checker("--check-historical")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("historical", result.stdout)
        self.assertEqual(self.paper_hashes(), before)

    def test_strict_check_still_rejects_changed_current_source(self):
        relative = "crates/kernel/chio-runtime-core/src/admission_hook.rs"
        with (self.repo / relative).open("a") as stream:
            stream.write("\n// a later source revision\n")
        result = self.run_checker("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"working artifact differs from pinned commit at {relative}",
                      result.stderr)

    def test_current_manuscript_and_pdf_drift_are_rejected(self):
        for relative in ("sections/01-introduction.tex", "paper-usenix.pdf"):
            with self.subTest(path=relative):
                path = self.repo / PAPER / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n% changed current artifact\n")
                self.require_rejection("artifact-manifest.json")
                path.write_bytes(original)

    def test_changed_raw_result_bytes_are_rejected(self):
        path = self.repo / PAPER / "bench/results/bilateral-admission-raw.csv"
        path.write_bytes(path.read_bytes() + b"\n")
        self.require_rejection("artifact-manifest.json")

    def test_current_summary_still_must_match_its_inline_measurements(self):
        path = self.repo / CHECKER.BILATERAL_SUMMARY
        result = json.loads(path.read_text())
        result["samples"] += 1
        path.write_text(json.dumps(result))
        self.require_rejection("differs from the macros rendered")

    def test_manifest_hash_and_metadata_tampering_are_rejected(self):
        path = self.repo / MANIFEST
        original = path.read_bytes()
        for field in ("sourceFiles", "source", "behavioralTests"):
            with self.subTest(field=field):
                manifest = json.loads(original)
                del manifest[field]
                path.write_text(json.dumps(manifest))
                self.require_rejection("artifact-manifest.json")
        path.write_bytes(original)

    def test_manifest_aggregate_must_be_recomputed_from_the_real_bound_files(self):
        path = self.repo / MANIFEST
        original = path.read_bytes()
        for digest in ("0" * 64,
                       "418d07c3038ca7e54d3b2f98ba5f2b7b9db66fe4df73d9a0f3ff85d7cf88e63a"):
            with self.subTest(digest=digest):
                manifest = json.loads(original)
                manifest["source"]["contentSetSha256"] = digest
                path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
                self.require_rejection("artifact-manifest.json")

    def test_retained_lean_archive_bytes_cannot_change(self):
        path = self.repo / PAPER / "supplementary/lean-source.tar.gz"
        path.write_bytes(path.read_bytes() + b"\n")
        self.require_rejection("lean-source.tar.gz")

    def test_invalid_missing_or_unavailable_pin_never_falls_back_to_head(self):
        path = self.repo / PIN
        original = path.read_bytes()
        for pin, diagnostic in (("HEAD", "source commit is not a full SHA"),
                                ("0" * 40, "not available in local repository history")):
            with self.subTest(pin=pin):
                path.write_text(f"{pin}\n")
                self.require_rejection(diagnostic)
        path.unlink()
        self.require_rejection("source-commit.txt")
        path.write_bytes(original)

    def test_producer_must_exist_and_match_the_recorded_input_tree(self):
        path = self.repo / CHECKER.BILATERAL_SUMMARY
        original = path.read_bytes()
        for producer, diagnostic in (("0" * 40, "provenance commit is unavailable"),
                                      (self.current_commit, "does not match its producer")):
            with self.subTest(producer=producer):
                result = json.loads(original)
                result["commit"] = producer
                path.write_text(json.dumps(result))
                self.require_rejection(diagnostic)

    def test_input_digest_must_match_real_producer_objects(self):
        path = self.repo / CHECKER.BILATERAL_SUMMARY
        result = json.loads(path.read_text())
        result["benchmarkInputTreeSha256"] = "0" * 64
        path.write_text(json.dumps(result))
        self.require_rejection("result input digest does not match its producer")

    def test_artifact_assembly_pin_must_be_available_and_bind_the_source_pin(self):
        pin = self.repo / ASSEMBLY_PIN
        original = pin.read_bytes()
        for value, diagnostic in (("HEAD", "artifact commit is not a full SHA"),
                                  ("0" * 40, "artifact commit is not available")):
            with self.subTest(pin=value):
                pin.write_text(value + "\n")
                self.require_rejection(diagnostic)
        pin.unlink()
        self.require_rejection("artifact-commit.txt")
        pin.write_bytes(original)
        (self.repo / PIN).write_text(self.current_commit + "\n")
        self.require_rejection("source-commit.txt differs from the artifact assembly")

    def test_inline_renderer_accepts_only_v2_or_complete_v3_results(self):
        path = self.repo / CHECKER.BILATERAL_SUMMARY
        original = json.loads(path.read_text())
        result = self.run_checker("--render-inline", str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, (self.repo / CHECKER.BILATERAL_INLINE).read_text())
        original["schema"] = "chio.programmable-sovereignty.bilateral-admission-results.v3"
        original["sustainedLoad"].update(concurrency=4, bottleneck={"classification": "host_cpu"})
        path.write_text(json.dumps(original))
        result = self.run_checker("--render-inline", str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("\\newcommand{\\PSSustainedConcurrency}{4}", result.stdout)
        for field in ("concurrency", "bottleneck"):
            with self.subTest(field=field):
                document = json.loads(json.dumps(original))
                del document["sustainedLoad"][field]
                path.write_text(json.dumps(document))
                result = self.run_checker("--render-inline", str(path))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(field, result.stderr)

    def test_unknown_result_schema_is_rejected_even_with_valid_v3_fields(self):
        path = self.repo / CHECKER.BILATERAL_SUMMARY
        document = json.loads(path.read_text())
        document["schema"] = "chio.programmable-sovereignty.bilateral-admission-results.v4"
        document["sustainedLoad"].update(concurrency=4, bottleneck={"classification": "host_cpu"})
        path.write_text(json.dumps(document))
        result = self.run_checker("--render-inline", str(path))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported bilateral result schema", result.stderr)

    def test_historical_mode_cannot_repin_or_write_measurements(self):
        before = self.paper_hashes()
        for args in (("--source-commit", self.current_commit),
                     ("--write-measurements", CHECKER.BILATERAL_SUMMARY),
                     ("--check",)):
            with self.subTest(args=args):
                result = self.run_checker("--check-historical", *args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(self.paper_hashes(), before)


if __name__ == "__main__":
    unittest.main()
