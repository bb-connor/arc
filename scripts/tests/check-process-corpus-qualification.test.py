#!/usr/bin/env python3
"""Exercise mandatory corpus loading outside the source tree and schema CI mode."""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "spec/fixtures/chio-process-v1.json"


class InstalledCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="chio-corpus-qualification-")
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.work = Path(cls.workspace.name)
        environment = cls.work / "venv"
        venv.EnvBuilder(with_pip=False).create(environment)
        cls.python = environment / "bin/python"
        site = Path(
            subprocess.check_output(
                [
                    str(cls.python),
                    "-I",
                    "-c",
                    'import sysconfig; print(sysconfig.get_path("purelib"))',
                ],
                text=True,
            ).strip()
        )
        shutil.copytree(
            ROOT / "sdks/python/chio-process/src/chio_process",
            site / "chio_process",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        tests = cls.work / "python-tests"
        tests.mkdir()
        cls.python_test = tests / "test_protocol_corpus.py"
        shutil.copy2(
            ROOT / "sdks/python/chio-process/tests/test_protocol_corpus.py",
            cls.python_test,
        )
        cls.node_package = cls.work / "node_modules/@chio-protocol/process"
        (cls.node_package / "test").mkdir(parents=True)
        for name in (
            "index.mjs",
            "index.d.ts",
            "package.json",
            "test/protocol-corpus.test.mjs",
        ):
            shutil.copy2(
                ROOT / "sdks/typescript/packages/process" / name,
                cls.node_package / name,
            )
        cls.environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("PYTHON", "NODE_", "CHIO_PROCESS_"))
        }

    def consumer(
        self, language, *, corpus=None, require_schemas=False, environment=None
    ):
        env = dict(self.environment if environment is None else environment)
        if corpus is not None:
            env["CHIO_PROCESS_PROTOCOL_CORPUS"] = str(corpus)
        if require_schemas:
            env["CHIO_PROCESS_REQUIRE_SCHEMA_VALIDATION"] = "1"
        if language == "python":
            selection = "SchemaCorpusTests" if require_schemas else "ClientCorpusTests"
            argv = [str(self.python), "-I", str(self.python_test), selection, "-v"]
        else:
            argv = [
                "node",
                "--test",
                "--test-reporter=tap",
                str(self.node_package / "test/protocol-corpus.test.mjs"),
            ]
        return subprocess.run(
            argv, cwd=self.work, env=env, capture_output=True, text=True, timeout=60
        )

    def test_absent_corpus_is_an_error_instead_of_a_successful_skip(self):
        for language in ("python", "node"):
            with self.subTest(language=language):
                result = self.consumer(language)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("shared protocol corpus", result.stdout + result.stderr)

    def test_configured_missing_corpus_fails(self):
        for language in ("python", "node"):
            with self.subTest(language=language):
                result = self.consumer(language, corpus=self.work / "absent.json")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("absent.json", result.stdout + result.stderr)

    def test_bound_corpus_runs_both_client_suites_outside_the_checkout(self):
        for language in ("python", "node"):
            with self.subTest(language=language):
                result = self.consumer(language, corpus=CORPUS)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                if language == "python":
                    self.assertIn("Ran 3 tests", result.stderr)
                    self.assertNotIn("skipped=", result.stderr)
                else:
                    self.assertIn("# skipped 0", result.stdout)
                    count = len(json.loads(CORPUS.read_text())["client"]["cases"]) + 1
                    self.assertIn(f"# pass {count}", result.stdout)

    def test_qualifier_overrides_stale_corpus_and_binds_its_identity(self):
        spec = importlib.util.spec_from_file_location(
            "process_qualification", ROOT / "scripts/qualify-process-packages.py"
        )
        qualifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(qualifier)
        env = {
            **self.environment,
            "CHIO_PROCESS_PROTOCOL_CORPUS": str(self.work / "stale.json"),
        }
        bound, identity = qualifier.protocol_test_environment(env)
        self.assertEqual(
            env["CHIO_PROCESS_PROTOCOL_CORPUS"], str(self.work / "stale.json")
        )
        self.assertEqual(bound["CHIO_PROCESS_PROTOCOL_CORPUS"], str(CORPUS))
        self.assertEqual(identity["path"], "spec/fixtures/chio-process-v1.json")
        self.assertEqual(
            identity["sha256"], hashlib.sha256(CORPUS.read_bytes()).hexdigest()
        )
        expected_blob = subprocess.check_output(
            ["git", "hash-object", "--", str(CORPUS)], cwd=ROOT, text=True
        ).strip()
        self.assertEqual(identity["git_blob"], expected_blob)
        for language in ("python", "node"):
            with self.subTest(language=language):
                result = self.consumer(language, environment=bound)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_required_schema_validation_refuses_missing_dependency(self):
        result = self.consumer("python", corpus=CORPUS, require_schemas=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("jsonschema", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
