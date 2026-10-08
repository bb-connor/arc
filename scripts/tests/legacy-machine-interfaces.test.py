#!/usr/bin/env python3
"""Persisted compatibility names retain their existing behavioral meaning."""

import ast
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def embedded_python(path, invocation):
    source = path.read_text(encoding="utf-8")
    start = source.index(invocation) + len(invocation)
    return source[start:source.index("\nPY\n", start)]


class PersistedCompatibilityTests(unittest.TestCase):
    def check_corpus_source(self, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "scripts/check-corpus-metadata.sh"
            script.parent.mkdir()
            shutil.copy2(ROOT / "scripts/check-corpus-metadata.sh", script)
            seed = root / "fuzz/corpus/policy/sample.json"
            seed.parent.mkdir(parents=True)
            seed.write_bytes(b'{"decision":"deny"}')
            digest = hashlib.sha256(seed.read_bytes()).hexdigest()
            metadata = root / "fuzz/corpus_metadata.toml"
            metadata.write_text(
                'schema_version = 1\n[[seed]]\ntarget = "policy"\n'
                'path = "fuzz/corpus/policy/sample.json"\n'
                f'sha256 = "{digest}"\nsource = "{source}"\n',
                encoding="utf-8",
            )
            before = metadata.read_bytes()
            result = subprocess.run(
                ["bash", str(script)], capture_output=True, text=True,
                check=False, timeout=10,
            )
            self.assertEqual(metadata.read_bytes(), before)
            return result

    def test_policy_corpus_accepts_the_retained_source_name(self):
        result = self.check_corpus_source("m03_counterexample")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sdk_corpus_accepts_the_retained_source_name(self):
        result = self.check_corpus_source("m02_verdict_divergence")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_corpus_accepts_the_behavioral_source_names(self):
        for source in ["policy_counterexample", "sdk_verdict_divergence"]:
            with self.subTest(source=source):
                result = self.check_corpus_source(source)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_corpus_still_refuses_an_unknown_source(self):
        result = self.check_corpus_source("unknown_source")
        self.assertEqual(result.returncode, 1)
        self.assertIn("source 'unknown_source'", result.stderr)

    def test_bilateral_report_keeps_the_retained_key_and_false_trigger(self):
        script = ROOT / "scripts/qualify-cognition-market.sh"
        invocation = 'python3 - "${candidate_sha}" "${gate_index}" "${report_path}" <<\'PY\'\n'
        source = embedded_python(script, invocation)
        # Exercise the actual report writer with modeled input artifacts. This
        # tests report compatibility and supplies no native qualification.
        expected = next(
            ast.literal_eval(node.value)
            for node in ast.parse(source).body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "expected_dogfood"
                    for target in node.targets)
        )
        for field in ["findingId", "payloadSha256", "purchaseRecordSha256"]:
            expected[field] = "a" * 64
        for field in ["purchaseRequestId", "reservationId", "deliveryReceiptId"]:
            expected[field] = "modeled-compatibility-fixture"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "logs/public-purchase-route.log"
            log.parent.mkdir()
            log.write_text("cognition-market-dogfood-result " + json.dumps(expected) + "\n")
            index = root / "gate-index.tsv"
            index.write_text("public-purchase-route\tlogs/public-purchase-route.log\tmodeled fixture\n")
            report = root / "qualification.json"
            result = subprocess.run(
                [sys.executable, "-", "b" * 40, str(index), str(report)],
                input=source, capture_output=True, text=True, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(report.read_bytes())
            self.assertIn("m7", value)
            self.assertEqual(value["m7"], value["bilateral_deployment"])
            self.assertIs(value["m7"]["triggered"], False)

    def test_reference_run_keeps_both_incomplete_qualification_keys(self):
        path = ROOT / "examples/reference-swarm/process-run.py"
        spec = importlib.util.spec_from_file_location("reference_process_run", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, output = root / "state", root / "output"
            state.mkdir()
            (state / "swarm-calls.json").write_text(json.dumps({
                "schema": "chio.process.swarm-calls.v1", "calls": [],
                "runtime_id": "modeled-runtime",
            }))
            (state / "authority.db.kernel.pub").write_text("modeled-key")
            (state / "swarm-bootstrap.json").write_text(json.dumps({
                "action": {"parameters": {"capabilities": {}}},
            }))
            (state / "host.json").write_text(json.dumps({"config": {"servers": []}}))
            chio = root / "modeled-chio"
            chio.write_text("modeled native transcript only")
            completed = subprocess.CompletedProcess([], 0, '{"complete":true}', "")
            previous_umask = os.umask(0o077)
            try:
                with patch.object(module.sys, "argv", [str(path), "--chio", str(chio),
                                                       "--state", str(state), "--output", str(output)]), \
                     patch.object(module.sys, "platform", "linux"), \
                     patch.object(module.subprocess, "run", return_value=completed), \
                     patch.object(module, "run", side_effect=[{}, {"verified": True}]), \
                     redirect_stdout(io.StringIO()) as stdout:
                    module.main()
            finally:
                os.umask(previous_umask)
            report = json.loads((output / "run.json").read_bytes())
            self.assertEqual(report, json.loads(stdout.getvalue()))
            self.assertIs(report["qualification_complete"], False)
            self.assertIn("m5_acceptance_complete", report)
            self.assertIs(report["m5_acceptance_complete"], False)


if __name__ == "__main__":
    unittest.main()
