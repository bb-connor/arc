#!/usr/bin/env python3
"""Self-test for scripts/check-receipt-trace-negative-registry.py."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-receipt-trace-negative-registry.py"
SPEC = importlib.util.spec_from_file_location("receipt_trace_negative", SCRIPT)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

NATIVE = "crates/tooling/chio-conformance/src/native_suite.rs"
NATIVE_TESTS = "crates/tooling/chio-conformance/src/native_suite/tests.rs"
CAPTURE = "crates/tooling/chio-trace-validate/src/capture.rs"
SOURCES = {
    NATIVE: "BlindRevocationStore AdmissionDroppingObserver",
    NATIVE_TESTS: "runtime_trace_refuses_a_dropped_admission_callback",
    CAPTURE: "DuplicateReceiptTime DepthAboveLimit FutureRevocationEpoch",
}
INVARIANTS = sorted(GATE.FORMAL_REJECTIONS)


def registry_text(cases: list[dict[str, str]], schema: str = "chio.runtime-trace-negative.v1") -> str:
    out = f'schema = "{schema}"\n'
    for case in cases:
        out += "\n[[case]]\n" + "".join(f"{key} = {json.dumps(value)}\n" for key, value in case.items())
    return out


def report(invariant: str) -> dict:
    return {
        "schema": "chio.trace-validation.v1",
        "status": "failed",
        "divergence": {"failedConjunct": invariant, "apalacheEvaluation": {invariant: False}},
    }


class ReceiptTraceNegativeRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-trace-negative-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write("registry.toml", registry_text(GATE.EXPECTED))
        for rel, text in SOURCES.items():
            self.write(rel, text)
        for invariant in INVARIANTS:
            self.write(f"{invariant}.json", json.dumps(report(invariant)))

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def run_check(self, reports: list[str] | None = None) -> subprocess.CompletedProcess[str]:
        reports = [f"{name}={name}.json" for name in INVARIANTS] if reports is None else reports
        args = [arg for item in reports for arg in ("--report", item)]
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--registry", "registry.toml", *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_red(self, message: str, reports: list[str] | None = None) -> None:
        result = self.run_check(reports)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stderr.strip(), f"receipt-trace-negative: {message}")

    def test_green(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_red_registry_schema(self) -> None:
        self.write("registry.toml", registry_text(GATE.EXPECTED, "chio.runtime-trace-negative.v2"))
        self.assert_red("registry schema is invalid")

    def test_red_registry_entry_changed(self) -> None:
        cases = [dict(case) for case in GATE.EXPECTED]
        cases[0]["fault"] = "edited"
        self.write("registry.toml", registry_text(cases))
        self.assert_red("registry entries are not exact")

    def test_red_registry_entry_removed(self) -> None:
        self.write("registry.toml", registry_text(GATE.EXPECTED[:-1]))
        self.assert_red("registry entries are not exact")

    def test_red_report_missing(self) -> None:
        self.assert_red("report set is not exact", [f"{name}={name}.json" for name in INVARIANTS[:-1]])

    def test_red_report_duplicated(self) -> None:
        reports = [f"{name}={name}.json" for name in INVARIANTS] + [f"{INVARIANTS[0]}={INVARIANTS[0]}.json"]
        self.assert_red("report set is not exact", reports)

    def test_red_report_schema(self) -> None:
        name = INVARIANTS[0]
        self.write(f"{name}.json", json.dumps({**report(name), "schema": "other"}))
        self.assert_red(f"{name} report schema is invalid")

    def test_red_mutation_not_rejected(self) -> None:
        name = INVARIANTS[1]
        self.write(f"{name}.json", json.dumps({**report(name), "status": "passed"}))
        self.assert_red(f"{name} mutation was not rejected")

    def test_red_wrong_invariant(self) -> None:
        name = INVARIANTS[2]
        self.write(f"{name}.json", json.dumps(report(INVARIANTS[0])))
        self.assert_red(f"{name} hit the wrong invariant")

    def test_red_missing_apalache_witness(self) -> None:
        name = INVARIANTS[3]
        broken = report(name)
        broken["divergence"]["apalacheEvaluation"] = {name: True}
        self.write(f"{name}.json", json.dumps(broken))
        self.assert_red(f"{name} lacks an Apalache witness")

    def test_red_missing_calibration_symbol(self) -> None:
        cases = [
            (NATIVE, "BlindRevocationStore"),
            (NATIVE_TESTS, "runtime_trace_refuses_a_dropped_admission_callback"),
            (NATIVE, "AdmissionDroppingObserver"),
            (CAPTURE, "DuplicateReceiptTime"),
            (CAPTURE, "DepthAboveLimit"),
            (CAPTURE, "FutureRevocationEpoch"),
        ]
        for rel, symbol in cases:
            with self.subTest(symbol):
                self.write(rel, SOURCES[rel].replace(symbol, "Renamed"))
                self.assert_red(f"missing calibration symbol {symbol}")
                self.write(rel, SOURCES[rel])

    def test_red_bad_report_argument(self) -> None:
        result = self.run_check(["Unknown=report.json"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("report must be INVARIANT=PATH", result.stderr)


if __name__ == "__main__":
    unittest.main()
