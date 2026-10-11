#!/usr/bin/env python3
"""The solver runner must reject vacuity and failed negative calibration."""
import importlib.util
from pathlib import Path
import sys
import unittest
import z3

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
spec = importlib.util.spec_from_file_location("progress", Path(__file__).resolve().parents[1] / "check-revocation-progress.py")
progress = importlib.util.module_from_spec(spec)
spec.loader.exec_module(progress)


class VerdictTests(unittest.TestCase):
    def test_vacuity_is_failure(self):
        report, _ = progress.check(z3.BoolVal(False), z3.BoolVal(True), False)
        self.assertFalse(report["passed"])

    def test_negative_requires_a_real_counterexample(self):
        report, _ = progress.check(z3.BoolVal(True), z3.BoolVal(True), True)
        self.assertFalse(report["passed"])
        report, model = progress.check(z3.BoolVal(True), z3.BoolVal(False), True)
        self.assertTrue(report["passed"])
        self.assertIsNotNone(model)


if __name__ == "__main__":
    unittest.main()
