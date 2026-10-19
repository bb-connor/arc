#!/usr/bin/env python3
"""Self-test for scripts/check-dudect-threshold.sh."""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-dudect-threshold.sh"
VERDICT = re.compile(r"^dudect verdict: max\|t\|=(\S+) threshold=(\S+) result=(PASS|FAIL)$")


def bench(*ts: str) -> str:
    out = "running 1 bench\nbench jwt_verify seeded with 0xdeadbeef\n"
    for t in ts:
        out += f"bench jwt_verify ... : n == +0.040M, max t = {t}, max tau = +1.0e-3\n"
    return out


class DudectThresholdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-dudect-")
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def run_check(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", str(SCRIPT), *args],
            cwd=self.dir,
            capture_output=True,
            text=True,
            check=False,
        )

    def verdict(self, text: str, *extra: str) -> subprocess.CompletedProcess[str]:
        path = self.dir / "dudect.out"
        path.write_text(text, encoding="utf-8")
        return self.run_check("--input", str(path), *extra)

    def assert_verdict(self, result: subprocess.CompletedProcess[str], code: int, outcome: str) -> float:
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        match = VERDICT.match(result.stdout.strip())
        self.assertIsNotNone(match, result.stdout)
        self.assertEqual(match.group(3), outcome)
        return float(match.group(1))

    def test_green_dry_run(self) -> None:
        result = self.run_check("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("dudect threshold script dry-run OK (parser max|t|=5.7321"), result.stdout)

    def test_green_under_threshold(self) -> None:
        peak = self.assert_verdict(self.verdict(bench("+2.13", "-3.9", "+1.0")), 0, "PASS")
        self.assertAlmostEqual(peak, 3.9)

    def test_green_borderline_value_is_not_rounded_up(self) -> None:
        self.assert_verdict(self.verdict(bench("+4.49996")), 0, "PASS")

    def test_red_over_threshold(self) -> None:
        peak = self.assert_verdict(self.verdict(bench("+2.0", "+61.61472")), 1, "FAIL")
        self.assertAlmostEqual(peak, 61.61472, places=4)

    def test_red_negative_statistic_counts_by_magnitude(self) -> None:
        peak = self.assert_verdict(self.verdict(bench("+1.0", "-7.25")), 1, "FAIL")
        self.assertAlmostEqual(peak, 7.25)

    def test_red_value_equal_to_threshold_fails(self) -> None:
        self.assert_verdict(self.verdict(bench("+4.5")), 1, "FAIL")

    def test_red_exponent_notation(self) -> None:
        self.assert_verdict(self.verdict(bench("+1.0e1")), 1, "FAIL")

    def test_custom_threshold(self) -> None:
        self.assert_verdict(self.verdict(bench("+6.0"), "--threshold", "10"), 0, "PASS")
        self.assert_verdict(self.verdict(bench("+6.0"), "--threshold", "5.5"), 1, "FAIL")

    def test_precondition_invalid_threshold(self) -> None:
        for bad in ("abc", "0", "-1", "", "4.5.1"):
            with self.subTest(bad):
                result = self.verdict(bench("+1.0"), "--threshold", bad)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn(f"--threshold must be a strictly-positive number; got '{bad}'", result.stderr)

    def test_precondition_no_statistics(self) -> None:
        result = self.verdict("running 0 benches\n")
        self.assertEqual(result.returncode, 2)
        self.assertIn("no 'max t = <float>' lines found", result.stderr)

    def test_precondition_missing_input_file(self) -> None:
        result = self.run_check("--input", str(self.dir / "absent.out"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("input file not readable", result.stderr)

    def test_precondition_argument_errors(self) -> None:
        cases = (
            ((), "Usage:"),
            (("--bogus",), "unknown argument: --bogus"),
            (("--input",), "--input requires a path argument"),
            (("--threshold",), "--threshold requires a numeric argument"),
            (("--threshold", "4.5"), "missing --input <file> (or pass --dry-run for the self-test)"),
        )
        for args, message in cases:
            with self.subTest(args):
                result = self.run_check(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)

    def test_help(self) -> None:
        result = self.run_check("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("check-dudect-threshold.sh --dry-run", result.stdout)


if __name__ == "__main__":
    unittest.main()
