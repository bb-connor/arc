#!/usr/bin/env python3
"""Self-test for scripts/check-upstream-skips.sh."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-upstream-skips.sh"
TODAY = "2026-04-26"
PROG = "check-upstream-skips.sh"


def entry(
    target: str = "wasm_guard_escape",
    sunset: str = "2026-05-26",
    issue: str = "https://example.invalid/issues/1",
    reason: str = "upstream wasmtime instability",
) -> str:
    return (
        "[[skips]]\n"
        f'target = "{target}"\n'
        f'reason = "{reason}"\n'
        f'upstream_issue = "{issue}"\n'
        f'sunset = "{sunset}"\n'
    )


class UpstreamSkipsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-upstream-skips-")
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def run_check(self, text: str | None, *extra: str) -> subprocess.CompletedProcess[str]:
        table = self.dir / "upstream_skips.toml"
        if text is not None:
            table.write_text(text, encoding="utf-8")
        args = ["--file", str(table), "--today", TODAY, *extra]
        return subprocess.run(
            ["bash", "--noprofile", "--norc", str(SCRIPT), *args],
            cwd=self.dir,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_exit(self, result: subprocess.CompletedProcess[str], code: int, *messages: str) -> None:
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        for message in messages:
            self.assertIn(message, result.stderr)

    def test_green_valid_entry(self) -> None:
        result = self.run_check(entry())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            f"{PROG}: OK (1 valid skip entr(y/ies) in {self.dir}/upstream_skips.toml, today={TODAY})",
        )

    def test_green_empty_table_sentinel(self) -> None:
        result = self.run_check("# no skips\nskips = []\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("has no active skips", result.stdout)

    def test_green_sunset_boundaries(self) -> None:
        result = self.run_check(entry("a", sunset=TODAY) + entry("b", sunset="2026-07-25"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2 valid skip", result.stdout)

    def test_green_url_fragment_and_inline_comment(self) -> None:
        text = entry(issue="https://example.invalid/issues/1#issuecomment-2").replace(
            'sunset = "2026-05-26"', 'sunset = "2026-05-26" # trimmed'
        )
        result = self.run_check(text)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_green_dry_run_and_help(self) -> None:
        dry = self.run_check(None, "--dry-run")
        self.assertEqual(dry.returncode, 0)
        self.assertEqual(dry.stdout.strip(), f"{PROG}: dry-run OK")
        helped = self.run_check(None, "--help")
        self.assertEqual(helped.returncode, 0)
        self.assertIn("Usage: " + PROG, helped.stdout)

    def test_red_expired_sunset(self) -> None:
        result = self.run_check(entry(sunset="2026-04-25"))
        self.assert_exit(
            result,
            1,
            f"{PROG}: skip wasm_guard_escape: sunset 2026-04-25 has expired (today={TODAY}); remove or re-evaluate",
            f"{PROG}: FAIL: 1 problem(s) across 1 skip entr(y/ies)",
        )

    def test_red_sunset_more_than_90_days_out(self) -> None:
        result = self.run_check(entry(sunset="2026-07-26"))
        self.assert_exit(result, 1, "sunset 2026-07-26 is more than 90 days out")

    def test_red_sunset_not_a_date(self) -> None:
        for sunset in ("2026-13-45", "soon", "2026-5-1"):
            with self.subTest(sunset):
                result = self.run_check(entry(sunset=sunset))
                self.assert_exit(result, 1, f"sunset is not a valid YYYY-MM-DD: {sunset}")

    def test_red_issue_is_not_a_url(self) -> None:
        for issue in ("TODO", "ftp://example.invalid/1", "https://has space"):
            with self.subTest(issue):
                result = self.run_check(entry(issue=issue))
                self.assert_exit(result, 1, f"upstream_issue is not an http(s) URL: {issue}")

    def test_red_counts_every_problem(self) -> None:
        result = self.run_check(entry("a", sunset="2026-01-01") + entry("b", issue="nope"))
        self.assert_exit(result, 1, "FAIL: 2 problem(s) across 2 skip entr(y/ies)")

    def test_parse_error_missing_field(self) -> None:
        text = '[[skips]]\ntarget = "a"\nreason = "r"\nsunset = "2026-05-26"\n'
        self.assert_exit(self.run_check(text), 2, "parse error: missing field in [[skips]] entry", "FAIL (parse): 1 structural problem(s)")

    def test_parse_error_unknown_key(self) -> None:
        text = entry() + 'owner = "someone"\n'
        self.assert_exit(self.run_check(text), 2, "parse error: unknown key")

    def test_parse_error_misspelled_table_header(self) -> None:
        self.assert_exit(self.run_check(entry().replace("[[skips]]", "[[skip]]")), 2, "unknown top-level content")

    def test_parse_error_unparseable_line(self) -> None:
        self.assert_exit(self.run_check(entry() + "just words\n"), 2, "unparseable line in [[skips]] entry")

    def test_parse_error_takes_precedence_over_policy_error(self) -> None:
        text = entry(sunset="2026-01-01") + entry().replace("[[skips]]", "[[skip]]")
        result = self.run_check(text)
        self.assert_exit(result, 2, "FAIL (parse)")
        self.assertNotIn(f"{PROG}: FAIL:", result.stderr)

    def test_usage_errors(self) -> None:
        self.assert_exit(self.run_check(None, "--bogus"), 2, "unknown argument: --bogus")
        self.assert_exit(self.run_check(entry(), "--today", "tomorrow"), 2, "today value is not YYYY-MM-DD: tomorrow")
        missing = subprocess.run(
            ["bash", "--noprofile", "--norc", str(SCRIPT), "--file", str(self.dir / "absent.toml")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assert_exit(missing, 2, "skip table not found")
        dangling = subprocess.run(
            ["bash", "--noprofile", "--norc", str(SCRIPT), "--file"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assert_exit(dangling, 2, "--file requires an argument")


if __name__ == "__main__":
    unittest.main()
