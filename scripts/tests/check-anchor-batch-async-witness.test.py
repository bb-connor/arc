#!/usr/bin/env python3
"""Self-test for scripts/check-anchor-batch-async-witness.sh."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-anchor-batch-async-witness.sh"
LIB = "crates/economy/chio-demo/src/lib.rs"
CALL = "    let r = verify_anchor_batch_with_witness_policy(&batch, &policy);"
TRUE = "    let policy = WitnessPolicy { require_public_witness: true };"
PREFIX = "[PUBLIC-WITNESS-LINT]"


def source(*lines: str, gap: int = 0, call_first: bool = False) -> str:
    """Lines around a call, separated by `gap` filler lines."""
    filler = ["    let _ = 0;"] * gap
    body = [CALL, *filler, *lines] if call_first else [*lines, *filler, CALL]
    return "fn go() {\n" + "\n".join(body) + "\n}\n"


class AnchorBatchAsyncWitnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-anchor-witness-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts" / SCRIPT.name)
        self.write("crates/economy/chio-demo/src/other.rs", "fn ok() {}\n")

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def run_check(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "scripts/check-anchor-batch-async-witness.sh", *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_flagged(self, result: subprocess.CompletedProcess[str], *sites: str) -> None:
        self.assertEqual(result.returncode, 1, result.stdout)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], f"{PREFIX} anchor-batch async-witness gate FAILED:")
        flagged = [line for line in lines if "sync wrapper called near literal" in line]
        self.assertEqual(len(flagged), len(sites), result.stdout)
        for line, site in zip(flagged, sites):
            self.assertTrue(line.startswith(f"  {PREFIX} {site}: sync wrapper called near literal"), line)

    def test_green_call_without_strict_policy(self) -> None:
        self.write(LIB, source("    let policy = WitnessPolicy::advisory();"))
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[0], f"{PREFIX} anchor-batch async-witness lint passed")

    def test_green_advisory_flag_message(self) -> None:
        result = self.run_check("--advisory")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--advisory caller acknowledged the load-bearing runtime gate", result.stdout)

    def test_green_policy_outside_the_window(self) -> None:
        for call_first in (False, True):
            with self.subTest(call_first=call_first):
                self.write(LIB, source(TRUE, gap=50, call_first=call_first))
                self.assertEqual(self.run_check().returncode, 0)

    def test_green_async_variant_definition_and_doc_lines(self) -> None:
        self.write(
            LIB,
            "\n".join(
                [
                    TRUE,
                    "    verify_anchor_batch_with_witness_policy_async(&b, &p).await;",
                    "pub fn verify_anchor_batch_with_witness_policy(b: &B, p: &P) {}",
                    "    pub async fn verify_anchor_batch_with_witness_policy(b: &B) {}",
                    "    // verify_anchor_batch_with_witness_policy(&b, &p)",
                    "    /// verify_anchor_batch_with_witness_policy(&b, &p)",
                ]
            )
            + "\n",
        )
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_green_excluded_paths_are_not_scanned(self) -> None:
        for rel in (
            "crates/economy/chio-demo/tests/it.rs",
            "crates/economy/chio-demo/benches/b.rs",
            "crates/economy/chio-demo/fuzz/f.rs",
            "crates/economy/chio-demo/examples/e.rs",
            "crates/economy/chio-demo/src/helper_test.rs",
            "crates/economy/chio-demo/src/helper_tests.rs",
        ):
            with self.subTest(rel):
                self.write(rel, source(TRUE))
                self.assertEqual(self.run_check().returncode, 0)

    def test_red_policy_before_call(self) -> None:
        self.write(LIB, source(TRUE))
        self.assert_flagged(self.run_check(), f"{LIB}:3")

    def test_red_policy_after_call(self) -> None:
        self.write(LIB, source(TRUE, call_first=True))
        self.assert_flagged(self.run_check(), f"{LIB}:2")

    def test_red_policy_without_space_after_colon(self) -> None:
        self.write(LIB, source("    let p = WitnessPolicy { require_public_witness:true };"))
        self.assert_flagged(self.run_check(), f"{LIB}:3")

    def test_red_window_boundary_is_fifty_lines(self) -> None:
        for call_first, call_line in ((False, 52), (True, 2)):
            with self.subTest(call_first=call_first):
                self.write(LIB, source(TRUE, gap=49, call_first=call_first))
                self.assert_flagged(self.run_check(), f"{LIB}:{call_line}")

    def test_red_reports_every_site_and_prints_hint(self) -> None:
        self.write(LIB, source(TRUE))
        self.write("crates/trust/chio-demo/src/lib.rs", source(TRUE, call_first=True))
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.count("sync wrapper called near literal"), 2)
        self.assertIn(f"{PREFIX} Hint: route public-witness verification through", result.stdout)

    def test_usage(self) -> None:
        bad = self.run_check("--bogus")
        self.assertEqual(bad.returncode, 2)
        self.assertIn("unknown argument: --bogus", bad.stderr)
        helped = self.run_check("--help")
        self.assertEqual(helped.returncode, 0)
        self.assertIn("SOUNDNESS CONTRACT", helped.stdout)


if __name__ == "__main__":
    unittest.main()
