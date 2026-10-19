#!/usr/bin/env python3
"""Self-test for scripts/check-no-eip3009-broadcast.sh."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-no-eip3009-broadcast.sh"
PAYMENTS = "crates/economy/chio-settle/src/payments.rs"


class NoEip3009BroadcastTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-eip3009-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts" / SCRIPT.name)

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def run_check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "scripts/check-no-eip3009-broadcast.sh"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_green_clean_payments(self) -> None:
        self.write(PAYMENTS, "pub fn sign() {}\n")
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "check-no-eip3009-broadcast: OK (1 files scanned)")

    def test_green_comment_mentions_are_allowed(self) -> None:
        self.write(
            PAYMENTS,
            "// never call eth_sendTransaction here\n    // broadcast_transfer_with_authorization is on-chain only\n",
        )
        self.assertEqual(self.run_check().returncode, 0)

    def test_green_other_files_are_not_scanned(self) -> None:
        self.write(PAYMENTS, "pub fn sign() {}\n")
        self.write("crates/economy/chio-settle/src/onchain.rs", "client.send_transaction(tx);\n")
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("(1 files scanned)", result.stdout)

    def test_green_counts_nested_payments_files(self) -> None:
        self.write(PAYMENTS, "")
        self.write("crates/economy/chio-settle/src/rail/payments.rs", "")
        self.assertIn("(2 files scanned)", self.run_check().stdout)

    def test_red_each_broadcast_marker(self) -> None:
        for marker in (
            'rpc("eth_sendTransaction", params);',
            "provider.send_transaction(tx);",
            "broadcast_transfer_with_authorization(auth);",
        ):
            with self.subTest(marker):
                self.write(PAYMENTS, f"fn go() {{\n    {marker}\n}}\n")
                result = self.run_check()
                self.assertEqual(result.returncode, 1)
                self.assertEqual(
                    result.stdout.strip().splitlines(),
                    [
                        f"VIOLATION: broadcast path in off-chain settle lane: {self.root}/{PAYMENTS}",
                        "check-no-eip3009-broadcast: FAILED",
                    ],
                )

    def test_red_trailing_comment_does_not_excuse_code(self) -> None:
        self.write(PAYMENTS, "provider.send_transaction(tx); // ok\n")
        self.assertEqual(self.run_check().returncode, 1)

    def test_red_zero_files_scanned(self) -> None:
        (self.root / "crates/economy/chio-settle/src").mkdir(parents=True)
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.strip(), "FALSE-GREEN GUARD: scanned 0 files")

    def test_red_settle_directory_missing(self) -> None:
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
