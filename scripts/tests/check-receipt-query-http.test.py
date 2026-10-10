#!/usr/bin/env python3
"""Exercise the HTTP boundary gate against real source substitutions."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

GATE = Path(__file__).resolve().parents[1] / "check-receipt-query-http.py"


class HttpReceiptBoundary(unittest.TestCase):
    def run_gate(self, source, extra_files=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            gate = root / "scripts/check-receipt-query-http.py"
            shutil.copyfile(GATE, gate)
            handler = root / "crates/platform/chio-control-plane/src/trust_control/receipt_handlers.rs"
            handler.parent.mkdir(parents=True)
            if source is not None:
                handler.write_text(source)
            for name, content in (extra_files or {}).items():
                path = handler.parent / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            return subprocess.run([sys.executable, str(gate)], capture_output=True, text=True, check=False)

    def test_every_legacy_entrypoint_is_refused_across_formatting(self):
        for method in ("query_receipts", "load_chio_receipt_with_context", "with_retained_snapshot"):
            for gap in ("", " ", "\n        "):
                with self.subTest(method=method, gap=gap):
                    result = self.run_gate(f"async fn handle() {{ store.{method}{gap}(&query); }}\n")
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("full-history receipt read", result.stderr)

    def test_snapshot_adapter_and_unrelated_receipt_writes_are_allowed(self):
        result = self.run_gate("receipt_query_service::query(&state, query).await;\nstore.append_chio_receipt(&receipt);\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_missing_handler_cannot_qualify(self):
        result = self.run_gate(None)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS", result.stdout)

    def test_other_handler_files_cannot_restore_full_history_reads(self):
        for name in ("new_handlers.rs", "nested/receipt_reads.rs"):
            with self.subTest(name=name):
                result = self.run_gate("receipt_query_service::query(&state, query).await;\n", {
                    name: "async fn handle() { store.query_receipts(&query); }\n",
                })
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(name, result.stderr)

    def test_only_snapshot_query_is_allowed_in_the_adapter(self):
        for source, expected in (
            ("snapshots.query_receipts(&query)", 0),
            ("store.query_receipts(&query)", 1),
            ("snapshots.load_chio_receipt_with_context(&id, &context)", 1),
        ):
            with self.subTest(source=source):
                result = self.run_gate("receipt_query_service::query(&state, query).await;\n", {
                    "receipt_query_service.rs": source,
                })
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_chained_or_parenthesized_receivers_remain_checked(self):
        for receiver in ("factory()", "(store)", "store?", "state.store"):
            with self.subTest(receiver=receiver):
                result = self.run_gate(f"{receiver}.query_receipts(&query);\n")
                self.assertEqual(result.returncode, 1, result.stderr)


if __name__ == "__main__":
    unittest.main()
