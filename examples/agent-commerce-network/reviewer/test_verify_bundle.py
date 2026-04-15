from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_bundle import verify_bundle


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / "contracts"


class ReviewerVerifierTests(unittest.TestCase):
    def make_bundle(self) -> Path:
        tempdir = Path(tempfile.mkdtemp(prefix="agent-commerce-network-bundle-"))
        (tempdir / "contracts").mkdir()
        for name in ["README.md", "steps.md", "expected-outputs.md"]:
            (tempdir / name).write_text(f"# {name}\n")
        for contract in CONTRACTS_DIR.glob("*.json"):
            shutil.copy(contract, tempdir / "contracts" / contract.name)
        return tempdir

    def test_verifies_complete_bundle(self) -> None:
        bundle = self.make_bundle()
        self.addCleanup(lambda: shutil.rmtree(bundle, ignore_errors=True))
        result = verify_bundle(bundle)
        self.assertTrue(result["ok"])
        self.assertEqual(result["errors"], [])

    def test_reports_missing_contract(self) -> None:
        bundle = self.make_bundle()
        self.addCleanup(lambda: shutil.rmtree(bundle, ignore_errors=True))
        (bundle / "contracts" / "settlement-reconciliation.json").unlink()
        result = verify_bundle(bundle)
        self.assertFalse(result["ok"])
        self.assertIn("missing contract artifact: settlement-reconciliation.json", result["errors"])


if __name__ == "__main__":
    unittest.main()
