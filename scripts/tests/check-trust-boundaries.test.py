#!/usr/bin/env python3
"""Negative calibration against the actual approved source inventory."""
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("boundary_gate", ROOT / "scripts/check-trust-boundaries.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class BoundaryGateCalibration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads((ROOT / gate.CATALOG).read_text())
        cls.files = dict(gate.sources(ROOT))

    def errors(self, path=None, edit=None):
        files = self.files.copy()
        if path:
            files[path] = edit(files.get(path, ""))
        with patch.object(gate, "sources", return_value=iter(files.items())):
            return gate.check(ROOT, self.catalog)[0]

    def test_current_sources_match(self):
        self.assertEqual(self.errors(), [])

    def test_unscoped_sql_is_rejected_even_with_a_known_identifier(self):
        path = gate.STORE + "/receipt_store/support/store_impl.rs"
        errors = self.errors(path, lambda text: text + '\nfn leak() { query("SELECT raw_json FROM chio_tool_receipts WHERE receipt_id = ?1"); }')
        self.assertTrue(any("unscoped tenant SQL" in error for error in errors), errors)

    def test_raw_signed_decoder_is_rejected(self):
        path = self.catalog["signed_input_files"][0]
        errors = self.errors(path, lambda text: text + '\nfn bypass(s: &str) { serde_json::from_str(s) }')
        self.assertTrue(any("raw_decoders" in error for error in errors), errors)

    def test_new_table_requires_a_principal(self):
        errors = self.errors(gate.STORE + "/new_schema.sql", lambda _: "CREATE TABLE leaked (tenant_id TEXT, id TEXT);")
        self.assertTrue(any("classification is incomplete" in error for error in errors), errors)

    def test_public_proof_field_is_rejected(self):
        proof = self.catalog["proofs"][0]
        errors = self.errors(proof["path"], lambda text: text.replace("    id: String,", "    pub id: String,", 1))
        self.assertTrue(any("proof fields are not sealed" in error for error in errors), errors)

    def test_secret_extraction_outside_custody_is_rejected(self):
        errors = self.errors(gate.STORE + "/leaked.rs", lambda _: "fn send(package: FrostRound2Package) { package.secret_bytes(); }")
        self.assertTrue(any("plaintext extracted" in error for error in errors), errors)

    def test_test_helper_does_not_hide_later_production_code(self):
        text = '#[cfg(test)] fn helper() { let s = "}"; }\nfn production() { leak(); }'
        masked = gate.without_test_items(text)
        self.assertNotIn("helper", masked)
        self.assertIn("fn production() { leak(); }", masked)


if __name__ == "__main__":
    unittest.main()
