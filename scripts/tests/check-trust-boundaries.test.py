#!/usr/bin/env python3
"""Negative calibration against the actual approved source inventory."""
import importlib.util
import json
import unittest
from functools import lru_cache
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
        # Unchanged source text is identical across calibrated mutations. Cache
        # lexing only; every edited buffer still goes through the actual gate.
        cls.lex = staticmethod(lru_cache(maxsize=None)(gate._lexer.blank_rust_noise))
        decoders, sql = gate.json_decoders, gate.sql_statements
        cls.decoders = staticmethod(lru_cache(maxsize=None)(lambda code: tuple(decoders(code))))
        cls.sql = staticmethod(lru_cache(maxsize=None)(lambda path, text: tuple(sql(path, text))))
        cls.owner = staticmethod(lru_cache(maxsize=None)(gate.owner_at))

    def errors(self, path=None, edit=None):
        files = self.files.copy()
        if path:
            files[path] = edit(files.get(path, ""))
        with patch.object(gate, "sources", return_value=iter(files.items())), patch.object(
            gate._lexer, "blank_rust_noise", self.lex
        ), patch.multiple(
            gate, json_decoders=self.decoders, sql_statements=self.sql, owner_at=self.owner
        ):
            return gate.check(ROOT, self.catalog)[0]

    def test_current_sources_match(self):
        self.assertEqual(self.errors(), [])

    def test_reviewed_kernel_sqlite_owner_cannot_be_unregistered(self):
        catalog = json.loads(json.dumps(self.catalog))
        path = next(iter(catalog["reviewed_kernel_sqlite_owners"]))
        catalog["signed_input_files"].remove(path)
        with patch.object(self, "catalog", catalog):
            self.assertTrue(any("reviewed kernel/SQLite owner is unregistered" in error for error in self.errors()))

    def test_reviewed_kernel_sqlite_owner_cannot_return_to_baseline(self):
        catalog = json.loads(json.dumps(self.catalog))
        path = next(path for path in catalog["reviewed_kernel_sqlite_owners"] if path in catalog["decoder_file_contracts"])
        catalog["decoder_file_contracts"][path]["kind"] = "raw-input-baseline"
        with patch.object(self, "catalog", catalog):
            self.assertTrue(any("regressed to baseline" in error for error in self.errors()))

    def test_unscoped_sql_is_rejected_even_with_a_known_identifier(self):
        path = gate.STORE + "/receipt_store/support/store_impl.rs"
        errors = self.errors(path, lambda text: text + '\nfn leak() { query("SELECT raw_json FROM chio_tool_receipts WHERE receipt_id = ?1"); }')
        self.assertTrue(any("unscoped tenant SQL" in error for error in errors), errors)

    def test_raw_signed_decoder_is_rejected(self):
        path = self.catalog["signed_input_files"][0]
        errors = self.errors(path, lambda text: text + '\nfn bypass(s: &str) { serde_json::from_str(s) }')
        self.assertTrue(any("raw_decoders" in error for error in errors), errors)

    def test_new_unregistered_reader_requires_classification(self):
        errors = self.errors("crates/new/src/reader.rs", lambda _: 'fn load(s: &str) { serde_json::from_str(s) }')
        self.assertTrue(any("decoder census changed" in error for error in errors), errors)

    def test_imported_decoder_cannot_bypass_registered_owner(self):
        path = self.catalog["signed_input_files"][0]
        for declaration, call in [
            ("use serde_json::from_str;", "from_str(s)"),
            ("use serde_json::{from_str as parse};", "parse::<Value>(s)"),
            ("use serde_json as json;", "json::from_str(s)"),
            ("use serde_json::{self as json};", "json::from_str(s)"),
            ("use serde_json::de::Deserializer as Reader;", "Reader::from_str(s)"),
            ("use serde_json::*;", "from_str(s)"),
        ]:
            with self.subTest(declaration=declaration):
                errors = self.errors(path, lambda text: text + f'\n{declaration}\nfn bypass(s: &str) {{ {call} }}')
                self.assertTrue(any("raw_decoders" in error for error in errors), errors)

    def test_custom_deserializer_requires_classification(self):
        errors = self.errors("crates/new/src/reader.rs", lambda _: 'impl Deserialize for Signed { fn deserialize<D>(d: D) { Value::deserialize(d) } }')
        self.assertTrue(any("decoder census changed" in error for error in errors), errors)

    def test_documented_decoders_are_not_production_calls(self):
        path = self.catalog["signed_input_files"][0]
        errors = self.errors(path, lambda text: text + '\n/// fn example() { serde_json::from_slice(bytes); }\nfn text_only() { let s = "serde_json::from_str(bytes)"; }')
        self.assertEqual(errors, [])

    def test_new_table_requires_a_principal(self):
        errors = self.errors(gate.STORE + "/new_schema.sql", lambda _: "CREATE TABLE leaked (tenant_id TEXT, id TEXT);")
        self.assertTrue(any("classification is incomplete" in error for error in errors), errors)

    def test_table_without_runtime_family_is_rejected(self):
        catalog = json.loads(json.dumps(self.catalog))
        catalog["tables"][next(iter(catalog["tables"]))].pop("runtime_family")
        with patch.object(self, "catalog", catalog):
            self.assertTrue(any("runtime matrix is incomplete" in error for error in self.errors()))

    def test_public_proof_field_is_rejected(self):
        proof = self.catalog["proofs"][0]
        errors = self.errors(proof["path"], lambda text: text.replace("    id: String,", "    pub id: String,", 1))
        self.assertTrue(any("proof fields are not sealed" in error for error in errors), errors)

    def test_derived_proof_deserializer_is_rejected(self):
        proof = self.catalog["proofs"][0]
        errors = self.errors(proof["path"], lambda text: text.replace("pub struct " + proof["type"], "#[derive(serde::Deserialize)]\npub struct " + proof["type"], 1))
        self.assertTrue(any("proof implements Deserialize" in error for error in errors), errors)

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
