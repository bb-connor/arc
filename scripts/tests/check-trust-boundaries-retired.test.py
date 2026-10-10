#!/usr/bin/env python3
"""Actual gate calibration for retained debt after two direct-reader migrations."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("retirement_gate", ROOT / "scripts/check-trust-boundaries.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
MERCURY = "crates/products/chio-mercury/src/commands/shared/utils.rs"
BINDING = "crates/sdk/chio-binding-helpers/src/receipt.rs"


class RetirementCalibration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads((ROOT / gate.CATALOG).read_text())
        cls.files = dict(gate.sources(ROOT))
        cls.found = gate.scan(ROOT, cls.catalog)[0]

    def errors(self, catalog=None, files=None):
        chosen_catalog = self.catalog if catalog is None else catalog
        chosen_files = self.files if files is None else files
        if files is None:
            with patch.object(gate, "scan", return_value=(self.found, chosen_files)):
                return gate.check(ROOT, chosen_catalog)[0]
        with patch.object(gate, "sources", return_value=iter(chosen_files.items())):
            return gate.check(ROOT, chosen_catalog)[0]

    def retirement_errors(self, catalog=None):
        return [error for error in self.errors(catalog) if
                "decoder file contracts" in error or "retired direct" in error or
                "raw-input baseline debt" in error]

    def test_retired_helpers_keep_original_baseline_debt_and_are_accepted(self):
        baseline = [path for path, row in self.catalog["decoder_file_contracts"].items()
                    if row["kind"] == "raw-input-baseline"]
        self.assertEqual(len(baseline), 45)
        self.assertNotIn(MERCURY, self.found["decoder_census"])
        self.assertNotIn(BINDING, self.found["decoder_census"])
        self.assertIn(MERCURY, self.found["ingress_census"])
        self.assertIn(BINDING, self.found["ingress_census"])
        self.assertEqual(self.retirement_errors(), [])

    def test_retired_baseline_row_removal_is_rejected(self):
        changed = copy.deepcopy(self.catalog)
        changed["decoder_file_contracts"].pop(MERCURY)
        self.assertIn("retired direct-reader baseline is missing or changed: " + MERCURY,
                      self.retirement_errors(changed))

    def test_double_removal_cannot_erase_original_debt(self):
        changed = copy.deepcopy(self.catalog)
        changed["decoder_file_contracts"].pop(MERCURY)
        changed["retired_direct_readers"].pop(MERCURY)
        self.assertIn("raw-input baseline debt identities changed", self.retirement_errors(changed))

    def test_unexplained_vanished_reader_is_rejected(self):
        changed = copy.deepcopy(self.catalog)
        changed["retired_direct_readers"].pop(MERCURY)
        self.assertIn("workspace decoder file contracts are incomplete", self.retirement_errors(changed))

    def test_unreviewed_retirement_is_rejected(self):
        changed = copy.deepcopy(self.catalog)
        extra = "crates/core/chio-supervisor/src/health.rs"
        changed["retired_direct_readers"][extra] = copy.deepcopy(changed["retired_direct_readers"][MERCURY])
        self.assertIn("unreviewed retired direct reader: " + extra, self.retirement_errors(changed))

    def test_signed_helper_cannot_downgrade_after_catalog_metadata_refresh(self):
        files = self.files.copy()
        before = "UntrustedJsonText::new(text).decode_signed()"
        self.assertIn(before, files[MERCURY])
        files[MERCURY] = files[MERCURY].replace(before, "UntrustedJsonText::new(text).decode_document()", 1)
        changed = copy.deepcopy(self.catalog)
        row = changed["retired_direct_readers"][MERCURY]
        row["constructor_contract"] = row["constructor_contract"].replace("decode_signed", "decode_document")
        text = files[MERCURY]
        code = gate._lexer.blank_rust_noise(text)
        function = next(row for row in gate._contracts.functions(code) if row[0] == "read_json_file")
        row["helper_source_sha256"] = hashlib.sha256(text[function[1]:function[3]].encode()).hexdigest()
        with patch.object(gate, "sources", return_value=iter(files.items())):
            observed = gate.scan(ROOT, changed)[0]
        changed["decoding_contracts"] = observed["decoding_contracts"]
        changed["ingress_census"] = observed["ingress_census"]
        row["ingress"] = observed["ingress_census"][MERCURY]
        with patch.object(gate, "scan", return_value=(observed, files)):
            errors = gate.check(ROOT, changed)[0]
        self.assertIn("retired direct-reader signed helper changed: " + MERCURY, errors)

    def test_helper_consumer_cannot_be_silently_dropped(self):
        changed = copy.deepcopy(self.catalog)
        changed["retired_direct_readers"][BINDING]["consumers"] = []
        self.assertIn("retired direct-reader consumer custody changed: " + BINDING,
                      self.retirement_errors(changed))

    def test_direct_reader_reappearance_is_rejected(self):
        files = self.files.copy()
        files[MERCURY] += "\nfn unregistered_json(s: &str) { serde_json::from_str(s); }\n"
        changed = copy.deepcopy(self.catalog)
        with patch.object(gate, "sources", return_value=iter(files.items())):
            observed = gate.scan(ROOT, changed)[0]
        # A count update cannot conceal that a retired direct site is active again.
        changed["decoder_census"] = observed["decoder_census"]
        with patch.object(gate, "scan", return_value=(observed, files)):
            errors = gate.check(ROOT, changed)[0]
        self.assertIn("retired direct reader gained direct decoder: " + MERCURY, errors)


    def test_one_existing_consumer_pin_cannot_be_dropped(self):
        changed = copy.deepcopy(self.catalog)
        consumers = changed["retired_direct_readers"][BINDING]["consumers"]
        self.assertEqual(len(consumers), 2)
        consumers.pop()
        self.assertIn("retired direct-reader consumer custody changed: " + BINDING,
                      self.retirement_errors(changed))

    def test_new_unrecorded_consumer_is_rejected_after_census_refresh(self):
        files = self.files.copy()
        files[MERCURY] += "\nfn added_review_consumer(path: &Path) { read_json_file::<serde_json::Value>(path); }\n"
        changed = copy.deepcopy(self.catalog)
        with patch.object(gate, "sources", return_value=iter(files.items())):
            observed = gate.scan(ROOT, changed)[0]
        changed["ingress_census"] = observed["ingress_census"]
        changed["retired_direct_readers"][MERCURY]["ingress"] = observed["ingress_census"][MERCURY]
        with patch.object(gate, "scan", return_value=(observed, files)):
            errors = gate.check(ROOT, changed)[0]
        self.assertIn("retired direct-reader consumer custody changed: " + MERCURY, errors)


class BorrowedMcpFormattingCalibration(unittest.TestCase):
    def test_current_formatted_raw_member_preserves_checked_original_wire_evidence(self):
        path = gate._contracts._rules.MCP_INBOX
        source = (ROOT / path).read_text()
        code = gate._lexer.blank_rust_noise(gate.without_test_items(source))
        row = next(row for row in gate._contracts.functions(code) if row[0] == "scalar")
        body = gate._contracts.owner_code(code, row)
        apis = gate._contracts._rules.special_apis(path, "scalar", body, {path: code})
        self.assertEqual(apis, ["borrowed-control::bounded_scalar+same_wire_aggregate_admission"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
