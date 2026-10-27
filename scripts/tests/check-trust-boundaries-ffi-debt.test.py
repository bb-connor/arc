#!/usr/bin/env python3
"""Keep migrated FFI readers in the unresolved source baseline."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("gate", ROOT / "scripts/check-trust-boundaries.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class MigratedFileDebt(unittest.TestCase):
    path = "crates/kernel/chio-kernel-mobile/src/lib.rs"

    def setUp(self):
        self.source = "const MAX_JSON_INPUT_BYTES: usize = 1024 * 1024;\npub fn bounded_reader() {}\n"
        contract = {"kind": "raw-input-baseline", "contract": "Caller acceptance remains open."}
        self.review = {
            "baseline_kind": "raw-input-baseline",
            "baseline_contract_sha256": hashlib.sha256(json.dumps(
                contract, sort_keys=True, separators=(",", ":")
            ).encode()).hexdigest(),
            "source_sha256": hashlib.sha256(self.source.encode()).hexdigest(),
            "bound_source_sha256": gate.constant_hash(self.source, "MAX_JSON_INPUT_BYTES"),
            "ingress": ["bounded_reader::original-json-reader::UntrustedJsonText"],
            "status": "direct-serde-site-migrated-original-debt-open",
            "scope": "Bounded signed reader migration only.",
            "remaining_acceptance": "Caller and semantic review remains open.",
        }
        self.catalog = {
            "decoder_file_contracts": {self.path: contract},
            "retired_direct_readers": {self.path: self.review},
        }
        self.found = {
            "decoder_census": {}, "ingress_census": {self.path: self.review["ingress"]},
            "decoding_contracts": sorted(f"{self.path}::{owner}::from_wire#1::decode_signed"
                                        for owner in gate.RETIRED_DIRECT_FILES[self.path]),
        }
        self.files = {self.path: self.source}
        self.digest = hashlib.sha256(json.dumps([self.path], separators=(",", ":")).encode()).hexdigest()

    def errors(self):
        with patch.object(gate, "RAW_INPUT_BASELINE_IDENTITIES_SHA256", self.digest):
            return gate.retired_direct_contracts(self.catalog, self.found, self.files)

    def test_unchanged_migrated_file_retains_debt(self):
        self.assertEqual(self.errors(), [])

    def test_unsigned_or_unbounded_reader_cannot_be_reapproved_in_metadata(self):
        for old, new in (("decode_signed", "decode_document"), ("from_wire", "new")):
            with self.subTest(replacement=new):
                original = self.found["decoding_contracts"]
                self.found["decoding_contracts"] = [site.replace(old, new) for site in original]
                self.assertIn("retired direct-reader contract changed: " + self.path, self.errors())
                self.found["decoding_contracts"] = original

    def test_canonical_transform_contract_cannot_be_replaced_with_signed_decode(self):
        old_path = self.path
        self.path = "crates/sdk/chio-binding-helpers/src/canonical.rs"
        self.catalog["decoder_file_contracts"][self.path] = self.catalog["decoder_file_contracts"].pop(old_path)
        self.catalog["retired_direct_readers"][self.path] = self.catalog["retired_direct_readers"].pop(old_path)
        self.files = {self.path: self.source, "crates/sdk/chio-binding-helpers/src/lib.rs": self.source}
        self.found["ingress_census"] = {self.path: self.review["ingress"]}
        self.found["decoding_contracts"] = [f"{self.path}::canonicalize_json_str::from_wire#1::decode_document"]
        self.digest = hashlib.sha256(json.dumps([self.path], separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(self.errors(), [])
        self.found["decoding_contracts"][0] = self.found["decoding_contracts"][0].replace("decode_document", "decode_signed")
        self.assertIn("retired direct-reader contract changed: " + self.path, self.errors())

    def test_source_change_requires_review(self):
        self.files[self.path] += "pub fn another_reader() {}\n"
        self.assertIn("retired direct-reader file changed: " + self.path, self.errors())

    def test_bound_change_requires_separate_review(self):
        self.files[self.path] = self.source.replace("1024 * 1024", "usize::MAX")
        self.review["source_sha256"] = hashlib.sha256(self.files[self.path].encode()).hexdigest()
        self.assertIn("retired direct-reader bound constant changed: " + self.path, self.errors())

    def test_remaining_acceptance_cannot_disappear(self):
        self.review.pop("remaining_acceptance")
        self.assertIn("retired direct-reader remaining debt is missing: " + self.path, self.errors())

    def test_ingress_change_requires_review(self):
        self.found["ingress_census"][self.path] = ["other_reader"]
        self.assertIn("retired direct-reader file changed: " + self.path, self.errors())

    def test_baseline_cannot_be_promoted(self):
        self.catalog["decoder_file_contracts"][self.path]["kind"] = "strict-preflight-reparse"
        self.assertIn("raw-input baseline debt identities changed", self.errors())
        self.assertIn("retired direct-reader baseline is missing or changed: " + self.path, self.errors())

    def test_direct_decoder_cannot_return_unreviewed(self):
        self.found["decoder_census"][self.path] = ["from_str"]
        self.assertIn("retired direct reader gained direct decoder: " + self.path, self.errors())


if __name__ == "__main__":
    unittest.main()
