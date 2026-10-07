"""Regeneration preserves historical signed bytes and describes current profiles."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

SCRIPT = Path(__file__).with_name("generate-recovery-authority-corpus.py")
MODULE_SPEC = importlib.util.spec_from_file_location("recovery_authority_corpus", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
CORPUS = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(CORPUS)
ROOT = SCRIPT.parents[2]
VECTOR_ROOT = ROOT / "spec/vectors/recovery/v1"


class AuthorityCorpusTests(unittest.TestCase):
    def setUp(self):
        self.previous = json.loads((VECTOR_ROOT / "authority-contracts.json").read_bytes())
        self.native = json.loads((VECTOR_ROOT / "authority-positive.json").read_bytes())

    def test_legacy_records_remain_byte_for_byte_unchanged(self):
        original = [row for row in self.previous["vectors"]
                    if not row["name"].startswith((CORPUS.PROFILE_PREFIX, "utf8-bound/"))]
        result = CORPUS.build_corpus(self.previous, self.native)
        retained = result["vectors"][:len(original)]
        self.assertEqual(retained, original)
        self.assertEqual(len(original), 102)
        # Commit the historical wire identity independently of generator output.
        wires = json.dumps([(row["name"], row["wire"]) for row in retained],
                           ensure_ascii=False, separators=(",", ":")).encode()
        self.assertEqual(hashlib.sha256(wires).hexdigest(),
                         "6cc4a22d155dc522864a178aa697d5f51a4d6077b6f4c0eaa81f96ba2ba51fc8")

    def test_regeneration_is_idempotent_and_does_not_mutate_inputs(self):
        before = copy.deepcopy(self.previous), copy.deepcopy(self.native)
        first = CORPUS.build_corpus(self.previous, self.native)
        self.assertEqual(CORPUS.build_corpus(first, self.native), first)
        self.assertEqual((self.previous, self.native), before)
        self.assertEqual(len(first["vectors"]), 155)
        self.assertEqual(len(first["profiles"]["native_origin_bound"]["vectors"]), 31)

    def test_utf8_profile_covers_exact_and_oversized_native_field_roles(self):
        result = CORPUS.build_corpus(self.previous, self.native)
        rows = {row["name"]: row for row in result["vectors"]
                if row["name"].startswith("utf8-bound/")}
        limits = {"title": 256, "body": 16384, "resource": 2048,
                  "provider": 256, "account": 256, "capability": 256,
                  "recipient": 256, "purpose": 256, "owner": 256,
                  "reader": 256, "compartment": 256}
        self.assertEqual(len(rows), 2 * len(limits))
        for role, limit in limits.items():
            for suffix, valid, expected_bytes in [("exact", True, limit),
                                                   ("oversized", False, limit + 2)]:
                row = rows[f"utf8-bound/{role}-{suffix}"]
                self.assertEqual(row["valid"], valid)
                self.assertEqual(row["schema_valid"], valid)
                self.assertNotIn(row["contract"], {"grant", "coverage", "provider_finality"})
                value = json.loads(row["wire"])
                if role == "capability":
                    text = value["capability_id"]
                elif role == "owner":
                    text = next(iter(value["source_label"]["owners"]))
                    self.assertEqual(value["source_label"]["owners"][text], [text])
                elif role == "reader":
                    text = value["source_label"]["owners"]["owner"][1]
                elif role == "compartment":
                    text = value["source_label"]["compartments"][0]
                else:
                    text = value[role]
                self.assertEqual(len(text.encode("utf-8")), expected_bytes)
        self.assertEqual(set(result["profiles"]["decoded_utf8_bounds"]["vectors"]), set(rows))

    def test_current_profile_preserves_raw_refusal_distinctions(self):
        rows = {row["name"]: row for row in CORPUS.current_vectors(self.native)}
        positive = [row for row in rows.values() if row["valid"]]
        self.assertEqual(len(positive), 14)
        for kind in ["float-token", "exponent-token", "duplicate-origin",
                     "duplicate-origin-closure", "current-action-noncanonical"]:
            suffix = "origin-operation-version-" + kind if kind.endswith("token") else kind
            row = rows[CORPUS.PROFILE_PREFIX + suffix]
            self.assertTrue(row["schema_valid"])
            self.assertFalse(row["valid"])
        for member in ["request_id", "closure"]:
            row = rows[CORPUS.PROFILE_PREFIX + "origin-" + member.replace("_", "-") + "-newline"]
            self.assertFalse(row["schema_valid"])
            self.assertFalse(row["valid"])

    def test_originless_export_cannot_replace_the_current_profile(self):
        self.native["action"].pop("origin")
        with self.assertRaisesRegex(ValueError, "mandatory current origin"):
            CORPUS.build_corpus(self.previous, self.native)


if __name__ == "__main__":
    unittest.main()
