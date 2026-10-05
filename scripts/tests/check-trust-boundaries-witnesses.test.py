#!/usr/bin/env python3
"""Exercise reviewed reader witnesses through the gate's actual evidence path."""
import importlib.util
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("boundary_gate", ROOT / "scripts/check-trust-boundaries.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
contracts = gate._contracts
witnesses = contracts._witnesses


class ReaderWitnessCalibration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        paths = set(contracts.SUPPORT_PATHS) | {rule["path"] for rule in witnesses.RULES}
        cls.files = {path: gate.without_test_items((ROOT / path).read_text()) for path in paths}

    def evidence(self, rule, edits=None):
        files = self.files | (edits or {})
        codes = {path: gate._lexer.blank_rust_noise(text) for path, text in files.items()}
        code = codes[rule["path"]]
        return contracts.reader_evidence(
            rule["path"], code, list(gate.json_decoders(code)),
            gate._lexer.blank_test_scoped_items(code),
            {path: codes[path] for path in contracts.SUPPORT_PATHS},
        )

    def labels(self, rule, edits=None):
        return {api for row in self.evidence(rule, edits) for api in row["apis"]}

    def owner(self, path, name, text=None):
        code = gate._lexer.blank_rust_noise(self.files[path] if text is None else text)
        if name == "@file":
            return code, 0, len(code)
        row = next(row for row in contracts.functions(code) if row[0] == name)
        return contracts.owner_code(code, row), row[1], row[3]

    def actual_reader(self, rule):
        code = gate._lexer.blank_rust_noise(self.files[rule["path"]])
        return next(row[0] for row in contracts.functions(code)
                    if row[0].split("#")[0] == rule["reader"]
                    and all(re.search(pattern, contracts.owner_code(code, row))
                            for pattern in rule["required_source_expressions"]))

    def targets(self, rule):
        return [{"path": rule["path"], "owner": self.actual_reader(rule),
                 "required_source_expressions": rule["required_source_expressions"]},
                *rule["required_owner_witnesses"]]

    def replace_expression(self, target, pattern, replacement=""):
        body, start, _ = self.owner(target["path"], target["owner"])
        match = re.search(pattern, body)
        self.assertIsNotNone(match, (target, pattern))
        begin, end = start + match.start(), start + match.end()
        text = self.files[target["path"]]
        return text[:begin] + replacement + text[end:], text[begin:end]

    def rule(self, reader):
        return next(rule for rule in witnesses.RULES if rule["reader"] == reader)

    def test_reviewed_sources_supply_every_named_witness(self):
        for rule in witnesses.RULES:
            with self.subTest(reader=rule["reader"], path=rule["path"]):
                self.assertIn(rule["api_label"], self.labels(rule))

    def test_bilateral_authority_requires_strict_signature_verification(self):
        rule = next(rule for rule in witnesses.RULES
                    if rule["api_label"] == "read_frame::capped_timed_receipt_request+cosign_authority")
        path = rule["path"]
        self.assertIn(rule["api_label"], self.labels(rule))
        original = "directory_key.verify_strict(subject.signed_bytes, subject.org_b_signature)"
        self.assertEqual(self.files[path].count(original), 1)
        changed = self.files[path].replace(original, original.replace("verify_strict", "verify"))
        self.assertNotIn(rule["api_label"], self.labels(rule, {path: changed}))

    def test_each_required_guard_removal_loses_actual_reader_evidence(self):
        for rule in witnesses.RULES:
            for target in self.targets(rule):
                for pattern in target["required_source_expressions"]:
                    with self.subTest(api=rule["api_label"], owner=target["owner"], pattern=pattern):
                        changed, _ = self.replace_expression(target, pattern)
                        self.assertNotIn(rule["api_label"], self.labels(rule, {target["path"]: changed}))

    def test_new_private_callers_require_review_even_when_qualified(self):
        for rule in witnesses.RULES:
            for relation in rule["producer_relationships"]:
                for prefix in ("", "self::", "super::", "crate::module::"):
                    with self.subTest(callee=relation["callee"], prefix=prefix):
                        path = relation["path"]
                        added = "\nfn unreviewed_reader() { " + prefix + relation["callee"] + "(raw, expected); }\n"
                        self.assertNotIn(rule["api_label"], self.labels(rule, {path: self.files[path] + added}))

    def test_additional_call_from_existing_producer_requires_review(self):
        rule = self.rule("decode_hashed")
        path = rule["path"]
        _, _, end = self.owner(path, "load_slot")
        for prefix in ("", "self::"):
            with self.subTest(prefix=prefix):
                changed = self.files[path][:end - 1] + prefix + "decode_hashed(raw, expected);\n" + self.files[path][end - 1:]
                self.assertNotIn(rule["api_label"], self.labels(rule, {path: changed}))

    def test_comments_strings_and_unrelated_owners_do_not_restore_helpers(self):
        rule = self.rule("receipt")
        path = "crates/kernel/chio-kernel/src/tool_outcome.rs"
        target = {"path": path, "owner": "canonical"}
        changed, removed = self.replace_expression(target, r"canonical_json_bytes\(value\)")
        for decoy in (
            "\n// " + removed + "\n",
            '\nconst DOC: &str = r###"' + removed + '"###;\n',
            "\nfn unrelated() { " + removed + "; }\n",
        ):
            with self.subTest(decoy=decoy):
                self.assertNotIn(rule["api_label"], self.labels(rule, {path: changed + decoy}))

    def test_nested_helper_cannot_supply_its_enclosing_owner_guard(self):
        rule = self.rule("receipt")
        path = "crates/kernel/chio-kernel/src/tool_outcome.rs"
        target = {"path": path, "owner": "canonical"}
        changed, _ = self.replace_expression(target, r"canonical_json_bytes\(value\)")
        code = gate._lexer.blank_rust_noise(changed)
        row = next(row for row in contracts.functions(code) if row[0] == "canonical")
        nested = "fn decoy() { canonical_json_bytes(value).map_err(error); }\n"
        changed = changed[:row[2] + 1] + nested + changed[row[2] + 1:]
        self.assertNotIn(rule["api_label"], self.labels(rule, {path: changed}))

    def test_file_visibility_witness_cannot_be_supplied_by_comments(self):
        rule = self.rule("decode_hashed")
        path = rule["path"]
        changed = self.files[path].replace("fn decode_hashed<", "pub fn decode_hashed<", 1)
        changed += "\n// fn decode_hashed<T: DeserializeOwned>\n"
        self.assertNotIn(rule["api_label"], self.labels(rule, {path: changed}))

    def test_nested_constant_cannot_restore_the_original_file_bound(self):
        rule = self.rule("receipt")
        path = rule["path"]
        changed = self.files[path].replace(
            "const MAX_BYTES: usize = 1024 * 1024;",
            "const MAX_BYTES: usize = usize::MAX;", 1,
        )
        for decoy in (
            "fn misleading() { const MAX_BYTES: usize = 1024 * 1024; }",
            "mod misleading { const MAX_BYTES: usize = 1024 * 1024; }",
            "impl Misleading { const MAX_BYTES: usize = 1024 * 1024; }",
        ):
            with self.subTest(decoy=decoy):
                self.assertNotIn(rule["api_label"], self.labels(rule, {path: changed + "\n" + decoy}))

    def test_missing_support_and_wrong_reader_path_do_not_grant_evidence(self):
        rule = self.rule("receipt")
        path = "crates/kernel/chio-kernel/src/tool_outcome.rs"
        self.assertNotIn(rule["api_label"], self.labels(rule, {path: ""}))
        body, _, _ = self.owner(rule["path"], "receipt")
        self.assertEqual(witnesses.verified_apis(
            "crates/unreviewed/src/lib.rs", "receipt", body, {},
            contracts.scoped_owner_bodies, contracts.scoped_declarations,
        ), [])

    def test_noise_does_not_create_extra_private_callers(self):
        rule = self.rule("decode_hashed")
        path = rule["path"]
        changed = self.files[path] + '''
            // fn fake() { decode_hashed(raw, expected); }
            const DOC: &str = "fn fake() { self::decode_hashed(raw, expected); }";
        '''
        self.assertIn(rule["api_label"], self.labels(rule, {path: changed}))

    def test_size_check_after_typed_allocation_loses_evidence(self):
        rule = self.rule("from_canonical_bytes")
        path = rule["path"]
        body, start, _ = self.owner(path, "from_canonical_bytes")
        begin = start + body.index("if bytes.is_empty()")
        code = gate._lexer.blank_rust_noise(self.files[path])
        end = contracts.closing(code, code.index("{", begin), "{", "}")
        guard = self.files[path][begin:end]
        changed = self.files[path][:begin] + self.files[path][end:]
        after = changed.index(";", changed.index("serde_json::from_slice(bytes)", begin)) + 1
        changed = changed[:after] + guard + changed[after:]
        self.assertNotIn(rule["api_label"], self.labels(rule, {path: changed}))

    def test_frame_allocation_before_cap_and_signing_before_replay_are_rejected(self):
        cases = [
            (self.rule("receipt_exchange"), "read_frame", "if len > MAX_WIRE_BYTES", "let mut buf:"),
            (self.rule("export_outcome_unknown_projection"), "export_outcome_unknown_projection",
             "verify_exact_terminal_replay(transaction,", "let envelope ="),
        ]
        for rule, owner, early, late in cases:
            with self.subTest(reader=rule["reader"]):
                path = rule["path"]
                body, start, _ = self.owner(path, owner)
                first = start + body.index(early)
                code = gate._lexer.blank_rust_noise(self.files[path])
                end = (contracts.closing(code, code.index("{", first), "{", "}")
                       if early.startswith("if") else code.index(";", first) + 1)
                moved = self.files[path][first:end]
                changed = self.files[path][:first] + self.files[path][end:]
                after = changed.index(";", changed.index(late, first)) + 1
                changed = changed[:after] + moved + changed[after:]
                self.assertNotIn(rule["api_label"], self.labels(rule, {path: changed}))

    def test_other_serve_overload_cannot_supply_receipt_reader_witness(self):
        rule = self.rule("serve")
        path = rule["path"]
        changed = self.files[path].replace(
            "let request: WireReceiptCoSigningRequest = serde_json::from_slice(&request_bytes)?;",
            "let request: WireReply = serde_json::from_slice(&request_bytes)?;", 1,
        )
        self.assertNotEqual(changed, self.files[path])
        self.assertNotIn(rule["api_label"], self.labels(rule, {path: changed}))

    def test_mutated_encoder_is_rejected_by_full_gate(self):
        files = dict(gate.sources(ROOT))
        path = "crates/kernel/chio-kernel/src/tool_outcome.rs"
        files[path] = files[path].replace(
            "canonical_json_bytes(value).map_err", "serde_json::to_vec(value).map_err", 1,
        )
        catalog = json.loads((ROOT / gate.CATALOG).read_text())
        with patch.object(gate, "sources", return_value=iter(files.items())):
            errors, _ = gate.check(ROOT, catalog)
        self.assertTrue(any("reader evidence" in error and
                            "tool_outcome/execution_evidence.rs" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
