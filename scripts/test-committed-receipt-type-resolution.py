#!/usr/bin/env python3
"""Regression cases for crate-qualified receipt wrapper resolution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "receipt_decode_gate", Path(__file__).with_name("check-committed-receipt-raw-decode.py")
)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
GATE.ALLOWED = ()


class TypeResolutionTests(unittest.TestCase):
    def findings(self, files):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, contents in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
            return GATE.scan(root)

    def test_unrelated_crate_cannot_erase_strict_wrapper(self):
        findings = self.findings({
            "crates/strict/src/lib.rs": "struct ScenarioOutcome { receipt: Option<ChioReceipt> }\nfn bad(s: &str) { serde_json::from_str::<ScenarioOutcome>(s); }",
            "crates/plain/src/lib.rs": "struct ScenarioOutcome { code: u32 }\nfn good(s: &str) { serde_json::from_str::<ScenarioOutcome>(s); }",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("crates/strict/src/lib.rs::bad", findings[0])

    def test_qualified_sibling_types_remain_distinct(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "mod strict; mod plain;\nfn bad(s: &str) { serde_json::from_str::<strict::Envelope>(s); }\nfn good(s: &str) { serde_json::from_str::<plain::Envelope>(s); }",
            "crates/demo/src/strict.rs": "pub struct Envelope { receipt: ChioReceipt }",
            "crates/demo/src/plain.rs": "pub struct Envelope { number: u32 }",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("::bad", findings[0])

    def test_inline_modules_and_renamed_imports_keep_scope(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "mod strict { pub struct Envelope { receipt: ChioReceipt } }\nmod plain { pub struct Envelope { number: u32 } }\nmod consumer { use crate::strict::Envelope as Input; type Wrapped = Option<Input>; fn bad(s: &str) { serde_json::from_str::<Wrapped>(s); } }\nmod other { use crate::plain::Envelope as Input; fn good(s: &str) { serde_json::from_str::<Input>(s); } }",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("::bad", findings[0])

    def test_local_seed_name_does_not_impersonate_core_receipt(self):
        findings = self.findings({
            "crates/plain/src/lib.rs": "struct ChioReceipt { value: u32 }\nfn good(s: &str) { serde_json::from_str::<ChioReceipt>(s); }",
        })
        self.assertEqual(findings, [])

    def test_strict_wrapper_without_collision_is_still_refused(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "struct Envelope { receipt: ChioReceipt }\nfn bad(s: &str) { serde_json::from_str::<Envelope>(s); }",
        })
        self.assertEqual(len(findings), 1, findings)

    def test_plain_wrappers_are_allowed(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "struct Envelope { value: u32 }\nfn good(s: &str) { serde_json::from_str::<Option<Envelope>>(s); }",
        })
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
