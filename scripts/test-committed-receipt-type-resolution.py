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

    def test_cross_crate_reexport_and_dependency_rename(self):
        findings = self.findings({
            "crates/producer/Cargo.toml": '[package]\nname = "receipt-producer"\nversion = "0.1.0"\n',
            "crates/producer/src/lib.rs": "mod model; pub use model::Envelope;",
            "crates/producer/src/model.rs": "pub struct Envelope { receipt: ChioReceipt }",
            "crates/consumer/Cargo.toml": '[package]\nname = "consumer"\nversion = "0.1.0"\n[dependencies]\nrecords = { package = "receipt-producer", path = "../producer" }\n',
            "crates/consumer/src/lib.rs": "use records::Envelope as Input; fn bad(s: &str) { serde_json::from_str::<Input>(s); }",
            "crates/plain/src/lib.rs": "struct Envelope { n: u32 }",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("crates/consumer/src/lib.rs::bad", findings[0])

    def test_module_alias_glob_and_super_resolution(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "mod model { pub struct Envelope { receipt: ChioReceipt } } mod consumer { use super::model as source; use source::*; fn bad(s: &str) { serde_json::from_str::<Envelope>(s); } }",
        })
        self.assertEqual(len(findings), 1, findings)

    def test_path_attribute_resolves_declared_module_name(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": '#[path = "wire_impl.rs"] mod wire; fn bad(s: &str) { serde_json::from_str::<wire::Envelope>(s); }',
            "crates/demo/src/wire_impl.rs": "pub struct Envelope { receipt: ChioReceipt }",
        })
        self.assertEqual(len(findings), 1, findings)

    def test_block_imports_do_not_leak_to_another_block(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "mod strict { pub struct Envelope { receipt: ChioReceipt } } mod plain { pub struct Envelope { n: u32 } } fn scan(s: &str) { { use crate::strict::Envelope as Input; serde_json::from_str::<Input>(s); } { use crate::plain::Envelope as Input; serde_json::from_str::<Input>(s); } }",
        })
        self.assertEqual(len(findings), 1, findings)

    def test_cyclic_reexports_terminate(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "mod a { pub use super::b::*; pub struct Envelope { receipt: ChioReceipt } } mod b { pub use super::a::*; } fn bad(s: &str) { serde_json::from_str::<b::Envelope>(s); }",
        })
        self.assertEqual(len(findings), 1, findings)

    def test_unresolved_external_glob_does_not_recurse(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "use serde::*; struct Plain { value: u32 } fn good(s: &str) { serde_json::from_str::<Plain>(s); }",
        })
        self.assertEqual(findings, [])

    def test_workspace_dependency_rename_resolves_the_producer(self):
        findings = self.findings({
            "Cargo.toml": '[workspace]\nmembers = ["crates/producer", "crates/consumer"]\n[workspace.dependencies]\nrecords = { package = "receipt-producer", path = "crates/producer" }\n',
            "crates/producer/Cargo.toml": '[package]\nname = "receipt-producer"\nversion = "0.1.0"\n',
            "crates/producer/src/lib.rs": "pub struct Envelope { receipt: ChioReceipt }",
            "crates/consumer/Cargo.toml": '[package]\nname = "consumer"\nversion = "0.1.0"\n[dependencies]\nrecords = { workspace = true }\n',
            "crates/consumer/src/lib.rs": "fn bad(s: &str) { serde_json::from_str::<records::Envelope>(s); }",
        })
        self.assertEqual(len(findings), 1, findings)

    def test_inline_path_attribute_uses_its_containing_module_directory(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": 'mod outer { #[path = "impl.rs"] mod wire; fn bad(s: &str) { serde_json::from_str::<wire::Envelope>(s); } }',
            "crates/demo/src/outer/impl.rs": "pub struct Envelope { receipt: ChioReceipt }",
            "crates/demo/src/impl.rs": "pub struct Envelope { value: u32 }",
        })
        self.assertEqual(len(findings), 1, findings)

    def test_local_module_shadows_external_crate_name(self):
        findings = self.findings({
            "crates/producer/src/lib.rs": "pub struct Envelope { receipt: ChioReceipt }",
            "crates/consumer/src/lib.rs": "mod producer { pub struct Envelope { value: u32 } } fn good(s: &str) { serde_json::from_str::<producer::Envelope>(s); }",
        })
        self.assertEqual(findings, [])

    def test_import_named_like_its_source_crate_terminates(self):
        findings = self.findings({
            "crates/producer/src/lib.rs": "pub struct Wrapper { receipt: ChioReceipt }",
            "crates/consumer/src/lib.rs": "use producer::Wrapper as producer; struct Envelope { value: producer } fn bad(s: &str) { serde_json::from_str::<Envelope>(s); }",
        })
        self.assertEqual(len(findings), 1, findings)

    def test_absolute_external_path_bypasses_local_module(self):
        findings = self.findings({
            "crates/producer/src/lib.rs": "pub struct Envelope { receipt: ChioReceipt }",
            "crates/consumer/src/lib.rs": "mod producer { pub struct Envelope { value: u32 } } fn bad(s: &str) { serde_json::from_str::<::producer::Envelope>(s); }",
        })
        self.assertEqual(len(findings), 1, findings)

    def test_root_group_and_absolute_imports_keep_namespace(self):
        findings = self.findings({
            "crates/producer/src/lib.rs": "pub struct Envelope { receipt: ChioReceipt }",
            "crates/consumer/src/lib.rs": "mod producer { pub struct Envelope { value: u32 } } use {producer::Envelope as Plain}; use ::producer::{Envelope as Signed}; fn good(s: &str) { serde_json::from_str::<Plain>(s); } fn bad(s: &str) { serde_json::from_str::<Signed>(s); }",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("::bad", findings[0])

    def test_included_receipt_type_reaches_sibling_wrappers(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": 'include!("session.rs"); mod pending; mod restored;',
            "crates/demo/src/session.rs": "pub struct RemoteSession { receipt: ChioReceipt }",
            "crates/demo/src/pending.rs": "use super::*; struct PendingCompletion { session: RemoteSession } fn bad(s: &str) { serde_json::from_str::<PendingCompletion>(s); }",
            "crates/demo/src/restored.rs": "use super::*; struct RestoredSession { session: RemoteSession } fn bad(s: &str) { serde_json::from_str::<RestoredSession>(s); }",
        })
        self.assertEqual(len(findings), 2, findings)

    def test_unresolved_type_path_is_reported(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "struct Envelope { receipt: missing::ReceiptWrapper } fn bad(s: &str) { serde_json::from_str::<Envelope>(s); }",
        })
        self.assertTrue(any("unresolved" in finding and "missing::ReceiptWrapper" in finding for finding in findings), findings)

    def test_shared_include_keeps_each_including_namespace(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": 'mod strict { struct Member { receipt: ChioReceipt } include!("shared.rs"); fn bad(s: &str) { serde_json::from_str::<Wrapper>(s); } } mod plain { struct Member { n: u32 } include!("shared.rs"); fn good(s: &str) { serde_json::from_str::<Wrapper>(s); } }',
            "crates/demo/src/shared.rs": "struct Wrapper { member: Member }",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("::bad", findings[0])

    def test_test_only_field_does_not_erase_following_production_code(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "struct Envelope { receipt: ChioReceipt, #[cfg(test)] probe: Option<u32>, } fn bad(s: &str) { serde_json::from_str::<Envelope>(s); }",
        })
        self.assertTrue(any("raw decode" in finding and "::bad" in finding for finding in findings), findings)

    def test_local_named_type_macro_preserves_receipt_fields(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "macro_rules! envelope { ($name:ident) => { pub struct $name { receipt: ChioReceipt } }; } envelope!(Wrapped); fn bad(s: &str) { serde_json::from_str::<Wrapped>(s); }",
        })
        self.assertTrue(any("raw decode" in finding for finding in findings), findings)
        self.assertFalse(any("unresolved" in finding for finding in findings), findings)

    def test_multiple_cyclic_globs_do_not_hide_a_later_export(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "mod first { use super::*; pub struct Plain {} } mod second { pub struct Wrapper { receipt: ChioReceipt } } pub use first::*; pub use second::*; mod consumer { use super::*; struct Envelope { item: Wrapper } fn bad(s: &str) { serde_json::from_str::<Envelope>(s); } }",
        })
        self.assertTrue(any("raw decode" in finding for finding in findings), findings)
        self.assertFalse(any("unresolved" in finding for finding in findings), findings)

    def test_middle_tuple_variant_field_remains_strict(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "enum Envelope { Item(u32, ChioReceipt, u32), Empty } fn bad(s: &str) { serde_json::from_str::<Envelope>(s); }",
        })
        self.assertTrue(any("raw decode" in finding for finding in findings), findings)

    def test_lowercase_unresolved_type_is_reported(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "struct Envelope { item: missing_type }",
        })
        self.assertTrue(any("unresolved" in finding and "missing_type" in finding for finding in findings), findings)

    def test_unresolved_path_requires_a_nonempty_allow_reason(self):
        key = ("crates/demo/src/lib.rs", "missing_type")
        files = {key[0]: "struct Envelope { item: missing_type }"}
        try:
            GATE.ALLOWED_TYPE_PATHS[key] = ""
            self.assertTrue(self.findings(files))
            GATE.ALLOWED_TYPE_PATHS[key] = "Fixture-only opaque scalar supplied by an external generator."
            self.assertEqual(self.findings(files), [])
        finally:
            GATE.ALLOWED_TYPE_PATHS.pop(key, None)

    def test_unresolved_include_is_reported(self):
        findings = self.findings({"crates/demo/src/lib.rs": 'include!(concat!(env!("OUT_DIR"), "/unknown.rs"));'})
        self.assertTrue(any("include source" in finding for finding in findings), findings)

    def test_generated_mirror_prefix_is_excluded(self):
        findings = self.findings({
            "crates/core/chio-core-types/src/_generated/chio_wire_v1.rs": "struct Envelope { item: missing_type, receipt: ChioReceipt } fn mirror(s: &str) { serde_json::from_str::<Envelope>(s); }",
        })
        self.assertEqual(findings, [])

    def test_test_only_enum_variant_preserves_following_types(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "enum Mode { Live, #[cfg(test)] Test(u32), } struct Envelope { receipt: ChioReceipt } fn bad(s: &str) { serde_json::from_str::<Envelope>(s); }",
        })
        self.assertTrue(any("raw decode" in finding for finding in findings), findings)
        self.assertFalse(any("unresolved" in finding for finding in findings), findings)

    def test_plain_wrappers_are_allowed(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "struct Envelope { value: u32 }\nfn good(s: &str) { serde_json::from_str::<Option<Envelope>>(s); }",
        })
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
