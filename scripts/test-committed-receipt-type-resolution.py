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
GATE.ALLOWED_INFERRED = {}


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

    def test_binary_crate_roots_keep_crate_paths_and_namespaces(self):
        findings = self.findings({
            "crates/demo/src/bin/strict.rs": "mod model { pub struct Envelope { receipt: ChioReceipt } } fn bad(s: &str) { serde_json::from_str::<crate::model::Envelope>(s); }",
            "crates/demo/src/bin/plain.rs": "mod model { pub struct Envelope { n: u32 } } fn good(s: &str) { serde_json::from_str::<crate::model::Envelope>(s); }",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("::bad", findings[0])

    def test_qualified_deserialize_keeps_the_complete_target(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "mod nested { pub struct Envelope { receipt: ChioReceipt } } fn bad(d: D) { crate::nested::Envelope::deserialize(d); }",
        })
        self.assertTrue(any("raw decode" in finding for finding in findings), findings)
        self.assertFalse(any("unresolved" in finding for finding in findings), findings)

    def test_repeated_macro_names_after_a_fixed_argument(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "macro_rules! wrapped { ($check:ident; $($name:ident),+ $(,)?) => { $(pub struct $name(ChioReceipt);)+ }; } wrapped!(validate; First, Second); fn bad(s: &str) { serde_json::from_str::<Second>(s); }",
        })
        self.assertTrue(any("raw decode" in finding for finding in findings), findings)
        self.assertFalse(any("unresolved" in finding for finding in findings), findings)

    def test_self_and_associated_bindings_are_type_syntax(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "enum Tree { Leaf(ChioReceipt), Children(Vec<Self>) } type Work = Box<dyn std::future::Future<Output = Tree>>; fn bad(s: &str) { serde_json::from_str::<Work>(s); }",
        })
        self.assertTrue(any("raw decode" in finding for finding in findings), findings)
        self.assertFalse(any("unresolved" in finding for finding in findings), findings)

    def test_array_lengths_and_nested_attributes_are_not_type_paths(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "struct Plain { #[arg(values = [1, 2], default_value = 1)] values: [u8; Purpose::ALL.len()] } fn good(s: &str) { serde_json::from_str::<Plain>(s); }",
        })
        self.assertEqual(findings, [])

    def test_external_glob_does_not_hide_an_unresolved_type(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "use serde::*; struct Envelope { item: missing_type }",
        })
        self.assertTrue(any("unresolved" in finding and "missing_type" in finding for finding in findings), findings)

    def test_later_cross_crate_glob_resolves_a_public_reexport(self):
        findings = self.findings({
            "crates/producer/src/lib.rs": "pub mod first {} pub mod second { mod data { pub struct Envelope { receipt: ChioReceipt } } pub use data::*; }",
            "crates/consumer/src/lib.rs": "use producer::{first::*, second::*}; fn bad(s: &str) { serde_json::from_str::<Envelope>(s); }",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("raw decode", findings[0])

    def test_macro_repeated_fields_preserve_the_supplied_types(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "macro_rules! envelope { ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => { pub struct $name { marker: u32, $(pub $field: $ty,)* } }; } envelope!(Wrapped { receipt: Option<ChioReceipt> }); fn bad(s: &str) { serde_json::from_str::<Wrapped>(s); }",
        })
        self.assertTrue(any("raw decode" in finding for finding in findings), findings)
        self.assertFalse(any("unresolved" in finding for finding in findings), findings)

    def test_cfg_all_test_module_does_not_enter_production_types(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "#[cfg(all(test, unix))] mod checks { struct OnlyInTests { temporary: NotProduction } } struct Plain { value: u32 }",
        })
        self.assertEqual(findings, [])

    def test_test_only_out_of_line_module_is_not_a_production_root(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "#[cfg(all(test, unix))] mod checks; struct Plain { value: u32 }",
            "crates/demo/src/checks.rs": "struct OnlyInTests { temporary: NotProduction }",
        })
        self.assertEqual(findings, [])

    def test_macro_template_local_types_are_not_instantiated_types(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "macro_rules! wrapped { ($name:ident) => { pub struct $name(u32); const _: () = { type Target = $name; }; }; } wrapped!(Plain); fn good(s: &str) { serde_json::from_str::<Plain>(s); }",
        })
        self.assertEqual(findings, [])

    def test_fixed_name_enum_generated_from_unit_variants(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "macro_rules! domain { ($($variant:ident),+) => { pub enum Domain { $($variant),+ } }; } domain!(First, Second); struct Plain { domain: Domain }",
        })
        self.assertEqual(findings, [])

    def test_aliased_external_glob_cannot_resolve_unknown_members(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "use serde as ser; use ser::*; struct Envelope { item: missing_type }",
        })
        self.assertTrue(any("unresolved" in finding and "missing_type" in finding for finding in findings), findings)

    def test_unknown_qualified_receipt_name_is_still_an_error(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "struct Envelope { item: missing::ChioReceipt }",
        })
        self.assertTrue(any("unresolved" in finding and "missing::ChioReceipt" in finding for finding in findings), findings)

    def test_glob_reexports_preserve_module_alias_paths(self):
        findings = self.findings({
            "crates/producer/src/lib.rs": "pub struct Envelope { receipt: ChioReceipt }",
            "crates/consumer/src/lib.rs": "use producer as remote; mod outer { use super::*; mod inner { use super::*; fn bad(s: &str) { serde_json::from_str::<remote::Envelope>(s); } } }",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("raw decode", findings[0])

    def test_package_name_does_not_inherit_another_crates_directory_name(self):
        findings = self.findings({
            "crates/library/worker/Cargo.toml": '[package]\nname = "worker"\nversion = "0.1.0"\n',
            "crates/library/worker/src/lib.rs": "pub struct Envelope { receipt: ChioReceipt }",
            "crates/products/worker/Cargo.toml": '[package]\nname = "worker-daemon"\nversion = "0.1.0"\n',
            "crates/products/worker/src/main.rs": "use worker::Envelope; fn bad(s: &str) { serde_json::from_str::<Envelope>(s); }",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("raw decode", findings[0])

    def test_test_only_brace_macro_preserves_following_production(self):
        for invocation in ["std::thread_local! { static X: u32 = 0; }", "probe! { nested! { x } };", "probe!(a < 3);", "probe![a < 3];"]:
            with self.subTest(invocation=invocation):
                findings = self.findings({
                    "crates/demo/src/lib.rs": "#[cfg(test)] " + invocation + " fn bad(s: &str) { serde_json::from_str::<ChioReceipt>(s); }",
                })
                self.assertEqual(len(findings), 1, findings)
                self.assertIn("raw decode", findings[0])

    def test_test_only_comparison_preserves_production_decode(self):
        for statement in ["assert!(a < 3);", "let x = a < 3;", "let x = a > 3;"]:
            with self.subTest(statement=statement):
                findings = self.findings({
                    "crates/demo/src/lib.rs": "fn bad(s: &str, a: u32) { #[cfg(test)] " + statement + " serde_json::from_str::<ChioReceipt>(s); }",
                })
                self.assertEqual(len(findings), 1, findings)
                self.assertIn("raw decode", findings[0])

    def test_test_only_generic_item_preserves_production_decode(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "#[cfg(test)] fn helper<T: Trait<Vec<(u32, u32)>>>() { noop::<T>(); } fn bad(s: &str) { serde_json::from_str::<ChioReceipt>(s); }",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("::bad: raw decode", findings[0])

    def test_test_only_block_expression_preserves_production_decode(self):
        for tail in ["serde_json::from_str::<ChioReceipt>(s); }", "} fn other(s: &str) { serde_json::from_str::<ChioReceipt>(s); }"]:
            with self.subTest(tail=tail):
                findings = self.findings({
                    "crates/demo/src/lib.rs": "fn bad(s: &str, a: u32) { #[cfg(test)] if a < 3 { noop(); } " + tail,
                })
                self.assertEqual(len(findings), 1, findings)
                self.assertIn("raw decode", findings[0])

    def test_macro_template_concrete_decode_is_scanned(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "macro_rules! m { () => { fn bad(s: &str) { serde_json::from_str::<ChioReceipt>(s); } }; } m!();",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("raw decode", findings[0])

    def test_macro_template_capture_does_not_hide_concrete_target(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "macro_rules! m { ($name:ident) => { fn bad(s: &str) { serde_json::from_str::<($name, ChioReceipt)>(s); } }; } m!(u32);",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("raw decode", findings[0])

    def test_macro_template_private_wrapper_keeps_concrete_strict_fields(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "macro_rules! m { ($ty:ty) => { struct Private { item: $ty, receipt: ChioReceipt } fn bad(s: &str) { serde_json::from_str::<Private>(s); } }; } m!(u32);",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("raw decode", findings[0])

    def test_macro_trait_capture_does_not_hide_concrete_decode(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "macro_rules! m { ($Name:ty) => { fn decode(d: D) { $Name::deserialize(d); ChioReceipt::deserialize(d); } }; } m!(u32);",
        })
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("raw decode", findings[0])

    def test_macro_template_unknown_concrete_target_is_an_error(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "macro_rules! m { () => { fn bad(s: &str) { serde_json::from_str::<missing::Envelope>(s); } }; } m!();",
        })
        self.assertTrue(any("unresolved type path missing::Envelope" in finding for finding in findings), findings)

    def test_macro_decoder_template_is_not_a_concrete_raw_decode(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "macro_rules! make { ($name:ident) => { struct $name(u32); const _: () = { type PrivateMirror = $name; fn deserialize(d: D) { PrivateMirror::deserialize(d); } }; }; } make!(Plain);",
        })
        self.assertEqual(findings, [])

    def test_unlisted_sibling_workspace_is_not_scanned(self):
        findings = self.findings({
            "Cargo.toml": '[workspace]\nmembers = ["formal/checks"]\n',
            "formal/checks/src/lib.rs": "struct Plain { n: u32 }",
            "formal/experiment/src/lib.rs": "struct Model { n: nat }",
        })
        self.assertEqual(findings, [])

    def raw_decodes(self, source, extra=None):
        files = {"crates/demo/src/lib.rs": source}
        files.update(extra or {})
        return [finding for finding in self.findings(files) if ": raw " in finding]

    def test_serde_json_submodule_aliases_are_raw_decodes(self):
        for source in [
            "use serde_json::de as json_de; fn bad(s: &str) { json_de::from_str::<ChioReceipt>(s); }",
            "use serde_json::{de as json_de, Value}; fn bad(s: &str) -> Result<ChioReceipt, E> { json_de::from_str(s) }",
            "use serde_json::value as json_value; fn bad(v: Value) { json_value::from_value::<ChioReceipt>(v); }",
            "use serde_json::de; fn bad(s: &[u8]) { de::from_slice::<ChioReceipt>(s); }",
            "use serde_json as json; use json::de as nested; fn bad(s: &str) { nested::from_str::<ChioReceipt>(s); }",
            "use serde_json::de::Deserializer as Stream; fn bad(s: &str) { Stream::from_str(s).into_iter::<ChioReceipt>(); }",
        ]:
            with self.subTest(source=source):
                self.assertEqual(len(self.raw_decodes(source)), 1, source)

    def test_serde_json_submodule_alias_reaches_child_modules(self):
        findings = self.raw_decodes("use serde_json::de as json_de; mod child { use super::*; fn bad(s: &str) { json_de::from_str::<ChioReceipt>(s); } }")
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("::bad", findings[0])

    def test_other_crate_submodule_alias_is_not_a_raw_decode(self):
        self.assertEqual(self.raw_decodes("use toml::de as toml_de; fn good(s: &str) { toml_de::from_str::<ChioReceipt>(s); }"), [])

    def test_placeholder_targets_take_the_contextual_type(self):
        for source in [
            "fn bad(d: D) -> Result<Option<ChioReceipt>, E> { <Option<_> as Deserialize>::deserialize(d) }",
            "fn bad(d: D) -> Result<Option<ChioReceipt>, E> { let r = <Option<_>>::deserialize(d)?; Ok(r) }",
            "fn bad(s: &str) -> Result<Vec<ChioReceipt>, E> { serde_json::from_str::<Vec<_>>(s) }",
            "fn bad(s: &str) { let r: Vec<ChioReceipt> = serde_json::from_str::<Vec<_>>(s).unwrap_or_default(); }",
        ]:
            with self.subTest(source=source):
                self.assertEqual(len(self.raw_decodes(source)), 1, source)

    def test_placeholder_target_with_a_named_strict_part_is_raw(self):
        findings = self.raw_decodes("fn load<S, T: DeserializeOwned>(s: &S, v: Value) -> Result<T, E> { serde_json::from_value(v) } fn bad(s: &S, v: Value) { consume(load::<_, ChioReceipt>(s, v)); }")
        self.assertEqual(len(findings), 1, findings)

    def test_placeholder_target_of_a_plain_type_is_allowed(self):
        self.assertEqual(self.raw_decodes("fn good(s: &str) -> Result<Vec<u32>, E> { serde_json::from_str::<Vec<_>>(s) }"), [])

    def test_placeholder_target_without_context_is_refused(self):
        findings = self.findings({"crates/demo/src/lib.rs": "fn unknown(s: &str) { consume(serde_json::from_str::<Vec<_>>(s)); }"})
        self.assertEqual(findings, ["crates/demo/src/lib.rs::unknown: inferred decode target serde_json::from_str::<Vec<_>>(s)"])

    def test_tail_match_and_if_decodes_take_the_return_type(self):
        for source in [
            "fn bad(s: &str, a: bool) -> Result<ChioReceipt, E> { match a { true => serde_json::from_str(s), false => Err(e()) } }",
            "fn bad(s: &str, a: bool) -> Result<ChioReceipt, E> { match a { true => { check(); serde_json::from_str(s) } false => Err(e()) } }",
            "fn bad(s: &str, a: bool) -> Result<ChioReceipt, E> { if a { serde_json::from_str(s) } else { Err(e()) } }",
            "fn bad(s: &str, a: u8) -> Result<ChioReceipt, E> { if a == 0 { Err(e()) } else if a == 1 { serde_json::from_str(s) } else { Err(e()) } }",
            "fn bad(s: &str, a: Option<u8>) -> Result<ChioReceipt, E> { if let Some(_) = a { match a { _ => serde_json::from_str(s) } } else { Err(e()) } }",
            "fn bad(s: &str, a: bool) -> Result<ChioReceipt, E> { let r = if a { serde_json::from_str(s)? } else { return Err(e()) }; Ok(r) }",
        ]:
            with self.subTest(source=source):
                self.assertEqual(len(self.raw_decodes(source)), 1, source)

    def test_tail_match_of_a_plain_type_is_allowed(self):
        self.assertEqual(self.raw_decodes("fn good(s: &str, a: bool) -> Result<u32, E> { match a { true => serde_json::from_str(s), false => Ok(0) } }"), [])

    def test_inferred_decode_without_a_known_target_is_refused(self):
        findings = self.findings({"crates/demo/src/lib.rs": "fn unknown(s: &str) { let r = serde_json::from_str(s).unwrap(); consume(r); }"})
        self.assertEqual(findings, ["crates/demo/src/lib.rs::unknown: inferred decode target serde_json::from_str(s)"])

    def test_inferred_decode_allowlist_requires_a_reason(self):
        files = {"crates/demo/src/lib.rs": "fn unknown(s: &str) { let r = serde_json::from_str(s).unwrap(); consume(r); }"}
        key = ("crates/demo/src/lib.rs", "unknown", "serde_json::from_str(s)")
        try:
            GATE.ALLOWED_INFERRED[key] = " "
            self.assertEqual(len(self.findings(files)), 1)
            GATE.ALLOWED_INFERRED[key] = "consume takes a plain Settings value."
            self.assertEqual(self.findings(files), [])
            files["crates/demo/src/lib.rs"] = "fn unknown(s: &str) {}"
            self.assertEqual(self.findings(files), ["crates/demo/src/lib.rs::unknown: inferred decode allowance serde_json::from_str(s) matched no call"])
        finally:
            GATE.ALLOWED_INFERRED.pop(key, None)

    def test_renamed_axum_extractors_are_refused(self):
        for source in [
            "use axum::Json as Payload; async fn bad(Payload(r): Payload<ChioReceipt>) {}",
            "use axum::extract::{Json as Body, State}; async fn bad(State(s): State<u32>, Body(r): Body<ChioReceipt>) {}",
            "use axum::extract::Query as Params; async fn bad(Params(r): Params<ChioReceipt>) {}",
            "use axum::Json as Payload; async fn bad(req: Request, st: &S) { let Payload(r): Payload<ChioReceipt> = Payload::from_request(req, st).await.unwrap(); }",
            "use axum::Json as Payload; async fn bad(req: Request, st: &S) { let r = Payload::<ChioReceipt>::from_request(req, st).await; }",
            "use axum as web; async fn bad(web::Json(r): web::Json<ChioReceipt>) {}",
        ]:
            with self.subTest(source=source):
                self.assertEqual(len(self.raw_decodes(source)), 1, source)

    def test_renamed_axum_extractor_of_a_plain_type_is_allowed(self):
        self.assertEqual(self.raw_decodes("use axum::Json as Payload; async fn good(Payload(r): Payload<u32>) {}"), [])

    def test_macro_expanded_decodes_take_the_invocation_types(self):
        for source in [
            "macro_rules! decoder { ($name:ident, $ty:ty) => { fn $name(s: &str) -> $ty { serde_json::from_str(s).unwrap() } }; } decoder!(bad, ChioReceipt);",
            "macro_rules! decoder { ($name:ident, $ty:ty) => { fn $name(s: &str) { serde_json::from_str::<$ty>(s); } }; } decoder!(bad, ChioReceipt);",
            "struct Envelope { receipt: ChioReceipt } macro_rules! decoder { ($ty:ty) => { fn bad(s: &str) { serde_json::from_str::<Vec<$ty>>(s); } }; } decoder!(Envelope);",
            "macro_rules! decoder { ($ty:ty) => { fn bad(d: D) -> Result<$ty, E> { <$ty>::deserialize(d) } }; } decoder!(ChioReceipt);",
        ]:
            with self.subTest(source=source):
                self.assertEqual(len(self.raw_decodes(source)), 1, source)

    def test_expression_macro_decodes_are_refused_at_each_expansion(self):
        for source in [
            "macro_rules! decode_receipt { ($raw:expr) => { serde_json::from_str::<ChioReceipt>($raw) }; }",
            "macro_rules! decode { ($ty:ty, $raw:expr) => { serde_json::from_str::<$ty>($raw) }; } fn bad(s: &str) { let _ = decode!(ChioReceipt, s); }",
            "macro_rules! decode { ($raw:expr) => { serde_json::from_str($raw) }; } fn bad(s: &str) -> Result<ChioReceipt, E> { decode!(s) }",
            "macro_rules! decode { ($raw:expr) => {{ let r = serde_json::from_str($raw)?; r }}; } fn bad(s: &str) -> Result<(), E> { let r: ChioReceipt = decode!(s); Ok(()) }",
        ]:
            with self.subTest(source=source):
                self.assertEqual(len(self.raw_decodes(source)), 1, source)

    def test_expression_macro_decodes_of_plain_types_are_allowed(self):
        for source in [
            "macro_rules! decode { ($ty:ty, $raw:expr) => { serde_json::from_str::<$ty>($raw) }; } fn good(s: &str) { let _ = decode!(u32, s); }",
            "macro_rules! decode { ($raw:expr) => { serde_json::from_str($raw) }; } fn good(s: &str) -> Result<u32, E> { decode!(s) }",
            "macro_rules! decode { ($ty:ty, $raw:expr) => { serde_json::from_str::<$ty>($raw) }; }",
        ]:
            with self.subTest(source=source):
                self.assertEqual(self.findings({"crates/demo/src/lib.rs": source}), [], source)

    def test_tail_match_scrutinee_decode_takes_the_return_type(self):
        for source in [
            "fn bad(s: &str) -> Result<ChioReceipt, E> { match serde_json::from_str(s) { Ok(r) => Ok(r), Err(e) => Err(wrap(e)) } }",
            "fn bad(s: &str) -> Option<ChioReceipt> { if let Ok(r) = serde_json::from_str(s) { Some(r) } else { None } }",
        ]:
            with self.subTest(source=source):
                self.assertEqual(len(self.raw_decodes(source)), 1, source)

    def test_macro_expanded_decode_in_another_file_is_refused(self):
        findings = self.raw_decodes(
            "#[macro_use] mod macros; mod user;",
            {
                "crates/demo/src/macros.rs": "macro_rules! decoder { ($ty:ty) => { fn decoded(s: &str) -> $ty { serde_json::from_str(s).unwrap() } }; }",
                "crates/demo/src/user.rs": "decoder!(ChioReceipt);",
            },
        )
        self.assertEqual(len(findings), 1, findings)

    def test_macro_expanded_decode_of_a_plain_type_is_allowed(self):
        self.assertEqual(self.raw_decodes("macro_rules! decoder { ($name:ident, $ty:ty) => { fn $name(s: &str) { serde_json::from_str::<$ty>(s); } }; } decoder!(good, u32);"), [])

    def test_helper_calls_resolve_to_the_generic_helper(self):
        helper = "use std::fs; mod input { pub fn decode<T: DeserializeOwned>(t: &str) -> Result<T, E> { serde_json::from_str(t) } pub fn read<T: DeserializeOwned>(p: &[u8]) -> Result<T, E> { serde_json::from_slice(p) } } mod other { pub fn decode(p: &str) -> u32 { 0 } } "
        cases = [
            ("fn bad(t: &str) -> Result<ChioReceipt, E> { crate::input::decode(t) }", 1),
            ("use crate::input::decode as parse; fn bad(t: &str) -> Result<ChioReceipt, E> { parse(t) }", 1),
            ("fn good(t: &str) -> u32 { let n = crate::other::decode(t); n }", 0),
            ("fn good(p: &str) { let bytes = std::fs::read(p); consume(bytes); }", 0),
            ("mod nested { use super::*; fn good(p: &str) { let bytes = fs::read(p); consume(bytes); } }", 0),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                findings = self.findings({"crates/demo/src/lib.rs": helper + source})
                self.assertEqual(len(findings), expected, findings)

    def test_generic_helper_with_an_inferred_decode_checks_its_callers(self):
        helper = "fn decode<T: DeserializeOwned>(t: &str) -> Result<T, E> { let v = serde_json::from_str(t)?; post(v) } "
        self.assertEqual(self.findings({"crates/demo/src/lib.rs": helper + "fn good(t: &str) -> Result<u32, E> { decode(t) }"}), [])
        findings = self.findings({"crates/demo/src/lib.rs": helper + "fn bad(t: &str) -> Result<ChioReceipt, E> { decode(t) }"})
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("::bad: raw decode decode(t)", findings[0])

    def test_tail_decode_through_a_closure_argument(self):
        findings = self.raw_decodes("fn bad(v: &str) -> Result<ChioReceipt, E> { serde_json::from_str(v).map_err(|_| { wrap() }) }")
        self.assertEqual(len(findings), 1, findings)

    def test_associated_call_does_not_name_a_free_helper(self):
        source = "fn decode<T: DeserializeOwned>(t: &str) -> Result<T, E> { serde_json::from_str(t) } struct Record { n: u32 } fn good(t: &str) { let r = Record::decode(t); consume(r); }"
        self.assertEqual(self.findings({"crates/demo/src/lib.rs": source}), [])

    def test_local_generic_extractor_over_a_raw_decode_is_an_extractor(self):
        extractor = "pub struct Bounded<T>(pub T); impl<S, T> FromRequest<S> for Bounded<T> where T: DeserializeOwned { type Rejection = E; async fn from_request(request: Request, _state: &S) -> Result<Self, E> { let bytes = read(request); serde_json::from_slice(&bytes).map(Self).map_err(wrap) } } "
        findings = self.findings({"crates/demo/src/lib.rs": extractor + "async fn bad(Bounded(r): Bounded<ChioReceipt>) {}"})
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("::bad: raw extractor Bounded<ChioReceipt>", findings[0])
        self.assertEqual(self.findings({"crates/demo/src/lib.rs": extractor + "async fn good(Bounded(r): Bounded<u32>) {}"}), [])

    def test_plain_wrappers_are_allowed(self):
        findings = self.findings({
            "crates/demo/src/lib.rs": "struct Envelope { value: u32 }\nfn good(s: &str) { serde_json::from_str::<Option<Envelope>>(s); }",
        })
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
