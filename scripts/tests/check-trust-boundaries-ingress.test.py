#!/usr/bin/env python3
"""Calibrate request extraction and helper-consumer inventory coverage."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("boundary_gate", ROOT / "scripts/check-trust-boundaries.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class IngressCensusCalibration(unittest.TestCase):
    def census(self, files):
        with patch.object(gate, "sources", return_value=iter(files.items())):
            found, _ = gate.scan(ROOT, {"signed_input_files": []})
        return found.get("ingress_census", {})

    def test_request_extractors_are_seen_but_responses_are_not(self):
        path = "crates/platform/demo/src/lib.rs"
        code = """
        use axum::{Json, extract::Form};
        async fn publish(Json(body): Json<SignedDocument>) -> Json<Reply> {
            Json(Reply::new(body))
        }
        async fn form(Form(body): Form<FormBody>) {}
        async fn reply() -> Json<Reply> { Json(Reply::default()) }
        """
        rows = self.census({path: code}).get(path, [])
        self.assertIn("publish::request-json::SignedDocument", rows)
        self.assertIn("form::request-form::FormBody", rows)
        self.assertFalse(any(row.startswith("reply::") for row in rows), rows)

    def test_multiline_qualified_alias_and_optional_extractors(self):
        path = "crates/platform/demo/src/lib.rs"
        code = """
        use axum::Json as BodyJson;
        use axum::extract::{Form as BodyForm};
        async fn signed(body: Option<BodyJson<Envelope<SignedPolicy>>>) {}
        async fn posted(body: axum::extract::Json<SignedPolicy>) {}
        async fn form(body: Result<BodyForm<Fields>, Rejection>) {}
        """
        rows = self.census({path: code}).get(path, [])
        self.assertIn("signed::request-json::Envelope<SignedPolicy>", rows)
        self.assertIn("posted::request-json::SignedPolicy", rows)
        self.assertIn("form::request-form::Fields", rows)

    def test_json_response_readers_exclude_request_serialization(self):
        path = "crates/platform/demo/src/client.rs"
        code = """
        async fn receive(response: reqwest::Response) { response.json::<Reply>().await; }
        async fn infer(response: reqwest::Response) { let body: Reply = response.json().await; }
        async fn send(client: reqwest::Client, value: Request) { client.post(url).json(&value).send().await; }
        """
        rows = self.census({path: code}).get(path, [])
        self.assertIn("receive::http-response-json::json", rows)
        self.assertIn("infer::http-response-json::json", rows)
        self.assertFalse(any(row.startswith("send::") for row in rows), rows)

    def test_non_json_formats_and_aliases_are_recorded(self):
        path = "crates/platform/demo/src/config.rs"
        code = """
        use serde_yaml as yaml;
        use toml::from_str as parse_toml;
        fn yaml() { yaml::from_slice(bytes); }
        fn toml() { parse_toml(text); }
        fn cbor() { ciborium::de::from_reader(bytes); }
        fn binary() { bincode::deserialize(bytes); }
        """
        rows = self.census({path: code}).get(path, [])
        for expected in ["yaml::format-yaml::from_slice", "toml::format-toml::from_str",
                         "cbor::format-cbor::from_reader", "binary::format-bincode::deserialize"]:
            self.assertIn(expected, rows)

    def test_shared_reader_consumers_survive_cross_module_migration(self):
        caller = "crates/platform/demo/src/handlers.rs"
        helper = "crates/platform/demo/src/input.rs"
        files = {
            caller: "use crate::input::read as bounded_read; fn publish(bytes: &[u8]) { bounded_read(bytes); }",
            helper: "fn read(bytes: &[u8]) { UntrustedJsonText::from_wire(bytes, 100)?.decode_signed() }",
        }
        rows = self.census(files).get(caller, [])
        self.assertIn(f"publish::shared-reader::{helper}::read", rows)

    def test_transitive_reader_consumers_are_retained(self):
        caller = "crates/platform/demo/src/handlers.rs"
        helper = "crates/platform/demo/src/input.rs"
        files = {
            caller: "fn publish(bytes: &[u8]) { crate::input::read(bytes); }",
            helper: "fn read(bytes: &[u8]) { decode(bytes) } fn decode(bytes: &[u8]) { serde_json::from_slice(bytes) }",
        }
        rows = self.census(files).get(caller, [])
        self.assertIn(f"publish::shared-reader::{helper}::read", rows)

    def test_parent_glob_imports_retain_cbor_aliases(self):
        parent = "crates/platform/demo/src/attestation.rs"
        child = "crates/platform/demo/src/attestation/verify.rs"
        files = {
            parent: "use ciborium::de::from_reader as cbor_from_reader;",
            child: "use super::*; fn verify(bytes: &[u8]) { cbor_from_reader(bytes); }",
        }
        self.assertIn("verify::format-cbor::from_reader", self.census(files).get(child, []))

    def test_cross_crate_reexported_reader_retains_consumers(self):
        caller = "crates/platform/demo/src/handlers.rs"
        facade = "crates/platform/input-lib/src/lib.rs"
        helper = "crates/platform/input-lib/src/json.rs"
        files = {
            caller: "fn publish(bytes: &[u8]) { input_lib::read(bytes); }",
            facade: "pub use crate::json::read;",
            helper: "fn read(bytes: &[u8]) { UntrustedJsonText::from_wire(bytes, 100)?.decode_signed() }",
        }
        self.assertIn(f"publish::shared-reader::{helper}::read", self.census(files).get(caller, []))

    def test_reexported_module_alias_retains_reader_consumers(self):
        caller = "crates/platform/demo/src/handlers.rs"
        facade = "crates/platform/input-lib/src/lib.rs"
        helper = "crates/platform/input-lib/src/json.rs"
        files = {
            caller: "fn publish(bytes: &[u8]) { input_lib::readers::read(bytes); }",
            facade: "pub use crate::json as readers;",
            helper: "fn read(bytes: &[u8]) { UntrustedJsonText::from_wire(bytes, 100)?.decode_signed() }",
        }
        self.assertIn(f"publish::shared-reader::{helper}::read", self.census(files).get(caller, []))

    def test_original_reader_type_alias_retains_owner_and_caller(self):
        path = "crates/platform/demo/src/input.rs"
        code = """
        use chio_core::canonical::UntrustedJsonText as Input;
        fn read(bytes: &[u8]) { Input::from_wire(bytes, 100)?.decode_signed() }
        fn publish(bytes: &[u8]) { read(bytes) }
        """
        rows = self.census({path: code}).get(path, [])
        self.assertIn("read::original-json-reader::UntrustedJsonText", rows)
        self.assertIn(f"publish::shared-reader::{path}::read", rows)

    def test_glob_reexport_cycle_terminates_for_an_unresolved_call(self):
        facade = "crates/platform/input-lib/src/lib.rs"
        helper = "crates/platform/input-lib/src/json.rs"
        caller = "crates/platform/demo/src/lib.rs"
        files = {
            facade: "pub use crate::json::*;",
            helper: "use super::*; fn read(bytes: &[u8]) { UntrustedJsonText::from_wire(bytes, 100)?.decode_signed() }",
            caller: "fn publish(bytes: &[u8]) { input_lib::read(bytes); input_lib::unresolved(); }",
        }
        rows = self.census(files).get(caller, [])
        self.assertEqual(rows, [f"publish::shared-reader::{helper}::read"])

    def test_function_reexport_does_not_replace_a_same_named_module(self):
        facade = "crates/platform/input-lib/src/lib.rs"
        helper = "crates/platform/input-lib/src/json.rs"
        caller = "crates/platform/demo/src/lib.rs"
        files = {
            facade: "pub mod json; pub use json::{json, read};",
            helper: "fn json() {} fn read(bytes: &[u8]) { UntrustedJsonText::from_wire(bytes, 100)?.decode_signed() }",
            caller: "fn publish(bytes: &[u8]) { input_lib::json::read(bytes); input_lib::json::Missing::new(); }",
        }
        self.assertEqual(self.census(files).get(caller, []), [f"publish::shared-reader::{helper}::read"])

    def test_router_method_and_path_composition_is_observed(self):
        code = """
        fn router() { Router::new()
            .route(POLICY_PATH, get(load).put(publish).delete(remove))
            .route(IMPORT_PATH, post(import).layer(DefaultBodyLimit::max(64 * 1024)))
        }
        """
        self.assertEqual(gate._ingress.route_bindings(code, gate._contracts), [
            ("DELETE", "POLICY_PATH", "remove"), ("GET", "POLICY_PATH", "load"),
            ("POST", "IMPORT_PATH", "import"), ("PUT", "POLICY_PATH", "publish"),
        ])

    def test_noise_and_test_only_extractors_do_not_enter_census(self):
        path = "crates/platform/demo/src/lib.rs"
        code = '''
        // async fn fake(Json(x): Json<Secret>) {}
        const DOC: &str = "async fn fake(Json(x): Json<Secret>) {}";
        #[cfg(test)] mod tests { async fn fake(Json(x): Json<Secret>) {} }
        fn response() -> Json<Value> { Json(Value::Null) }
        '''
        self.assertEqual(self.census({path: gate.without_test_items(code)}), {})


class IngressContractCalibration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = json.loads((ROOT / gate._ingress.INVENTORY).read_text())
        cls.census = json.loads((ROOT / gate.CATALOG).read_text())["ingress_census"]
        paths = {row["source"] for row in cls.inventory["requests"]}
        paths.update(row["router"] for row in cls.inventory["requests"] if "router" in row)
        paths.add(gate._ingress.CONTROL_INPUT)
        cls.files = {path: (ROOT / path).read_text() for path in paths}

    def errors(self, path=None, edit=None, census=None):
        files = self.files.copy()
        if path:
            files[path] = edit(files[path])
        return gate._ingress.check(ROOT, census or self.census, files, gate._contracts, gate._lexer.blank_rust_noise)

    def test_registered_routes_and_modes_match_production(self):
        self.assertEqual(self.errors(), [])

    def test_handler_method_change_is_not_hidden_by_same_extractor_count(self):
        path = "crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs"
        errors = self.errors(path, lambda text: text.replace(".put(handle_upsert_verifier_policy)", ".post(handle_upsert_verifier_policy)"))
        self.assertTrue(any("method/path/handler" in error for error in errors), errors)

    def test_commented_middleware_does_not_count_as_installation(self):
        path = "crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs"
        needle = gate._ingress.MIDDLEWARE.search(self.files[path]).group()
        self.assertIn(needle, self.files[path])
        errors = self.errors(path, lambda text: text.replace(needle, "/* " + needle + " */"))
        self.assertTrue(any("not installed" in error for error in errors), errors)

    def test_middleware_before_protected_routes_is_not_accepted(self):
        path = "crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs"
        layer = gate._ingress.MIDDLEWARE.search(self.files[path]).group()
        changed = self.files[path].replace(layer, "")
        changed = changed.replace(".route(ISSUE_CAPABILITY_PATH", layer + ".route(ISSUE_CAPABILITY_PATH", 1)
        self.assertNotEqual(changed, self.files[path])
        self.assertTrue(any("composition" in error for error in self.errors(path, lambda _: changed)))

    def test_new_literal_alias_to_existing_handler_needs_composition_review(self):
        path = "crates/platform/chio-control-plane/src/trust_control/service_runtime/router.rs"
        needle = ".route(ISSUE_CAPABILITY_PATH"
        changed = self.files[path].replace(needle, '.route("/alias", post(handle_publish_certification))' + needle, 1)
        self.assertNotEqual(changed, self.files[path])
        self.assertTrue(any("composition" in error for error in self.errors(path, lambda _: changed)))

    def test_signed_route_cannot_be_relabelled_as_an_unsigned_document(self):
        path = gate._ingress.CONTROL_INPUT
        needle = '("POST", CERTIFICATIONS_PATH) => Some((Mode::Signed, 1024 * 1024))'
        self.assertIn(needle, self.files[path])
        errors = self.errors(path, lambda text: text.replace(needle, needle.replace("Mode::Signed", "Mode::Document")))
        self.assertTrue(any("mode or body limit" in error for error in errors), errors)

    def test_body_limit_growth_requires_explicit_review(self):
        path = gate._ingress.CONTROL_INPUT
        errors = self.errors(path, lambda text: text.replace("4 * 1024", "8 * 1024", 1))
        self.assertTrue(any("mode or body limit" in error for error in errors), errors)

    def test_new_request_in_an_existing_file_needs_a_semantic_disposition(self):
        census = {path: list(rows) for path, rows in self.census.items()}
        path = "crates/platform/chio-control-plane/src/trust_control/certification_handlers.rs"
        census[path].append("new_authority::request-json::SignedNewAuthority")
        self.assertTrue(any("dispositions" in error for error in self.errors(census=census)))

    def test_format_or_transport_input_in_a_new_file_needs_disposition(self):
        census = {path: list(rows) for path, rows in self.census.items()}
        census["crates/platform/demo/src/authority.rs"] = ["fetch::http-response-json::json"]
        self.assertTrue(any("alternate-format" in error for error in self.errors(census=census)))


if __name__ == "__main__":
    unittest.main()
