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

    def test_signed_and_canonical_readers_cannot_downgrade_to_document(self):
        for path, method in [
            (gate.STORE + "/receipt_store/support/signed_readback.rs", "decode_signed"),
            (gate.STORE + "/receipt_store/support/receipt_verify.rs", "decode_signed"),
            ("crates/security/chio-keyring/src/lib.rs", "decode_canonical"),
        ]:
            with self.subTest(path=path):
                self.assertIn("." + method + "(", self.files[path])
                errors = self.errors(path, lambda text: text.replace("." + method + "(", ".decode_document(", 1))
                self.assertTrue(any("decoding contract" in error for error in errors), errors)

    def test_real_mixed_owner_swap_is_rejected_with_identical_method_counts(self):
        path = "crates/products/chio-api-protect/src/proxy/input.rs"
        def swap(text):
            changed = text.replace(".decode_signed()", ".SWAP()", 1).replace(".decode_document()", ".decode_signed()", 1).replace(".SWAP()", ".decode_document()", 1)
            for method in ("decode_signed", "decode_document"):
                self.assertEqual(changed.count(method), text.count(method))
            return changed
        self.assertTrue(any("decoding contract" in error for error in self.errors(path, swap)))

    def test_inventory_only_promotion_of_all_raw_baselines_is_rejected(self):
        catalog = json.loads(json.dumps(self.catalog))
        promoted = []
        for path, contract in catalog["decoder_file_contracts"].items():
            if contract["kind"] == "raw-input-baseline":
                promoted.append(path)
                contract.update(kind="reviewed-bounded-input", contract="reviewed")
        self.assertTrue(promoted)
        with patch.object(self, "catalog", catalog):
            errors = self.errors()
        for path in promoted:
            self.assertTrue(any("reader evidence" in error and path in error for error in errors), path)

    def test_inventory_only_promotion_cannot_copy_an_unrelated_reader(self):
        catalog = json.loads(json.dumps(self.catalog))
        reviewed = next(row for row in catalog["decoder_file_contracts"].values() if row.get("readers"))
        for path, row in catalog["decoder_file_contracts"].items():
            if row["kind"] == "raw-input-baseline":
                row.update(kind="reviewed-bounded-input", contract="reviewed", readers=reviewed["readers"])
                catalog["reviewed_product_readers"][path] = {"contract": "reviewed"}
                catalog["signed_input_files"].append(path)
        # Supply all the census metadata too, as in CA2's stronger mutation.
        with patch.object(gate, "sources", return_value=iter(self.files.items())):
            scan = gate.scan(ROOT, catalog)[0]
        catalog["raw_decoders"] = scan["raw_decoders"]
        catalog["raw_decoder_contracts"] = {site: "reviewed" for site in scan["raw_decoders"]}
        with patch.object(self, "catalog", catalog):
            errors = self.errors()
        self.assertTrue(any("reader evidence" in error for error in errors), errors)
        self.assertFalse(any("raw_decoders changed" in error for error in errors), errors)

    def test_named_reader_and_api_evidence_must_exist_in_that_owner(self):
        path = "crates/core/chio-core-types/src/canonical/signed_json.rs"
        for field, bogus in [("reader", "not_a_reader"), ("apis", ["nonexistent_bounded_api"]), ("apis", ["UntrustedJsonText::from_wire#1::decode_signed"])]:
            with self.subTest(field=field, bogus=bogus):
                catalog = json.loads(json.dumps(self.catalog))
                row = catalog["decoder_file_contracts"][path]["readers"][0]
                row[field] = bogus
                with patch.object(self, "catalog", catalog):
                    errors = self.errors()
                self.assertTrue(any("reader evidence" in error and path in error for error in errors), errors)

    def test_raw_reader_loses_evidence_when_actual_preflight_is_removed(self):
        for path, call in [
            ("crates/core/chio-core-types/src/canonical/signed_json.rs", "validate_number_tokens(input)?;"),
            ("crates/security/chio-quarantine/src/correlation.rs", "validate_stored_body(partial)?;"),
        ]:
            with self.subTest(path=path):
                self.assertIn(call, self.files[path])
                errors = self.errors(path, lambda text: text.replace(call, "", 1))
                self.assertTrue(any("reader evidence" in error and path in error for error in errors), errors)

    def test_checkpoint_typed_evidence_requires_its_closed_source_shape(self):
        path = "crates/kernel/chio-kernel/src/checkpoint.rs"
        errors = self.errors(path, lambda text: text.replace("pub checkpoint_seq: u64,", "pub checkpoint_seq: serde_json::Value,", 1))
        self.assertTrue(any("reader evidence" in error and "checkpoint_validate.rs" in error for error in errors), errors)

    def test_unsigned_document_and_typed_projection_contracts_remain_supported(self):
        self.assertTrue(any(site.endswith("::decode_document") for site in self.catalog["decoding_contracts"]))
        path = "crates/products/chio-api-protect/src/proxy/input.rs"
        self.assertEqual(self.errors(path, lambda text: text + '\n// let sample = "input.decode_signed()";\n'), [])

    def test_reviewed_authority_owner_cannot_be_unregistered(self):
        catalog = json.loads(json.dumps(self.catalog))
        path = next(iter(catalog["reviewed_authority_owners"]))
        catalog["signed_input_files"].remove(path)
        with patch.object(self, "catalog", catalog):
            self.assertTrue(any("reviewed authority owner is unregistered" in error for error in self.errors()))

    def test_reviewed_authority_owner_cannot_return_to_baseline(self):
        catalog = json.loads(json.dumps(self.catalog))
        path = next(path for path in catalog["reviewed_authority_owners"] if path in catalog["decoder_file_contracts"])
        catalog["decoder_file_contracts"][path]["kind"] = "raw-input-baseline"
        with patch.object(self, "catalog", catalog):
            self.assertTrue(any("reviewed authority owner regressed to baseline" in error for error in self.errors()))

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
        path = "crates/kernel/chio-runtime-core/src/serde_io.rs"
        self.assertIn(path, self.catalog["signed_input_files"])
        errors = self.errors(path, lambda text: text + '\nfn bypass(s: &str) { serde_json::from_str(s) }')
        self.assertTrue(any("raw_decoders" in error for error in errors), errors)

    def test_new_unregistered_reader_requires_classification(self):
        errors = self.errors("crates/new/src/reader.rs", lambda _: 'fn load(s: &str) { serde_json::from_str(s) }')
        self.assertTrue(any("decoder census changed" in error for error in errors), errors)

    def test_imported_decoder_cannot_bypass_registered_owner(self):
        path = "crates/kernel/chio-runtime-core/src/serde_io.rs"
        self.assertIn(path, self.catalog["signed_input_files"])
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
        path = "crates/kernel/chio-runtime-core/src/serde_io.rs"
        self.assertIn(path, self.catalog["signed_input_files"])
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

    def test_borrowed_dispatch_proof_fields_are_sealed(self):
        path = "crates/platform/chio-control-plane/src/security/adapters/native_flow.rs"
        errors = self.errors(path, lambda source: source.replace("    prepared_at: u64,", "    pub prepared_at: u64,", 1))
        self.assertTrue(any("proof fields are not sealed: PreparedNativeFlowDispatch" in error for error in errors), errors)

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


class ContractScopeCalibration(unittest.TestCase):
    def contracts(self, source):
        return gate._contracts.decoding_contracts(gate._lexer.blank_rust_noise(source))

    def evidence(self, source, path="crates/synthetic/src/reader.rs"):
        code = gate._lexer.blank_rust_noise(source)
        supports = {
            support: gate._lexer.blank_rust_noise((ROOT / support).read_text())
            for support in gate._contracts.SUPPORT_PATHS
        }
        if path in supports:
            supports[path] = code
        return gate._contracts.reader_evidence(
            path, code, list(gate.json_decoders(code)), code, supports
        )

    def test_siem_pin_reader_requires_typed_list_and_both_bounds(self):
        path = "crates/products/chio-wall/src/commands/siem_pins.rs"
        source = (ROOT / path).read_text().split("#[cfg(test)]", 1)[0]
        self.assertTrue(all(row["checked"] for row in self.evidence(source, path)))
        for before, after in (
            ("value.len() > MAX_CONFIG_BYTES", "false"),
            ("Vec<String>", "serde_json::Value"),
            ("encoded.is_empty() || encoded.len() > MAX_KEYS", "false"),
        ):
            self.assertIn(before, source)
            with self.subTest(before=before):
                self.assertTrue(any(not row["checked"] for row in self.evidence(source.replace(before, after, 1), path)))

    def test_mcp_admission_reader_requires_full_structural_preflight(self):
        path = "crates/protocol/chio-mcp-edge/src/ingress/budget/admission.rs"
        source = (ROOT / path).read_text()
        self.assertTrue(all(row["checked"] for row in self.evidence(source, path)))
        for before, after in (
            ("wire_bytes: text.len()", "wire_bytes: 0"),
            ("counter.footprint.exceeded()", "None"),
            ("ValueSeed(&mut counter)", "UncheckedValue"),
            ("decoder.end()", "Ok(())"),
            ("self.footprint.checked_add(Footprint", "self.footprint.unchecked_add(Footprint"),
            ("next.exceeded()", "None"),
            ("self.0.add(1, 0)?", "Ok(())?"),
        ):
            self.assertIn(before, source)
            with self.subTest(before=before):
                self.assertTrue(any(not row["checked"] for row in self.evidence(source.replace(before, after, 1), path)))

    def test_mcp_control_projection_requires_borrowed_fields_and_scalar_bound(self):
        path = "crates/protocol/chio-mcp-edge/src/ingress/inbox.rs"
        source = (ROOT / path).read_text()
        observed = self.evidence(source, path)
        self.assertTrue(observed, observed)
        self.assertTrue(all(row["checked"] for row in observed), observed)
        for before, after in (
            ("const IDENTITY_BYTES: usize = 512;", "const IDENTITY_BYTES: usize = 512 * 1024 * 1024;"),
            ("jsonrpc: Option<&'a RawValue>", "jsonrpc: Option<serde_json::Value>"),
            ("task: Option<&'a RawValue>", "task: Option<Box<RawValue>>"),
            ("<&'de RawValue>::deserialize(decoder)", "Value::deserialize(decoder)"),
            ("raw.get().len() <= IDENTITY_BYTES", "true"),
            ("serde_json::from_str(raw.get())", "serde_json::from_str(other)"),
            ("serde_json::from_slice::<Envelope<'_>>(bytes)", "serde_json::from_slice::<Value>(bytes)"),
            ("bounded_id(&value).then_some(value)", "Some(value)"),
        ):
            self.assertIn(before, source)
            with self.subTest(before=before):
                changed = source.replace(before, after, 1)
                self.assertTrue(any(not row["checked"] for row in self.evidence(changed, path)))

    def test_mcp_control_projection_requires_same_wire_admission_before_full_decode(self):
        path = "crates/protocol/chio-mcp-edge/src/ingress/inbox.rs"
        source = (ROOT / path).read_text()
        self.assertTrue(all(row["checked"] for row in self.evidence(source, path)))
        for before, after in (
            ("UntrustedJsonText::from_wire(bytes, bound)?", "UntrustedJsonText::from_wire(other, bound)?"),
            ("control_identity(bytes)", "control_identity(other)"),
            ("std::str::from_utf8(bytes)", "std::str::from_utf8(other)"),
            ("let reservation = budget.admit(wire)?;", "let reservation = unrelated();"),
            ("super::decode_mcp_request(bytes, bound)?", "super::decode_mcp_request(other, bound)?"),
        ):
            self.assertIn(before, source)
            with self.subTest(before=before):
                changed = source.replace(before, after, 1)
                self.assertTrue(any(not row["checked"] for row in self.evidence(changed, path)))
        before = "let reservation = budget.admit(wire)?;\n        let value = super::decode_mcp_request(bytes, bound)?;"
        self.assertIn(before, source)
        changed = source.replace(
            before,
            "let value = super::decode_mcp_request(bytes, bound)?;\n        let reservation = budget.admit(wire)?;",
            1,
        )
        self.assertTrue(any(not row["checked"] for row in self.evidence(changed, path)))

    def test_mcp_control_projection_cannot_borrow_an_unrelated_readers_witness(self):
        path = "crates/protocol/chio-mcp-edge/src/ingress/inbox.rs"
        source = (ROOT / path).read_text()
        changed = source.replace(
            "serde_json::from_slice::<Envelope<'_>>(bytes)",
            "serde_json::from_slice::<Value>(bytes)",
            1,
        ) + "\nfn unrelated(bytes: &[u8]) { serde_json::from_slice::<Envelope<'_>>(bytes); }\n"
        observed = {row["reader"]: row for row in self.evidence(changed, path)}
        self.assertFalse(observed["control_identity"]["checked"], observed)

    def test_import_and_local_aliases_keep_the_actual_contract(self):
        source = """
            use chio_core_types::canonical::{UntrustedJsonText as Original};
            fn read(bytes: &[u8]) {
                let text = Original::from_wire(bytes, 64)?;
                let alias = text;
                alias.decode_signed()
            }
        """
        self.assertEqual(self.contracts(source), (("read::from_wire#1::decode_signed",), ()))
        self.assertEqual(self.contracts(source.replace("alias.decode_signed", "alias.decode_document")),
                         (("read::from_wire#1::decode_document",), ()))

    def test_type_alias_and_closure_pin_external_contract(self):
        source = """
            type Original<'a> = chio_core_types::canonical::UntrustedJsonText<'a>;
            fn read(bytes: &[u8]) {
                Original::from_wire(bytes, 64).and_then(|text| text.decode_external::<Value>())
            }
        """
        self.assertEqual(self.contracts(source), (("read::from_wire#1::decode_external",), ()))

    def test_same_count_method_swap_changes_each_constructor(self):
        source = """fn read(a: &[u8], b: &[u8]) {
            UntrustedJsonText::from_wire(a, 64)?.decode_signed();
            UntrustedJsonText::from_wire(b, 64)?.decode_document();
        }"""
        self.assertEqual(self.contracts(source)[0], (
            "read::from_wire#1::decode_signed", "read::from_wire#2::decode_document",
        ))
        swapped = source.replace("decode_signed", "SWAP").replace("decode_document", "decode_signed").replace("SWAP", "decode_document")
        self.assertEqual(self.contracts(swapped)[0], (
            "read::from_wire#1::decode_document", "read::from_wire#2::decode_signed",
        ))

    def test_unrelated_receiver_nested_function_and_noise_do_not_supply_contract(self):
        source = '''fn read(bytes: &[u8]) {
            let text = UntrustedJsonText::from_wire(bytes, 64)?;
            // text.decode_canonical();
            let example = r#"text.decode_external()"#;
            fn helper() { text.decode_signed(); }
            other.decode_signed();
            text.decode_document()
        }'''
        self.assertEqual(self.contracts(source), (("read::from_wire#1::decode_document",), ()))

    def test_unresolved_receiver_cannot_be_recorded_as_a_signed_contract(self):
        source = "fn read(bytes: &[u8]) { let text = UntrustedJsonText::from_wire(bytes, 64)?; other.decode_signed(); }"
        self.assertTrue(self.contracts(source)[1])

    def test_unrelated_owner_and_nested_helper_do_not_supply_reader_evidence(self):
        for source in [
            "fn read(s: &str) { serde_json::from_str(s) } fn checked(b: &[u8]) { UntrustedJsonText::from_wire(b, 64)?.decode_signed() }",
            "fn read(s: &str) { fn checked(b: &[u8]) { UntrustedJsonText::from_wire(b, 64)?.decode_signed() } serde_json::from_str(s) }",
            'fn read(s: &str) { let fake = "UntrustedJsonText::from_wire(s, 64)?.decode_signed()"; serde_json::from_str(s) }',
            "fn read(s: &str) { unrelated::read_file_bounded(); serde_json::from_str(s) }",
            "fn read_file_bounded() {} fn read(s: &str) { read_file_bounded(); serde_json::from_str(s) }",
        ]:
            with self.subTest(source=source):
                self.assertFalse(self.evidence(source)[0]["checked"])

    def test_intrinsic_projection_and_typed_deserializer_remain_typed_claims(self):
        self.assertEqual(self.evidence("fn project(value: Value) { serde_json::from_value(value) }")[0]["apis"], ["serde_json::from_value"])
        evidence = self.evidence("fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> { Hash::deserialize(d) }")
        self.assertTrue(evidence[0]["checked"], evidence)

    def test_grouping_repeated_typed_callbacks_checks_every_body(self):
        source = """
            impl A { fn deserialize<'de, D: Deserializer<'de>>(d: D) { String::deserialize(d) } }
            impl B { fn deserialize<'de, D: Deserializer<'de>>(d: D) { String::deserialize(d) } }
        """
        evidence = self.evidence(source)
        self.assertEqual(evidence[0]["instances"], 2)
        changed = source.replace("String::deserialize(d)", "serde_json::from_str(input)", 1)
        self.assertTrue(any(not row["checked"] for row in self.evidence(changed)))

    def test_typed_field_evidence_requires_the_named_supporting_type(self):
        code = "fn validate_effect_plan_binding(effect: &PlannedResponseEffect) { serde_json::from_slice(effect.canonical_contribution.as_bytes()) }"
        for declaration, expected in [
            ("pub struct PlannedResponseEffect { pub canonical_contribution: CanonicalBody, }", True),
            ("pub struct PlannedResponseEffect { pub canonical_contribution: Value, } pub struct Unrelated { pub canonical_contribution: CanonicalBody, }", False),
        ]:
            with self.subTest(declaration=declaration):
                rows = gate._contracts.reader_evidence(
                    "crates/core/chio-response-model/src/state.rs", code, list(gate.json_decoders(code)), code,
                    {gate._contracts._rules.EFFECT: declaration},
                )
                self.assertEqual(rows[0]["checked"], expected)


class PrivateAuditCustodyCalibration(unittest.TestCase):
    path = "crates/security/chio-secret-broker/src/privileged_audit/open_custody.rs"

    def evidence(self, source):
        code = gate._lexer.blank_rust_noise(source)
        return gate._contracts.reader_evidence(
            self.path, code, list(gate.json_decoders(code)),
            gate._lexer.blank_test_scoped_items(code), {},
        )

    def test_private_readers_require_the_bounded_original_and_canonical_custody(self):
        rows = self.evidence((ROOT / self.path).read_text())
        self.assertEqual({row["reader"] for row in rows}, {"typed", "seeded"})
        self.assertTrue(all(row["checked"] for row in rows))

    def test_private_reader_witness_rejects_removed_bounds_equality_and_real_cause(self):
        source = (ROOT / self.path).read_text()
        for old, new in (
            ("UntrustedJsonText::from_wire(input, MAX_AUDIT_OPEN_FRAME_BYTES)",
             "UntrustedJsonText::from_wire(input, usize::MAX)"),
            ("canonical.as_slice() != input", "canonical.as_slice() == input"),
            ("Err(failure.into_error())", 'Err(invalid(0, "hidden cause"))'),
            (".checked_add(values.byte_offset())", ".wrapping_add(values.byte_offset())"),
        ):
            with self.subTest(removed=old):
                self.assertIn(old, source)
                rows = self.evidence(source.replace(old, new, 1))
                self.assertTrue(all(not row["checked"] for row in rows))


if __name__ == "__main__":
    unittest.main()
