"""Mutation controls for the exact reject-only MCP source witness."""
from pathlib import Path
import importlib.util
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


LEXER = load("mcp_witness_test_lexer", REPO / "scripts/check-accounting-arithmetic.py")
WITNESS = load("mcp_witness", REPO / "scripts/trust_boundary_mcp_rejection.py")
# Retain actual source literals while masking test-only tokens.
SOURCE = (REPO / WITNESS.MCP_HTTP).read_text()
syntax = LEXER.blank_rust_noise(SOURCE)
production = LEXER.blank_test_scoped_items(syntax)
SOURCE = "".join(o if b == a else ("\n" if o == "\n" else " ")
                 for o, b, a in zip(SOURCE, syntax, production))


class InitializeRejectWitnessMutations(unittest.TestCase):
    def accepted(self, source):
        return WITNESS.apis(WITNESS.MCP_HTTP, "initialize_request_shape", source, LEXER)

    def mutate(self, old, new):
        self.assertIn(old, SOURCE)
        changed = SOURCE.replace(old, new, 1)
        self.assertNotEqual(changed, SOURCE)
        self.assertEqual(self.accepted(changed), [])

    def test_exact_proposed_source_is_checked(self):
        self.assertEqual(self.accepted(SOURCE), [WITNESS.API])

    def test_spacing_and_comments_preserve_same_tokens(self):
        changed = SOURCE.replace("if method.get().len() > 62", "if /* bound witness */ method.get().len()   >   62")
        self.assertEqual(self.accepted(changed), [WITNESS.API])

    def test_no_path_or_other_reader_exemption(self):
        self.assertEqual(WITNESS.apis("other.rs", "initialize_request_shape", SOURCE, LEXER), [])
        self.assertEqual(WITNESS.apis(WITNESS.MCP_HTTP, "other", SOURCE, LEXER), [])

    def test_wire_marker_removal(self):
        self.mutate("chio_core::canonical::UntrustedJsonText::from_wire(body, MCP_MAX_POST_BODY_BYTES).ok()?;", "")

    def test_unresolved_bound_local_binding(self):
        self.mutate("chio_core::canonical::UntrustedJsonText::from_wire(body, MCP_MAX_POST_BODY_BYTES).ok()?;", "let _wire = chio_core::canonical::UntrustedJsonText::from_wire(body, MCP_MAX_POST_BODY_BYTES).ok()?;")

    def test_body_ceiling_cannot_expand(self):
        self.mutate("const MCP_MAX_POST_BODY_BYTES: usize = 8 * 1024 * 1024;", "const MCP_MAX_POST_BODY_BYTES: usize = 16 * 1024 * 1024;")

    def test_object_literal_is_not_masked_into_acceptance(self):
        self.mutate("!= Some(b'{')", "!= Some(b'[')")

    def test_object_guard_cannot_disappear(self):
        self.mutate("if body.iter().copied().find(|byte| !byte.is_ascii_whitespace()) != Some(b'{') {", "if false {")

    def test_borrowed_method_cannot_become_value_dom(self):
        self.mutate("method: Option<&'a serde_json::value::RawValue>,", "method: Option<serde_json::Value>,")

    def test_method_bound_cannot_expand(self):
        self.mutate("if method.get().len() > 62", "if method.get().len() > 63")

    def test_method_literal_is_not_masked_into_acceptance(self):
        self.mutate('(method == "initialize").then_some(shape.id.0)', '(method == "ping").then_some(shape.id.0)')

    def test_method_literal_whitespace_alias_cannot_pass(self):
        self.mutate('(method == "initialize").then_some(shape.id.0)', '(method == "initialize ").then_some(shape.id.0)')

    def test_result_cannot_forget_id_presence(self):
        self.mutate(".then_some(shape.id.0)", ".then_some(true)")

    def test_present_cannot_project_full_value(self):
        self.mutate("<serde::de::IgnoredAny as serde::Deserialize<'de>>::deserialize(deserializer)", "<serde_json::Value as serde::Deserialize<'de>>::deserialize(deserializer)")

    def test_none_fallback_cannot_unwrap(self):
        self.mutate("serde_json::from_slice(body).ok()?", "serde_json::from_slice(body).unwrap()")

    def test_refusal_return_cannot_become_fallthrough(self):
        self.mutate("return if has_request_id", "let response = if has_request_id")

    def test_rejection_cannot_grant_or_mutate(self):
        self.mutate("initialize_session_header_refusal()", "grant_authority(); initialize_session_header_refusal()")

    def test_sender_cannot_decode_a_different_wire(self):
        self.mutate("sender.decode(&body, MCP_MAX_POST_BODY_BYTES)", "sender.decode(b\"{}\", MCP_MAX_POST_BODY_BYTES)")

    def test_dom_cannot_appear_before_reservation(self):
        self.mutate("let (initial_sender, _initial_receiver) = mcp_inbox();", "let value: Value = input::document(&body, MCP_MAX_POST_BODY_BYTES).unwrap(); let (initial_sender, _initial_receiver) = mcp_inbox();")

    def test_unbounded_body_call_cannot_replace_bounded_owner(self):
        self.mutate("read_limited_mcp_post_body(request).await", "read_unlimited_mcp_post_body(request).await")

    def test_new_unreviewed_consumer_cannot_pass(self):
        self.assertEqual(self.accepted(SOURCE + "\nfn added_consumer(wire: &[u8]) { initialize_request_shape(wire); }\n"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
