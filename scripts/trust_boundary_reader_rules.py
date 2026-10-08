"""Explicit source witnesses for readers implemented below the shared JSON API.

These rules retain existing numeric/typed contracts. They are checked lexical
witnesses, not path-only exemptions, and cannot be supplied by inventory prose.
"""
import importlib.util
import re
import sys
from functools import lru_cache
from pathlib import Path

_classifier_spec = importlib.util.spec_from_file_location(
    "trust_boundary_mcp_rejection", Path(__file__).with_name("trust_boundary_mcp_rejection.py")
)
_classifier = importlib.util.module_from_spec(_classifier_spec)
_classifier_spec.loader.exec_module(_classifier)
_lexer_spec = importlib.util.spec_from_file_location(
    "mcp_rejection_lexer", Path(__file__).with_name("check-accounting-arithmetic.py")
)
_lexer = importlib.util.module_from_spec(_lexer_spec)
sys.modules[_lexer_spec.name] = _lexer
_lexer_spec.loader.exec_module(_lexer)

CORE = "crates/core/chio-core-types/src/"
CHECKPOINT = "crates/kernel/chio-kernel/src/checkpoint.rs"
EFFECT = "crates/security/chio-security-types/src/response.rs"
MCP_INBOX = "crates/protocol/chio-mcp-edge/src/ingress/inbox.rs"
SUPPORT_PATHS = (CHECKPOINT, EFFECT, MCP_INBOX)

# (owner path, reader symbol): (constrained API, required source expressions).
# Every expression is confined to this named function with nested items masked.
RULES = {
    ("crates/products/chio-wall/src/commands/siem_pins.rs", "parse"): ("bounded_operator_key_list", (
        r"if\s+value\.len\(\)\s*>\s*MAX_CONFIG_BYTES\s*\{\s*return\s+Err\(",
        r"let\s+encoded\s*:\s*Vec<String>\s*=\s*serde_json::from_str\(&value\)",
        r"if\s+encoded\.is_empty\(\)\s*\|\|\s*encoded\.len\(\)\s*>\s*MAX_KEYS\s*\{\s*return\s+Err\(",
    )),
    (CORE + "canonical.rs", "from_str"): ("StrictJson::deserialize+Deserializer::end", (
        r"StrictJson::deserialize\s*\(\s*&mut\s+de\s*\)", r"\bde\.end\s*\(\s*\)",
    )),
    (CORE + "canonical/signed_json.rs", "parse"): ("StoredValue+validate_number_tokens", (
        r"\blet\s+value\s*:\s*StoredValue\s*=\s*serde_json::from_str\s*\(input\)",
        r"\bvalidate_number_tokens\s*\(input\)\s*\?",
    )),
    (CORE + "canonical/signed_json.rs", "parse_document"): ("StoredValue::Deserialize", (
        r"serde_json::from_str::<StoredValue>\s*\(input\)",
    )),
    (CORE + "canonical/untrusted.rs", "decode_external"): ("UntrustedJsonText::canonicalize", (
        r"let\s+canonical\s*=\s*self\.canonicalize\(\)\?",
        r"serde_json::from_slice\s*\(&canonical\)",
    )),
    (CORE + "canonical/untrusted.rs", "decode_canonical_with"): ("canonical_export+original_equality", (
        r"let\s+canonical\s*=\s*export\(&value\)",
        r"if\s+canonical\.as_slice\(\)\s*!=\s*self\.text\.as_bytes\(\)",
    )),
    ("crates/kernel/chio-process/src/store/prepared.rs", "prepare_invocation"): ("read_bytes+sha256_hex_equality", (
        r"super::blobs::read_bytes\(&tx,\s*process_id,\s*&sha256\)",
        r"if\s+sha256_hex\(&bytes\)\s*!=\s*sha256",
        r"serde_json::from_slice\(&bytes\)",
    )),
    ("crates/platform/chio-control-plane/src/fiscal_state_anchor.rs", "compare_and_swap"): ("VerifiedFiscalContinuityAdvance::canonical_proof_bytes", (
        r"advance\s*:\s*&VerifiedFiscalContinuityAdvance\b", r"advance\s*\.reverify\(",
        r"serde_json::from_slice\(advance\.canonical_proof_bytes\(\)\)",
    )),
    ("crates/products/chio-cli/src/cli/process_response_verify/json.rs", "parse_at"): ("UniqueObject+decimal_identity", (
        r"\.deserialize_map\(UniqueObject\)",
        r"if\s+decimal_identity\(text\)\?\s*!=\s*decimal_identity\(&rendered\)\?",
        r"if\s+depth\s*>\s*64",
    )),
    ("crates/products/chio-cli/src/cli/dispatch/finding/verified_fix.rs", "read_file_bounded"): ("crate::input::read_regular", (
        r"crate::input::read_regular\(path,\s*max_bytes\)\s*\?",
    )),
    ("crates/protocol/chio-mcp-remote/src/remote_mcp/session_resume.rs", "read_resume_hmac_keyring_file"): ("Read::take+keyring_length_check", (
        r"\.take\(MAX_KEYRING_BYTES\s*\+\s*1\)",
        r"\.read_to_end\(&mut\s+encoded\)", r"encoded_len\s*>\s*MAX_KEYRING_BYTES",
    )),
    ("crates/trust/chio-pheromone-runtime/src/lib.rs", "validate_json_schema"): ("jsonschema::options::build", (
        r"let\s+schema\s*:\s*serde_json::Value\s*=\s*serde_json::from_str\(schema_json\)",
        r"jsonschema::options\(\)\s*\.build\(&schema\)", r"\.iter_errors\(value\)",
    )),
}


@lru_cache(maxsize=16)
def closed_checkpoint(code):
    match = re.search(r"#\[serde\(deny_unknown_fields\)\]\s*pub struct KernelCheckpointBody\s*\{([^}]+)\}", code)
    if not match:
        return False
    fields = re.findall(r"pub\s+\w+\s*:\s*([^,]+),", match.group(1))
    return bool(fields) and all(field.strip() in {
        "String", "u64", "usize", "Hash", "PublicKey", "Option<String>", "Option<Hash>",
    } for field in fields)


def special_apis(path, reader, body, supports):
    apis = _classifier.apis(
        path, reader, supports.get(_classifier.RAW_SUPPORT, ""), _lexer
    )
    rule = RULES.get((path, reader.split("#")[0]))
    if rule and all(re.search(pattern, body) for pattern in rule[1]):
        apis.append(rule[0])
    if path == MCP_INBOX and reader == "scalar":
        source = supports.get(MCP_INBOX, "")
        envelope = re.search(r"struct\s+Envelope<'a>\s*\{([^}]+)\}", source)
        params = re.search(r"struct\s+Params<'a>\s*\{([^}]+)\}", source)
        borrowed = envelope and params and all(
            re.search(r"\b" + field + r"\s*:\s*Option<&'a\s+RawValue>", declaration)
            for declaration, fields in (
                (envelope.group(1), ("jsonrpc", "id", "method", "params")),
                (params.group(1), ("request", "task")),
            ) for field in fields
        )
        scalar = (
            r"let\s+raw\s*=\s*raw\.filter\(\|raw\|\s*raw\.get\(\)\.len\(\)\s*<=\s*IDENTITY_BYTES\)\?;",
            r"let\s+value\s*:\s*Value\s*=\s*serde_json::from_str\(raw\.get\(\)\)\.ok\(\)\?;",
            r"bounded_id\(&value\)\.then_some\(value\)",
        )
        route = (
            r"fn\s+decode\(\s*&self,\s*bytes\s*:\s*&\[u8\],\s*bound\s*:\s*usize\s*\)"
            r"\s*->\s*Result<AccountedMessage,\s*AdapterError>\s*\{\s*"
            r"(?:let\s+text\s*=\s*)?chio_core::canonical::UntrustedJsonText::from_wire\(bytes,\s*bound\)\?;\s*"
            r"(?:let\s+_\s*=\s*text;\s*)?"
            r"let\s+identity\s*=\s*control_identity\(bytes\);\s*"
            r"let\s+budget\s*=\s*self\.budget\(&identity\)\?;\s*"
            r"let\s+wire\s*=\s*std::str::from_utf8\(bytes\)\s*"
            r"\.map_err\(chio_core::canonical::UntrustedJsonError::NotUtf8\)\?;\s*"
            r"let\s+reservation\s*=\s*budget\.admit\(wire\)\?;\s*"
            r"let\s+value\s*=\s*super::decode_mcp_request\(bytes,\s*bound\)\?;"
        )
        if borrowed and all(re.search(pattern, body) for pattern in scalar) and all(
            re.search(pattern, source) for pattern in (
                r"const\s+IDENTITY_BYTES\s*:\s*usize\s*=\s*512;",
                r"fn\s+raw_member<'de,\s*D:\s*serde::Deserializer<'de>>\(\s*decoder:\s*D\s*,?\s*\)\s*"
                r"->\s*Result<Option<&'de\s+RawValue>,\s*D::Error>\s*\{\s*"
                r"<&'de\s+RawValue>::deserialize\(decoder\)\.map\(Some\)\s*\}",
                r"fn\s+control_identity\(bytes:\s*&\[u8\]\)\s*->\s*Value\s*\{\s*"
                r"let\s+Ok\(envelope\)\s*=\s*serde_json::from_slice::<Envelope<'_>>\(bytes\)\s*else\s*\{\s*"
                r"return\s+Value::Null;\s*\};\s*let\s+params\s*=\s*envelope\s*\.params\s*"
                r"\.and_then\(\|params\|\s*serde_json::from_str::<Params<'_>>\(params\.get\(\)\)\.ok\(\)\);",
                r"scalar\(raw\)\.unwrap_or\(Value::Bool\(false\)\)",
                r"fn\s+bounded_id\(value:\s*&Value\)\s*->\s*bool\s*\{\s*match\s+value\s*\{\s*"
                r"Value::String\(text\)\s*=>\s*text\.len\(\)\s*<=\s*IDENTITY_BYTES,\s*"
                r"Value::Number\(_\)\s*\|\s*Value::Null\s*=>\s*true,\s*_\s*=>\s*false,?\s*\}\s*\}",
                route,
            )
        ):
            apis.append("borrowed-control::bounded_scalar+same_wire_aggregate_admission")
    if path == "crates/protocol/chio-mcp-remote/src/remote_mcp/session_resume.rs" and reader.startswith("read_resume_hmac_keyring_file#") and re.search(
        r"\{\s*Err\(CliError::cli_other_error\(", body
    ) and not re.search(r"\bOk\s*\(", body):
        apis.append("unsupported-platform::Err")
    if closed_checkpoint(supports.get(CHECKPOINT, "")) and re.search(
        r"\blet\s+\w+\s*:\s*KernelCheckpointBody\s*=\s*serde_json::from_str\(", body
    ):
        apis.append("KernelCheckpointBody::closed_integer_fields")
    effect = re.search(r"pub struct PlannedResponseEffect\s*\{([^}]+)\}", supports.get(EFFECT, ""))
    if effect and re.search(r"pub\s+canonical_contribution\s*:\s*CanonicalBody\b", effect.group(1)) and re.search(
        r"effect\s*:\s*&PlannedResponseEffect\b", body
    ) and re.search(r"serde_json::from_slice\(effect\.canonical_contribution\.as_bytes\(\)\)", body):
        apis.append("PlannedResponseEffect::canonical_contribution[CanonicalBody]")
    return apis


def private_producer_apis(path, reader, body, owners, calls, canonical_equality):
    """Pin the finite private producer/readback relationships reviewed in code."""
    if path == "crates/security/chio-secret-broker/src/privileged_audit/open_custody.rs" and reader in {"typed", "seeded"}:
        # These private span readers consume only the original frame bounded
        # by decode_open_wire. Canonical readback precedes public projection;
        # the seed side channel preserves the original custody/bound cause.
        witnesses = {
            "decode_open_wire": (
                r"UntrustedJsonText::from_wire\(input,\s*MAX_AUDIT_OPEN_FRAME_BYTES\)\s*\.map_err\(BrokerError::UntrustedInput\)\?;\s*let\s+mut\s+fields\s*=\s*Fields\s*\{\s*input,\s*position:\s*0\s*\}",
                r"if\s+fields\.position\s*!=\s*input\.len\(\)\s*\{\s*return\s+Err\(",
                r"let\s+canonical\s*=\s*encode_private_open\(&value\)\?;\s*if\s+canonical\.as_slice\(\)\s*!=\s*input\s*\{\s*return\s+Err\(BrokerError::UntrustedInput\(",
                r"UntrustedJsonError::NonCanonical",
                r"Ok\(value\.into_public\(\)\)",
            ),
            "typed": (
                r"self\s*\.input\s*\.get\(self\.position\.\.\)",
                r"serde_json::Deserializer::from_slice\(rest\)\.into_iter::<T>\(\)",
                r"UntrustedJsonError::Decode\(\s*error,?\s*\)",
                r"\.checked_add\(values\.byte_offset\(\)\)",
            ),
            "seeded": (
                r"self\s*\.input\s*\.get\(self\.position\.\.\)",
                r"seed\.deserialize\(&mut\s+deserializer\)\.map_err\(",
                r"UntrustedJsonError::Decode\(\s*error,?\s*\)",
                r"self\.typed::<IgnoredAny>\(\)\?",
            ),
            "seed_result": (
                r"\(Err\(_\),\s*Some\(failure\)\)\s*=>\s*Err\(failure\.into_error\(\)\)",
                r"\(value,\s*None\)\s*=>\s*value",
                r"\(Ok\(_\),\s*Some\(_\)\)\s*=>\s*Err\(BrokerError::Invariant\(",
            ),
            "encode_private_open": (
                r"crate::private_request_wire::canonical_open_bytes\(",
                r"MAX_AUDIT_OPEN_FRAME_BYTES,\s*\)",
            ),
        }
        if all(re.search(pattern, owners.get(owner, "")) for owner, patterns in witnesses.items() for pattern in patterns):
            return ["private::decode_open_wire::bounded_original+canonical_readback+seed_cause"]
    if path == "crates/protocol/chio-mcp-edge/src/ingress/budget/admission.rs" and reader == "measure":
        witnesses = {
            "measure": (
                r"wire_bytes\s*:\s*text\.len\(\)",
                r"if\s+let\s+Some\(limit\)\s*=\s*counter\.footprint\.exceeded\(\)\s*\{\s*return\s+Err\(AdmissionError::Limit\(limit\)\)",
                r"ValueSeed\(&mut\s+counter\)\s*\.deserialize\(&mut\s+decoder\)",
                r"\.and_then\(\|\(\)\|\s*decoder\.end\(\)\)",
            ),
            "add": (
                r"self\.footprint\.checked_add\(Footprint\s*\{\s*nodes,\s*text_bytes,",
                r"if\s+let\s+Some\(limit\)\s*=\s*next\.exceeded\(\)\s*\{\s*self\.limit\s*=\s*Some\(limit\);\s*return\s+Err\(",
            ),
            "deserialize#1": (r"self\.0\.add\(1,\s*0\)\?",),
            "visit_str#1": (r"self\.0\.add\(0,\s*value\.len\(\)\)",),
            "visit_str#2": (r"self\.0\.add\(0,\s*value\.len\(\)\)",),
            "visit_seq": (r"sequence\.next_element_seed\(ValueSeed\(self\.0\)\)\?",),
            "visit_map": (
                r"map\.next_key_seed\(KeySeed\(self\.0\)\)\?",
                r"map\.next_value_seed\(ValueSeed\(self\.0\)\)\?",
            ),
        }
        if all(re.search(pattern, owners.get(owner, "")) for owner, patterns in witnesses.items() for pattern in patterns):
            return ["Counter::checked_add+ValueSeed::structural_limits+Deserializer::end"]
    if path == "crates/security/chio-active-response-authority/src/store.rs" and reader == "prepare_logical_records":
        callers = {name: text for name, text in owners.items() if name != reader and calls(text, reader)}
        check = owners.get("validate_payload_size", "")
        if callers and re.search(r"payload\.len\(\)\s*>\s*MAX_STORE_PAYLOAD_BYTES", check) and all(
            re.search(r"let\s+payload\s*=\s*canonical_json_bytes\(record\)", text)
            and calls(text, "validate_payload_size") for text in callers.values()
        ):
            return ["callers::" + "+".join(sorted(callers)) + "::canonical_json_bytes+validate_payload_size"]
    if path == "crates/security/chio-decoy/src/registry.rs" and reader == "decode_materialization_receipt":
        callers = {name: text for name, text in owners.items() if name != reader and calls(text, reader)}
        opened = owners.get("open_envelope", "")
        validated = owners.get("validate_opened_envelope", "")
        binding = owners.get("validate_materialization_binding", "")
        if callers and all(re.search(r"(?:\.load_envelope|\bopen_envelope)\s*\(", text) for text in callers.values()) and (
            canonical_equality(opened) and calls(opened, "validate_opened_envelope")
            and calls(validated, "validate_materialization_binding") and canonical_equality(binding)
            and re.search(r"envelope\s*:\s*&PrivateEnvelope", body)
            and re.search(r"envelope\s*\.materialization_receipt\s*\.as_deref\(\)", body)
        ):
            return ["private::open_envelope::validate_materialization_binding"]
    return []
