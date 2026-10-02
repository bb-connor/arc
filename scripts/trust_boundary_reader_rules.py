"""Explicit source witnesses for readers implemented below the shared JSON API.

These rules retain existing numeric/typed contracts. They are checked lexical
witnesses, not path-only exemptions, and cannot be supplied by inventory prose.
"""
import re
from functools import lru_cache

CORE = "crates/core/chio-core-types/src/"
CHECKPOINT = "crates/kernel/chio-kernel/src/checkpoint.rs"
EFFECT = "crates/security/chio-security-types/src/response.rs"
SUPPORT_PATHS = (CHECKPOINT, EFFECT)

# (owner path, reader symbol): (constrained API, required source expressions).
# Every expression is confined to this named function with nested items masked.
RULES = {
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
    apis = []
    rule = RULES.get((path, reader.split("#")[0]))
    if rule and all(re.search(pattern, body) for pattern in rule[1]):
        apis.append(rule[0])
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
