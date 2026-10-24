#!/usr/bin/env python3
"""Refuse production raw JSON decodes of the strict receipt and lossless types.

A raw `serde_json` decode keeps the last of two duplicate keys inside any
`serde_json::Value` member, and `decode_document` admits numeric spellings the
signed contract refuses, so production code decodes these types through
`UntrustedJsonText::decode_signed`, and HTTP routes use the `SignedJson`
extractor. A type that contains a strict type, at any depth, or a `type`
alias of one outside an `impl` or `trait`, is strict too.

Source is scanned with comments, literals and `#[cfg(test)]` items masked, so
multi-line calls and production items after a test module are both seen. A
raw decode is a `serde_json::from_*` call or stream, a `decode_document` call,
a direct `Deserialize::deserialize` call outside a `Deserialize` or `Visitor`
impl, or a call to a function of the same crate that is generic over a
`Deserialize` parameter and raw decodes it, in a function body or a `static`
or `const` initializer. It is flagged when its target is strict by turbofish,
by a `let` annotation (including a declared-then-assigned binding), by the
item's declared type, or by the strict return type of the function that holds
it (with `Self` read as the implementing type), either directly or through an
unannotated `let` binding that the function returns. An extractor is flagged
when its type argument is strict. Each exception in ALLOWED names
one exact call in one function that reads an already parsed `Value`, together
with the duplicate-refusing reader that produced it. The script checks itself
against fixture trees on every run before it scans the workspace.

Every production workspace member is scanned: `crates/` and each other
top-level member directory except `bench`, `examples` and `tests`. A renamed
import (`use path::ChioReceipt as Receipt`) is read as an alias.

The scan is lexical. It does not resolve paths, trait dispatch, or helpers in
other crates, and a short type name defined differently in two crates is only
strict when every definition is, so a pass is evidence for the listed forms
only.
"""

from __future__ import annotations

import argparse
import functools
import importlib.util
import re
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_gate = _load("trust_boundaries_gate", ROOT / "scripts/check-trust-boundaries.py")
_lexer = _gate._lexer
_contracts = _gate._contracts

# The receipt types that carry a serde_json::Value member (action parameters,
# metadata). Derived impls already refuse a duplicate field of a Chio object;
# only a Value member can keep the last of two duplicate keys.
STRICT_TYPES = frozenset({
    "ChioReceipt",
    "ChioReceiptBody",
    "ChioReceiptIdInput",
    "ChioReceiptSigningBody",
    "ChildRequestReceipt",
    "ChildRequestReceiptBody",
    "FinancialReceiptMetadata",
    "ToolCallAction",
})

# Each entry names one call (whitespace-normalized) in one function that reads
# an already parsed Value, and the custody chain that produced that Value. Each
# custody link (path, function, call) requires that function to make that call.
# By default the last link must call decode_signed and hold no raw text decode,
# so a producer that regresses to a raw serde_json read fails the gate. An
# "origin" of "receipt member" reads a member of a typed strict receipt, whose
# own decode this gate covers; "kernel built" reads metadata the listed kernel
# callers assemble in process.
ALLOWED = (
    {
        "path": "crates/platform/chio-store-sqlite/src/receipt_store/support/receipt_verify.rs",
        "owner": "decode_verified_chio_receipt",
        "call": "serde_json::from_value(value)",
        "custody": (
            ("crates/platform/chio-store-sqlite/src/receipt_store/support/receipt_verify.rs", "decode_verified_chio_receipt", "decode_stored_json("),
            ("crates/platform/chio-store-sqlite/src/receipt_store/support/receipt_verify.rs", "decode_stored_json", "decode_signed("),
        ),
    },
    {
        "path": "crates/platform/chio-store-sqlite/src/receipt_store/support/receipt_verify.rs",
        "owner": "decode_verified_child_receipt",
        "call": "serde_json::from_value(value)",
        "custody": (
            ("crates/platform/chio-store-sqlite/src/receipt_store/support/receipt_verify.rs", "decode_verified_child_receipt", "decode_stored_json("),
            ("crates/platform/chio-store-sqlite/src/receipt_store/support/receipt_verify.rs", "decode_stored_json", "decode_signed("),
        ),
    },
    {
        "path": "crates/platform/chio-control-plane/src/trust_control/cluster/snapshots.rs",
        "owner": "recover_cluster_snapshot",
        "call": "serde_json::from_value(record.receipt.clone())",
        "count": 2,
        "custody": (
            ("crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs", "sync_peer", "client.cluster_snapshot("),
            ("crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs", "sync_peer", "recover_cluster_snapshot("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/cluster.rs", "cluster_snapshot", "get_internal_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "get_internal_json", "request_internal_get_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "request_internal_get_json", "read_capped_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "read_capped_json", "crate::json_input::read("),
            ("crates/platform/chio-control-plane/src/json_input.rs", "read", "decode_signed("),
        ),
    },
    {
        "path": "crates/platform/chio-control-plane/src/trust_control/service_runtime/remote_stores.rs",
        "owner": "load_chio_receipt",
        "call": "serde_json::from_value(value)",
        "custody": (
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/remote_stores.rs", "load_chio_receipt", "list_tool_receipts("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/operations.rs", "list_tool_receipts", "get_json_with_query("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "get_json_with_query", "request_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "request_json", "request_json_capped("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "request_json_capped", "read_capped_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "read_capped_json", "crate::json_input::read("),
            ("crates/platform/chio-control-plane/src/json_input.rs", "read", "decode_signed("),
        ),
    },
    {
        "path": "crates/platform/chio-control-plane/src/trust_control/service_runtime/remote_stores.rs",
        "owner": "load_child_receipt",
        "call": "serde_json::from_value(value)",
        "custody": (
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/remote_stores.rs", "load_child_receipt", "list_child_receipts("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/operations.rs", "list_child_receipts", "get_json_with_query("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "get_json_with_query", "request_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "request_json", "request_json_capped("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "request_json_capped", "read_capped_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "read_capped_json", "crate::json_input::read("),
            ("crates/platform/chio-control-plane/src/json_input.rs", "read", "decode_signed("),
        ),
    },
    {
        "path": "crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs",
        "owner": "sync_peer_tool_receipts",
        "call": "serde_json::from_value(record.receipt)",
        "custody": (
            ("crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs", "sync_peer_tool_receipts", "tool_receipt_deltas("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/cluster.rs", "tool_receipt_deltas", "get_internal_json_with_query("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "get_internal_json_with_query", "request_internal_get_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "request_internal_get_json", "read_capped_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "read_capped_json", "crate::json_input::read("),
            ("crates/platform/chio-control-plane/src/json_input.rs", "read", "decode_signed("),
        ),
    },
    {
        "path": "crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs",
        "owner": "sync_peer_child_receipts",
        "call": "serde_json::from_value(record.receipt)",
        "custody": (
            ("crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs", "sync_peer_child_receipts", "child_receipt_deltas("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/cluster.rs", "child_receipt_deltas", "get_internal_json_with_query("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "get_internal_json_with_query", "request_internal_get_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "request_internal_get_json", "read_capped_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "read_capped_json", "crate::json_input::read("),
            ("crates/platform/chio-control-plane/src/json_input.rs", "read", "decode_signed("),
        ),
    },
    {
        "path": "crates/products/chio-cli/src/cli/process_host/call_evidence/outcomes.rs",
        "owner": "verify_file",
        "call": "serde_json::from_value(signed.action.parameters.clone())",
        "custody": (
            ("crates/products/chio-cli/src/cli/process_host/call_evidence/outcomes.rs", "verify_file", "verify_original_receipt("),
            ("crates/products/chio-cli/src/cli/receipt_verify.rs", "verify_original_receipt", "crate::input::decode("),
            ("crates/products/chio-cli/src/cli/input.rs", "decode", "decode_signed("),
        ),
    },
    {
        "path": "crates/products/chio-mercury/src/commands/core_cli/commands.rs",
        "owner": "cmd_mercury_verify",
        "call": "serde_json::from_value(value)",
        "count": 2,
        "custody": (
            ("crates/products/chio-mercury/src/commands/core_cli/commands.rs", "cmd_mercury_verify", "read_json_file("),
            ("crates/products/chio-mercury/src/commands/shared/utils.rs", "read_json_file", "read_json_file_bounded("),
            ("crates/products/chio-mercury/src/commands/shared/utils.rs", "read_json_file_bounded", "decode_signed("),
        ),
    },
    {
        "path": "crates/platform/chio-control-plane/src/evidence_export.rs",
        "owner": "decode_remote_import_request",
        "call": "serde_json::from_value::<RemoteEvidenceImportRequest>, |typed: &RemoteEvidenceImportRequest| serde_json::to_value(typed)",
        "custody": (
            ("crates/platform/chio-control-plane/src/trust_control/receipt_handlers.rs", "handle_evidence_import", "SignedJson(body): SignedJson<serde_json::Value>"),
            ("crates/platform/chio-control-plane/src/trust_control/receipt_handlers.rs", "handle_evidence_import", "evidence_export::decode_remote_import_request(body)"),
            ("crates/platform/chio-control-plane/src/trust_control/json_ingress.rs", "from_request", "decode_signed("),
        ),
    },
    {
        "path": "crates/kernel/chio-runtime-core/src/buyer/proof_package.rs",
        "owner": "proof_package_contains_signed_receipt",
        "call": "serde_json::from_value(value.clone())",
        "custody": (
            ("crates/kernel/chio-runtime-core/src/buyer/review_hydration.rs", "from_bound_sources", "parse_review_json("),
            ("crates/kernel/chio-runtime-core/src/buyer/helpers.rs", "parse_review_json", "decode_signed("),
        ),
    },
    {
        "path": "crates/kernel/chio-runtime-core/src/buyer/proof_package.rs",
        "owner": "proof_package_receipt_subject",
        "call": "serde_json::from_value(receipt_value.clone())",
        "custody": (
            ("crates/kernel/chio-runtime-core/src/buyer/review_hydration.rs", "from_bound_sources", "parse_review_json("),
            ("crates/kernel/chio-runtime-core/src/buyer/helpers.rs", "parse_review_json", "decode_signed("),
        ),
    },
    {
        "path": "crates/protocol/chio-mcp-remote/src/remote_mcp/session_credentials/completed_result.rs",
        "owner": "verified_receipt",
        "call": "serde_json::from_value::<chio_core::receipt::body::ChioReceipt>(evidence[ ].clone(),)",
        "custody": (
            ("crates/protocol/chio-mcp-remote/src/remote_mcp/session_core/writer.rs", "flush_complete_lines", "decode_json("),
            ("crates/protocol/chio-mcp-remote/src/input.rs", "decode", "decode_signed("),
        ),
    },
    {
        "path": "crates/products/chio-cli/src/active_defense_migration.rs",
        "owner": "verify_backfill_receipts",
        "call": "strict_typed_value(&registered.receipt,)",
        "custody": (
            ("crates/products/chio-cli/src/active_defense_migration.rs", "load_and_build_report", "parse_shadow_migration_input("),
            ("crates/products/chio-cli/src/active_defense_migration.rs", "parse_shadow_migration_input", "decode_signed("),
        ),
    },
    {
        "path": "crates/products/chio-cli/src/cli/replay/verify.rs",
        "owner": "verify_receipt",
        "call": "serde_json::from_value(value.clone())",
        "custody": (
            ("crates/products/chio-cli/src/cli/replay.rs", "run_log_replay", "verify_receipt("),
            ("crates/products/chio-cli/src/cli/receipt_verify.rs", "verify_original_receipt", "verify_receipt("),
            ("crates/products/chio-cli/src/cli/receipt_verify.rs", "verify_original_receipt", "crate::input::decode("),
            ("crates/products/chio-cli/src/cli/replay/reader.rs", "parse", "crate::input::decode("),
            ("crates/products/chio-cli/src/cli/input.rs", "decode", "decode_signed("),
        ),
    },
    {
        "path": "crates/products/chio-cli/src/cli/replay.rs",
        "owner": "run_log_replay",
        "call": "serde_json::from_value(value.clone())",
        "custody": (
            ("crates/products/chio-cli/src/cli/replay/reader.rs", "parse", "crate::input::decode("),
            ("crates/products/chio-cli/src/cli/input.rs", "decode", "decode_signed("),
        ),
    },
    {
        "path": "crates/products/chio-cli/src/cli/receipt_verify.rs",
        "owner": "verify_original_receipt",
        "call": "crate::input::project(value.clone())",
        "custody": (
            ("crates/products/chio-cli/src/cli/receipt_verify.rs", "verify_original_receipt", "crate::input::decode("),
            ("crates/products/chio-cli/src/cli/input.rs", "decode", "decode_signed("),
        ),
    },
    {
        "path": "crates/products/chio-cli/src/cli/trust/receipt/explain.rs",
        "owner": "explain_receipt_value",
        "call": "crate::input::project(value)",
        "custody": (
            ("crates/products/chio-cli/src/cli/trust/receipt/explain.rs", "cmd_receipt_explain", "crate::input::json::<serde_json::Value>("),
            ("crates/products/chio-cli/src/cli/trust/receipt/explain.rs", "load_receipt_for_explain", "client.query_receipts("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/operations.rs", "query_receipts", "get_json_with_query("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "get_json_with_query", "request_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "request_json", "request_json_capped("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "request_json_capped", "read_capped_json("),
            ("crates/platform/chio-control-plane/src/trust_control/service_runtime/client/transport.rs", "read_capped_json", "crate::json_input::read("),
            ("crates/platform/chio-control-plane/src/json_input.rs", "read", "decode_signed("),
        ),
    },
    {
        "path": "crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs",
        "owner": "sign_public_settlement_proof_bundle",
        "call": "crate::input::project(settlement_proof.clone())",
        "custody": (
            ("crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs", "add_public_stage_settlement_trust_market_refs", "read_json_value("),
            ("crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs", "read_json_value", "crate::input::json("),
            ("crates/products/chio-cli/src/cli/input.rs", "json", "decode("),
            ("crates/products/chio-cli/src/cli/input.rs", "decode", "decode_signed("),
        ),
    },
    {
        "path": "crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs",
        "owner": "reseal_public_settlement_anchor_receipt",
        "call": "crate::input::project(receipt_value)",
        "custody": (
            ("crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs", "add_public_settlement_deployment_provenance_to_bundle", "read_json_value("),
            ("crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs", "read_json_value", "crate::input::json("),
            ("crates/products/chio-cli/src/cli/input.rs", "json", "decode("),
            ("crates/products/chio-cli/src/cli/input.rs", "decode", "decode_signed("),
        ),
    },
    {
        "path": "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/financial_receipt.rs",
        "owner": "validate_retained_financial_receipt",
        "call": "serde_json::from_value::<FinancialReceiptMetadata>).transpose()",
        "origin": "receipt member",
        "custody": (
            ("crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/financial_receipt.rs", "validate_retained_financial_receipt", "ChioReceipt"),
            ("crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/financial_receipt.rs", "validate_retained_financial_receipt", ".metadata"),
        ),
    },
    {
        "path": "crates/observability/chio-siem/src/event.rs",
        "owner": "from_receipt_with_trusted_kernel_keys",
        "call": "serde_json::from_value::<FinancialReceiptMetadata>(val.clone())",
        "origin": "receipt member",
        "custody": (
            ("crates/observability/chio-siem/src/event.rs", "from_receipt_with_trusted_kernel_keys", "ChioReceipt"),
            ("crates/observability/chio-siem/src/event.rs", "from_receipt_with_trusted_kernel_keys", ".metadata"),
        ),
    },
    {
        "path": "crates/platform/chio-store-sqlite/src/receipt_store/support/claim_log/metadata.rs",
        "owner": "extract_financial_metadata",
        "call": "serde_json::from_value::<FinancialReceiptMetadata>(value)",
        "origin": "receipt member",
        "custody": (
            ("crates/platform/chio-store-sqlite/src/receipt_store/support/claim_log/metadata.rs", "extract_financial_metadata", "ChioReceipt"),
            ("crates/platform/chio-store-sqlite/src/receipt_store/support/claim_log/metadata.rs", "extract_financial_metadata", ".metadata"),
        ),
    },
    {
        "path": "crates/platform/chio-store-sqlite/src/receipt_store/support/claim_log/schema.rs",
        "owner": "receipt_cost_projection",
        "call": "serde_json::from_value::<FinancialReceiptMetadata>(financial.clone())",
        "origin": "receipt member",
        "custody": (
            ("crates/platform/chio-store-sqlite/src/receipt_store/support/claim_log/schema.rs", "receipt_cost_projection", "ChioReceipt"),
            ("crates/platform/chio-store-sqlite/src/receipt_store/support/claim_log/schema.rs", "receipt_cost_projection", ".metadata"),
        ),
    },
    {
        "path": "crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs",
        "owner": "request_receipt_metadata_with_payee_binding",
        "call": "serde_json::from_value::<FinancialReceiptMetadata>(financial)",
        "origin": "kernel built",
        "custody": (
            ("crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs", "request_receipt_metadata", "request_receipt_metadata_with_payee_binding("),
            ("crates/kernel/chio-kernel/src/kernel/effect_obligation/preparation.rs", "prepare_post_effect", "request_receipt_metadata_with_payee_binding("),
            ("crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs", "record_pre_dispatch_cleanup_fault_receipt", "request_receipt_metadata_with_payee_binding("),
            ("crates/kernel/chio-kernel/src/kernel/responses/deny_responses.rs", "build_pre_execution_monetary_deny_response_with_recording", "request_receipt_metadata_with_payee_binding("),
            ("crates/kernel/chio-kernel/src/kernel/responses/deny_responses.rs", "prepare_deny_response_with_recording", "request_receipt_metadata_with_payee_binding("),
        ),
    },
)

RAW_CALL = re.compile(r"(?<![\w.:])(?:::\s*)?(?:serde_json\s*::\s*(?:(?:de|value)\s*::\s*)?)?from_(?:str|slice|reader|value)\s*(?=::|\()")
EXTRACTOR = re.compile(r"(?<![\w:])(?:::\s*)?(?:axum\s*::\s*)?(?:extract\s*::\s*)?(?:Json|Query|Form)\s*<")
TYPE_DEFINITION = re.compile(r"\b(?:struct|enum)\s+(\w+)\b[^;{(]*([({])")
IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*\b")
TYPE_ALIAS = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?type\s+(\w+)\b[^=;]*=\s*([^;]+);", re.M)
TRAIT_CALL = re.compile(
    r"(?<![\w:.])(?:::\s*)?(?:[a-z_]\w*\s*::\s*)*(?:Deserialize\b"
    r"|<\s*((?:[\w:&',\s]|<(?:[^<>]|<[^<>]*>)*>)+?)(?:\s+as\s+[\w:]+(?:\s*<[^<>]*>)?)?\s*>|([A-Z]\w*))\s*::\s*deserialize\s*\("
)
GENERIC_BOUND = re.compile(r"\b([A-Z]\w*)\s*:\s*(?:for\s*<[^<>]*>|[^,>{])*?\bDeserialize")
SERDE_JSON_USE = re.compile(r"use\s+(?:::\s*)?serde_json\b")
STREAM_CALL = re.compile(
    r"(?<![\w.:])(?:::\s*)?(?:serde_json\s*::\s*)?(?:de\s*::\s*)?Deserializer\s*::\s*from_(?:str|slice|reader)\s*\("
)
INTO_ITER = re.compile(r"^\s*\.\s*into_iter\s*::\s*<")
FROM_REQUEST = re.compile(r"\bfrom_request(?:_parts)?\s*\(")
BODY_EXTRACTOR = re.compile(r"(?<![\w:])(?:::\s*)?(?:axum\s*::\s*)?(?:extract\s*::\s*)?(?:Json|Query|Form)\s*(?:::\s*)?<")
IMPL_HEADER = re.compile(r"\bimpl\b[^{};]*\{")
BLOCK_HEADER = re.compile(r"\b(?:impl|trait)\b[^{};]*\{")
USE_STATEMENT = re.compile(r"\buse\s[^;]*;")
USE_RENAME = re.compile(r"\b(\w+)\s+as\s+(\w+)\b")
VARIANT_NAME = re.compile(r"([{,]\s*(?:#\[[^\]]*\]\s*)*)[A-Z]\w*(?=\s*(?:[,{(}]|=))")
DOCUMENT_CALL = re.compile(r"\.\s*decode_document\s*(?=::|\()")
STATIC_ITEM = re.compile(r"\b(?:static|const)\s+(?:mut\s+)?(\w+)\s*:\s*([^=;]+?)\s*=(?![=>])")
LET = re.compile(r"\blet\s+(?:mut\s+)?([\w()\s,]+?)\s*(?::\s*([^=;]+?))?\s*=(?![=>])")


def without_test_items(code: str) -> str:
    """Blank every `#[cfg(test)]` item in code whose comments and literals are masked."""
    output = list(code)
    for match in re.finditer(r"#\[cfg\(test\)\]", code):
        start = match.end()
        while start < len(code) and code[start] not in "{;":
            start += 1
        end = start + 1
        if start < len(code) and code[start] == "{":
            end = _contracts.closing(code, start, "{", "}")
        output[match.start():end] = " " * (end - match.start())
    return "".join(output)


NONPRODUCTION_ROOTS = frozenset({"bench", "examples", "tests"})


def production_roots(root: Path) -> list[str]:
    """Top-level directories that hold production workspace members."""
    roots = {"crates"}
    manifest = root / "Cargo.toml"
    if manifest.is_file():
        members = tomllib.loads(manifest.read_text(encoding="utf-8")).get("workspace", {}).get("members", [])
        roots |= {member.split("/")[0] for member in members} - NONPRODUCTION_ROOTS
    return sorted(roots)


def production_files(root: Path) -> list[tuple[str, str]]:
    files = []
    paths = sorted(path for top in production_roots(root) for path in (root / top).rglob("*"))
    for path in paths:
        rel = path.relative_to(root).as_posix()
        if path.suffix not in {".rs", ".inc"} or not _gate.production(path) or "examples" in rel.split("/") or path.name == "fuzz.rs":
            continue
        code = _lexer.blank_rust_noise(path.read_text(encoding="utf-8"))
        files.append((rel, without_test_items(code)))
    return files


@functools.lru_cache(maxsize=64)
def brace_pairs(code: str) -> dict[int, int]:
    """Each `{` offset in noise-blanked `code` mapped to its closing `}`."""
    pairs, stack = {}, []
    for index, char in enumerate(code):
        if char == "{":
            stack.append(index)
        elif char == "}" and stack:
            pairs[stack.pop()] = index
    return pairs


@functools.lru_cache(maxsize=64)
def block_spans(code: str) -> tuple[tuple[int, int, str], ...]:
    """(start, end, header) for every `impl` and `trait` block in `code`."""
    pairs = brace_pairs(code)
    return tuple(
        (match.start(), pairs.get(match.end() - 1, len(code)), match.group(0))
        for match in BLOCK_HEADER.finditer(code)
    )


def implementing_type(code: str, offset: int) -> str:
    """The type of the innermost `impl` block holding `offset`, or an empty string."""
    found = ""
    for start, end, header in block_spans(code):
        if start < offset < end and header.startswith("impl"):
            text = header[4:-1].strip()
            if text.startswith("<"):
                _, close = angle_argument(text, 0)
                text = text[close:]
            found = re.split(r"\bfor\b", text)[-1].split("where")[0].strip()
    return found


def strict_closure(files: list[tuple[str, str]]) -> frozenset[str]:
    """Names whose every workspace definition holds a strict type at any depth.

    A name defined more than once with a non-strict body stays out, so an
    unrelated type that shares a name with a wrapper is not swept in. Error
    types carry receipts for reporting and are never decoded from input."""
    definitions: dict[str, list[str]] = {}
    for _, code in files:
        for match in TYPE_DEFINITION.finditer(code):
            opening = match.end(2) - 1
            right = ")" if code[opening] == "(" else "}"
            close = _contracts.closing(code, opening, code[opening], right)
            body = code[opening:close]
            if match.group(0).startswith("enum"):
                body = VARIANT_NAME.sub(r"\1", body)
            if not match.group(1).endswith("Error"):
                definitions.setdefault(match.group(1), []).append(body)
        for statement in USE_STATEMENT.finditer(code):
            for original, alias in USE_RENAME.findall(statement.group(0)):
                if original != alias:
                    definitions.setdefault(alias, []).append(original)
        for match in TYPE_ALIAS.finditer(code):
            if not any(start < match.start() < end for start, end, _ in block_spans(code)):
                definitions.setdefault(match.group(1), []).append(match.group(2))
    strict = set(STRICT_TYPES)
    changed = True
    while changed:
        changed = False
        for name, bodies in definitions.items():
            if name not in strict and all(set(IDENTIFIER.findall(body)) & strict for body in bodies):
                strict.add(name)
                changed = True
    return frozenset(strict)


def mentions_strict(text: str, strict: frozenset[str]) -> bool:
    return bool(set(IDENTIFIER.findall(text)) & strict)


def angle_argument(code: str, index: int) -> tuple[str, int]:
    """Return the text inside the `<...>` that opens at `index`."""
    close = _contracts.closing(code, index, "<", ">")
    return code[index + 1:close - 1], close


def return_type(fn_code: str) -> str:
    parameters = fn_code.find("(")
    after = _contracts.closing(fn_code, parameters)
    body = fn_code.find("{", after)
    signature = fn_code[after:body if body >= 0 else len(fn_code)]
    arrow = signature.find("->")
    if arrow < 0:
        return ""
    value = signature[arrow + 2:].split("where")[0].strip()
    wrapper = re.match(r"(?:[\w:]*::)?(?:Result|Option)\s*<", value)
    if wrapper:
        argument, _ = angle_argument(value, wrapper.end() - 1)
        depth = 0
        for index, char in enumerate(argument):
            depth += (char == "<") - (char == ">")
            if char == "," and depth == 0:
                return argument[:index]
        return argument
    return value


def normalized(text: str) -> str:
    return re.sub(r"\s+", "", text)


def call_text(code: str, start: int) -> str:
    paren = code.find("(", start)
    return normalized(code[start:_contracts.closing(code, paren)])


def statement_end(code: str, index: int) -> int:
    """The `;` that ends the expression starting at `index`, or the enclosing close."""
    depth = 0
    while index < len(code):
        char = code[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth < 0:
                break
        elif char == ";" and depth == 0:
            break
        index += 1
    return index


@functools.lru_cache(maxsize=4096)
def let_spans(fn_code: str) -> tuple[tuple[int, int, str, str], ...]:
    """(initializer start, initializer end, pattern, annotation) for each `let`."""
    spans = []
    for match in LET.finditer(fn_code):
        if re.search(r"(?:\bif|\bwhile|&&)\s*$", fn_code[:match.start()]):
            continue
        index = statement_end(fn_code, match.end())
        spans.append((match.end(), index, match.group(1).strip(), (match.group(2) or "").strip()))
    return tuple(spans)


def enclosing_let(fn_code: str, offset: int) -> tuple[str, str]:
    """The pattern and annotation of the innermost `let` whose initializer holds `offset`.

    The call may sit anywhere in that initializer, so a decode wrapped in a
    `match`, an `if let` or a method chain still takes the binding's type."""
    found = ("", "")
    for start, end, pattern, annotation in let_spans(fn_code):
        if start <= offset < end:
            found = (pattern, annotation)
    return found


def let_annotation(fn_code: str, offset: int) -> str:
    return enclosing_let(fn_code, offset)[1]


def returned(fn_code: str, offset: int) -> bool:
    """Whether the call at `offset` is the function's value: its tail or a `return`."""
    statement_start = max(fn_code.rfind(";", 0, offset), fn_code.rfind("{", 0, offset)) + 1
    prefix = fn_code[statement_start:offset].strip()
    if prefix.startswith("return"):
        return True
    pieces = prefix.split("(")
    if pieces[-1].strip() or not all(re.fullmatch(r"\s*[A-Za-z_][\w:]*\s*", piece) for piece in pieces[:-1]):
        return False
    paren = fn_code.find("(", offset)
    end = _contracts.closing(fn_code, paren)
    rest = fn_code[end:]
    rest = re.sub(r"^(?:\s*(?:\?|\)|\.\s*\w+\s*(?:::<[^;{}]*?>)?\s*\([^;{}]*?\)))*", "", rest)
    return rest.strip() == "}"


def let_binding(fn_code: str, offset: int) -> str:
    """The name an unannotated `let` binds to the call at `offset`, if any."""
    pattern, annotation = enclosing_let(fn_code, offset)
    return pattern if not annotation and re.fullmatch(r"\w+", pattern) else ""


def binding_returned(fn_code: str, offset: int, name: str) -> bool:
    """Whether `name` is the function's value after the statement at `offset`."""
    rest = fn_code[offset:]
    word = re.escape(name)
    if re.search(r"\breturn\s+(?:(?:Ok|Some)\(\s*)?" + word + r"\b", rest):
        return True
    if re.search(r"(?<![\w.])(?:Ok|Some)\(\s*" + word + r"\s*\)\s*}\s*$", rest):
        return True
    return bool(re.search(r"(?<![\w.])" + word + r"\s*}\s*$", rest))


def generic_parameters(fn_code: str) -> set[str]:
    signature_end = fn_code.find("{")
    return set(GENERIC_BOUND.findall(fn_code[:signature_end if signature_end >= 0 else len(fn_code)]))


def raw_aliases(code: str) -> tuple:
    """Per-file patterns for serde_json crate and function renames in `use` trees.

    Covers `use serde_json as x`, `use serde_json::{self as x}` and
    `use serde_json::{de::from_str as y, ..}`."""
    crates, functions = [], []
    for statement in USE_STATEMENT.finditer(code):
        text = statement.group(0)
        if not SERDE_JSON_USE.match(text):
            continue
        crates += re.findall(r"\b(?:serde_json|self)\s+as\s+(\w+)", text)
        functions += re.findall(r"\b(from_(?:str|slice|reader|value))\s+as\s+(\w+)", text)
    patterns = []
    if crates:
        patterns.append(re.compile(
            r"(?<![\w.:])(?:" + "|".join(map(re.escape, crates))
            + r")\s*::\s*(?:(?:de|value)\s*::\s*)?(from_(?:str|slice|reader|value))\s*(?=::|\()"
        ))
    for source, alias in functions:
        patterns.append(re.compile(r"(?<![\w.:])" + re.escape(alias) + r"(?P<" + source + r">)\s*(?=::|\()"))
    return tuple(patterns)


def receiver_start(code: str, index: int) -> int:
    """Where the method-call receiver ending just before `index` begins."""
    position = index - 1
    while position >= 0:
        char = code[position]
        if char in ")]":
            depth = 0
            while position >= 0:
                if code[position] in ")]":
                    depth += 1
                elif code[position] in "([":
                    depth -= 1
                    if depth == 0:
                        break
                position -= 1
            position -= 1
        elif char.isalnum() or char in "_:.?" or char.isspace() and code[position - 1] in ".:":
            position -= 1
        else:
            break
    return position + 1


def decode_sites(fn_code: str, body_start: int, helpers: dict[str, str], aliases: tuple = ()):
    """Yield (offset, explicit target or None, input kind) for each raw decode in a body.

    The input kind is "value" when the decode reads an already parsed Value and
    "text" when it reads wire text or a deserializer.
    """
    for match in RAW_CALL.finditer(fn_code, body_start):
        kind = "value" if match.group(0).rstrip().endswith("from_value") else "text"
        after = fn_code[match.end():].lstrip()
        if after.startswith("::"):
            target, _ = angle_argument(fn_code, fn_code.index("<", match.end()))
            yield match.start(), target, kind
        else:
            yield match.start(), None, kind
    for pattern in aliases:
        for match in pattern.finditer(fn_code, body_start):
            source = match.group(1) if pattern.groups and match.group(1) else next(iter(pattern.groupindex), "")
            kind = "value" if source == "from_value" else "text"
            after = fn_code[match.end():].lstrip()
            if after.startswith("::"):
                target, _ = angle_argument(fn_code, fn_code.index("<", match.end()))
                yield match.start(), target, kind
            else:
                yield match.start(), None, kind
    for match in TRAIT_CALL.finditer(fn_code, body_start):
        yield match.start(), match.group(1) or match.group(2), "text"
    for match in DOCUMENT_CALL.finditer(fn_code, body_start):
        start = receiver_start(fn_code, match.start())
        after = fn_code[match.end():].lstrip()
        if after.startswith("::"):
            target, _ = angle_argument(fn_code, fn_code.index("<", match.end()))
            yield start, target, "text"
        else:
            yield start, None, "text"
    for match in STREAM_CALL.finditer(fn_code, body_start):
        end = _contracts.closing(fn_code, match.end() - 1)
        if INTO_ITER.match(fn_code[end:]):
            target, _ = angle_argument(fn_code, fn_code.index("<", end))
            yield match.start(), target, "text"
        elif "StreamDeserializer" in let_annotation(fn_code, match.start()):
            yield match.start(), let_annotation(fn_code, match.start()), "text"
    if helpers:
        pattern = re.compile(r"(?<![\w.])(?:\w+\s*::\s*)*(" + "|".join(sorted(map(re.escape, helpers))) + r")\s*(?=::\s*<|\()")
        for match in pattern.finditer(fn_code, body_start):
            after = fn_code[match.end():].lstrip()
            kind = helpers[match.group(1)]
            if after.startswith("::"):
                target, _ = angle_argument(fn_code, fn_code.index("<", match.end()))
                yield match.start(), target, kind
            else:
                yield match.start(), None, kind


def assigned_annotation(fn_code: str, offset: int) -> str:
    """The declared type of `name` when the call is the value of `name = ...`."""
    statement_start = max(fn_code.rfind(";", 0, offset), fn_code.rfind("{", 0, offset)) + 1
    assignment = re.fullmatch(r"\s*(\w+)\s*=\s*", fn_code[statement_start:offset])
    if not assignment:
        return ""
    name = re.escape(assignment.group(1))
    declarations = re.findall(r"\blet\s+(?:mut\s+)?" + name + r"\s*:\s*([^=;]+?)\s*;", fn_code[:offset])
    return declarations[-1] if declarations else ""


def targets(fn_code: str, offset: int, explicit, returns: str) -> str:
    """The decode target text: explicit, annotated, or the function's value type."""
    if explicit is not None:
        return explicit
    annotation = let_annotation(fn_code, offset) or assigned_annotation(fn_code, offset)
    if annotation:
        return annotation
    if returned(fn_code, offset):
        return returns
    name = let_binding(fn_code, offset)
    if name and binding_returned(fn_code, offset, name):
        return returns
    return ""


def crate_of(rel: str) -> str:
    return rel.split("/src/")[0]


def generic_raw_helpers(files: list[tuple[str, str]]) -> dict[str, dict[str, str]]:
    """Per crate, functions generic over a `Deserialize` parameter that raw decode it.

    Each helper maps to "value" when every such decode reads a Value, else "text".
    """
    helpers: dict[str, dict[str, str]] = {}
    for rel, code in files:
        for row in _contracts.functions(code):
            fn_code = _contracts.owner_code(code, row)
            parameters = generic_parameters(fn_code)
            if not parameters:
                continue
            returns = return_type(fn_code)
            for offset, explicit, kind in decode_sites(fn_code, row[2] - row[1], {}):
                if set(IDENTIFIER.findall(targets(fn_code, offset, explicit, returns))) & parameters:
                    crate = helpers.setdefault(crate_of(rel), {})
                    name = row[0].split("#")[0]
                    crate[name] = "text" if "text" in (kind, crate.get(name)) else "value"
    return helpers


def custody_breaks(by_path: dict[str, str], custody, origin: str = "decode_signed") -> str:
    """The first custody link its source does not satisfy, or an empty string."""
    if origin not in {"decode_signed", "receipt member", "kernel built"}:
        return f"an unknown origin {origin}"
    signed = origin == "decode_signed"
    if not custody or signed and "decode_signed" not in custody[-1][2]:
        return "a chain that does not end in decode_signed"
    for index, (path, function, call) in enumerate(custody):
        code = by_path.get(path, "")
        bodies = [
            _contracts.owner_code(code, row)
            for row in _contracts.functions(code)
            if row[0].split("#")[0] == function
        ]
        token = re.sub(r"\s+", "", call)
        holders = [body for body in bodies if token in re.sub(r"\s+", "", body)]
        if signed and index == len(custody) - 1:
            holders = [
                body for body in holders
                if all(kind == "value" for _, _, kind in decode_sites(body, body.find("{"), {}))
            ]
        if not holders:
            return f"{path}::{function} -> {call}"
    return ""


@functools.lru_cache(maxsize=64)
def deserialize_impls(code: str) -> tuple[tuple[int, int], ...]:
    """Extents of every `impl` of `Deserialize` or a serde `Visitor` in `code`."""
    return tuple(
        (start, end)
        for start, end, header in block_spans(code)
        if header.startswith("impl") and re.search(r"\b(?:Deserialize|Visitor)\b", header)
    )


def in_deserialize_impl(code: str, offset: int) -> bool:
    """Whether `offset` sits inside an `impl` of `Deserialize` or a serde `Visitor`."""
    return any(start < offset < end for start, end in deserialize_impls(code))


def scan(root: Path) -> list[str]:
    files = production_files(root)
    strict = strict_closure(files)
    helpers = generic_raw_helpers(files)
    aliases = {rel: raw_aliases(code) for rel, code in files}
    findings = []
    for rel, code in files:
        for row in _contracts.functions(code):
            owner = row[0]
            fn_code = _contracts.owner_code(code, row)
            arguments_start = fn_code.find("(")
            arguments = fn_code[arguments_start:_contracts.closing(fn_code, arguments_start)]
            for match in EXTRACTOR.finditer(arguments):
                target, _ = angle_argument(arguments, match.end() - 1)
                if mentions_strict(target, strict):
                    findings.append((rel, owner, normalized(match.group(0) + target + ">"), "extractor", "text"))
            body_start = row[2] - row[1]
            for match in FROM_REQUEST.finditer(fn_code, body_start):
                statement_start = max(fn_code.rfind(c, 0, match.start()) for c in ";{}") + 1
                statement = fn_code[statement_start:match.start()] + " " + let_annotation(fn_code, match.start())
                for extractor in BODY_EXTRACTOR.finditer(statement):
                    target, _ = angle_argument(statement, extractor.end() - 1)
                    if mentions_strict(target, strict):
                        findings.append((rel, owner, call_text(fn_code, match.start()), "extractor", "text"))
                        break
            if owner.split("#")[0] == "deserialize" and in_deserialize_impl(code, row[1]):
                continue
            returns = return_type(fn_code)
            self_type = implementing_type(code, row[1])
            for offset, explicit, kind in decode_sites(fn_code, body_start, helpers.get(crate_of(rel), {}), aliases[rel]):
                target = targets(fn_code, offset, explicit, returns)
                if self_type:
                    target = re.sub(r"\bSelf\b", self_type, target)
                if mentions_strict(target, strict):
                    findings.append((rel, owner, call_text(fn_code, offset), "decode", kind))
        rows = _contracts.functions(code)
        for item in STATIC_ITEM.finditer(code):
            if any(row[1] < item.start() < row[3] for row in rows):
                continue
            initializer = code[item.start():statement_end(code, item.end())]
            for offset, explicit, kind in decode_sites(initializer, item.end() - item.start(), helpers.get(crate_of(rel), {}), aliases[rel]):
                target = explicit if explicit is not None else item.group(2)
                if mentions_strict(target, strict):
                    findings.append((rel, f"static {item.group(1)}", call_text(initializer, offset), "decode", kind))
    errors = []
    remaining = list(findings)
    by_path = dict(files)
    for entry in ALLOWED:
        key = (entry["path"], entry["owner"], normalized(entry["call"]), "decode", "value")
        count = entry.get("count", 1)
        matched = [finding for finding in remaining if finding == key]
        broken = custody_breaks(by_path, entry["custody"], entry.get("origin", "decode_signed"))
        if len(matched) != count:
            errors.append(f"{entry['path']}::{entry['owner']}: approved call {entry['call']} expects {count}, found {len(matched)}")
        elif broken:
            errors.append(f"{entry['path']}::{entry['owner']}: custody broken at {broken}")
        for finding in matched:
            remaining.remove(finding)
    errors.extend(f"{rel}::{owner}: raw {site} {text}" for rel, owner, text, site, _ in remaining)
    return errors


FIXTURES = {
    "direct raw decode": ("fn f(t: &str) { let r = serde_json::from_str::<ChioReceipt>(t); }", 1),
    "multi-line turbofish": ("fn f(t: &str) {\n    let r = serde_json::from_str::<\n        ChioReceipt,\n    >(t);\n}", 1),
    "annotated slice": ("fn f(b: &[u8]) -> Result<(), E> {\n    let body: ChioReceiptBody =\n        serde_json::from_slice(b)?;\n    Ok(())\n}", 1),
    "inferred return": ("fn f(t: &str) -> Result<ChioReceipt, serde_json::Error> {\n    serde_json::from_str(t)\n}", 1),
    "imported from_str": ("use serde_json::from_str;\nfn f(t: &str) -> Option<Vec<ChioReceipt>> { from_str(t).ok() }", 1),
    "after a test module": ("#[cfg(test)]\nmod tests { fn t() {} }\nfn f(t: &str) { serde_json::from_str::<ChioReceipt>(t); }", 1),
    "test module only": ("#[cfg(test)]\nmod tests { fn t() { serde_json::from_str::<ChioReceipt>(\"{}\"); } }", 0),
    "comment and literal": ("fn f() { // serde_json::from_str::<ChioReceipt>(t)\n let s = \"serde_json::from_str::<ChioReceipt>(t)\"; }", 0),
    "transitive wrapper": ("struct Wrapper { inner: Vec<ChioReceipt> }\nfn f(t: &str) { serde_json::from_str::<Wrapper>(t); }", 1),
    "wrapper extractor": ("struct Request { receipt: ChildRequestReceipt }\nasync fn h(Json(r): Json<Request>) {}", 1),
    "multi-line extractor": ("async fn h(\n    Json(r): Json<\n        ChioReceipt,\n    >,\n) {}", 1),
    "decode_signed": ("fn f(t: &str) -> Result<ChioReceipt, E> { UntrustedJsonText::new(t).decode_signed() }", 0),
    "unrelated decode": ("fn f(t: &str) -> Result<Other, E> { serde_json::from_str(t) }", 0),
    "inferred local returned": ("fn f(t: &str) -> Result<ChioReceipt, E> { let receipt = serde_json::from_str(t)?; Ok(receipt) }", 1),
    "inferred local returned by return": ("fn f(t: &str) -> Result<ChioReceipt, E> {\n    let receipt = serde_json::from_str(t)?;\n    check(&receipt);\n    return Ok(receipt);\n}", 1),
    "inferred local not returned": ("fn f(t: &str) -> Result<ChioReceipt, E> { let other = serde_json::from_str(t)?; use_it(other); build() }", 0),
    "type alias": ("type Receipt = ChioReceipt;\nfn f(t: &str) { serde_json::from_str::<Receipt>(t); }", 1),
    "associated type": ("impl Visitor for V {\n    type Value = ChioReceipt;\n}\nfn f(t: &str) { serde_json::from_str::<Value>(t); }", 0),
    "generic helper": ("fn decode<T: serde::de::DeserializeOwned>(t: &str) -> Result<T, E> { serde_json::from_str(t) }\nfn f(t: &str) -> Result<ChioReceipt, E> { decode(t) }", 1),
    "generic helper turbofish": ("fn decode<T>(t: &str) -> Result<T, E> where T: serde::de::DeserializeOwned { serde_json::from_slice(t) }\nfn f(t: &[u8]) { let r = crate::input::decode::<ChioReceipt>(t); }", 1),
    "strict generic helper": ("fn decode<T: serde::de::DeserializeOwned>(t: &str) -> Result<T, E> { UntrustedJsonText::new(t).decode_signed() }\nfn f(t: &str) -> Result<ChioReceipt, E> { decode(t) }", 0),
    "direct trait": ("fn f(d: &mut serde_json::Deserializer<serde_json::de::StrRead>) -> Result<ChioReceipt, E> { ChioReceipt::deserialize(d) }", 1),
    "qualified trait": ("fn f(d: D) -> Result<ChioReceipt, E> { let r = serde::Deserialize::deserialize(d)?; Ok(r) }", 1),
    "match-wrapped annotation": ("fn f(value: Value) -> Result<(), E> { let receipt: ChioReceipt = match serde_json::from_value(value) { Ok(r) => r, Err(e) => return Err(e) }; consume(receipt); Ok(()) }", 1),
    "if-let wrapped annotation": ("fn f(t: &str) {\n    let receipt: Option<ChioReceipt> = if let Ok(r) = serde_json::from_str(t) {\n        Some(r)\n    } else {\n        None\n    };\n}", 1),
    "match-wrapped local returned": ("fn f(t: &str) -> Option<ChioReceipt> { let receipt = match serde_json::from_str(t) { Ok(r) => r, Err(_) => return None }; Some(receipt) }", 1),
    "wrapped decode of another type": ("fn f(t: &str) { let body: Other = match serde_json::from_str(t) { Ok(r) => r, Err(_) => return }; }", 0),
    "higher-ranked helper bound": ("fn decode<T: for<'de> Deserialize<'de>>(t: &str) -> Result<T, E> { serde_json::from_str(t) }\nfn f(t: &str) -> Result<ChioReceipt, E> { decode(t) }", 1),
    "higher-ranked where bound": ("fn decode<T>(t: &str) -> Result<T, E>\nwhere\n    T: Clone + for<'de> serde::Deserialize<'de>,\n{\n    serde_json::from_str(t)\n}\nfn f(t: &str) -> Result<ChioReceipt, E> { decode(t) }", 1),
    "fully qualified trait": ("fn f(d: D) -> Result<ChioReceipt, E> { <ChioReceipt as serde::Deserialize>::deserialize(d) }", 1),
    "fully qualified trait with lifetime": ("fn f(d: D) -> Result<(), E> { let r = <ChioReceiptBody as Deserialize<'_>>::deserialize(d)?; Ok(()) }", 1),
    "crate alias": ("use serde_json as json;\nfn f(t: &str) { json::from_str::<ChioReceipt>(t); }", 1),
    "function alias": ("use serde_json::from_str as decode_raw;\nfn f(t: &str) -> Result<ChioReceipt, E> { decode_raw(t) }", 1),
    "aliased Value read of another type": ("use serde_json as json;\nfn f(v: Value) { json::from_value::<Other>(v); }", 0),
    "boxed return": ("fn f(raw: &str) -> Result<Box<ChioReceipt>, E> { Ok(Box::new(serde_json::from_str(raw)?)) }", 1),
    "free function named deserialize": ("fn deserialize(raw: &str) { serde_json::from_str::<ChioReceipt>(raw); }", 1),
    "inherent method named deserialize": ("impl Loader {\n    fn deserialize(&self, raw: &str) -> Result<ChioReceipt, E> { serde_json::from_str(raw) }\n}", 1),
    "visitor impl": ("impl<'de> Visitor<'de> for V {\n    fn deserialize(self, d: D) -> Result<ChioReceipt, E> { ChioReceipt::deserialize(d) }\n}", 0),
    "streaming decode": ("fn f(raw: &str) { for r in serde_json::Deserializer::from_str(raw).into_iter::<ChioReceipt>() { use_it(r); } }", 1),
    "streaming decode of another type": ("fn f(raw: &str) { for r in serde_json::Deserializer::from_str(raw).into_iter::<Other>() { use_it(r); } }", 0),
    "body extractor": ("async fn h(request: Request, state: &S) {\n    let Json(r): Json<ChioReceipt> = Json::from_request(request, state).await?;\n}", 1),
    "body extractor turbofish": ("async fn h(request: Request, state: &S) { let r = Json::<ChildRequestReceipt>::from_request(request, state).await; }", 1),
    "body extractor of another type": ("async fn h(request: Request, state: &S) { let Json(r): Json<Other> = Json::from_request(request, state).await?; }", 0),
    "absolute crate path": ("fn f(raw: &str) -> Result<ChioReceipt,E> { ::serde_json::from_str(raw) }", 1),
    "absolute turbofish": ("fn f(raw: &[u8]) { let r = ::serde_json::from_slice::<ChildRequestReceipt>(raw); }", 1),
    "absolute trait path": ("fn f(d: D) -> Result<ChioReceipt, E> { ::serde::Deserialize::deserialize(d) }", 1),
    "module-qualified type": ("fn f(d: D) { let r = chio_core::receipt::body::ChioReceipt::deserialize(d); }", 1),
    "absolute stream": ("fn f(raw: &str) { ::serde_json::Deserializer::from_str(raw).into_iter::<ChioReceipt>(); }", 1),
    "absolute extractor": ("async fn h(::axum::Json(r): ::axum::Json<ChioReceipt>) {}", 1),
    "declared then assigned": ("fn f(raw: &str) -> Result<(), E> {\n    let receipt: ChioReceipt;\n    receipt = serde_json::from_str(raw)?;\n    consume(receipt);\n    Ok(())\n}", 1),
    "assigned other type": ("fn f(raw: &str) { let body: Other; body = serde_json::from_str(raw).unwrap_or_default(); }", 0),
    "Self in a strict impl": ("struct Wrapper { receipt: ChioReceipt }\nimpl Wrapper {\n    fn parse(raw: &str) -> Result<Self, E> { serde_json::from_str(raw) }\n}", 1),
    "Self in a generic trait impl": ("impl<'a> FromStr for ChildRequestReceipt {\n    fn from_str(raw: &str) -> Result<Self, E> { serde_json::from_str(raw) }\n}", 1),
    "Self in an unrelated impl": ("impl Other {\n    fn parse(raw: &str) -> Result<Self, E> { serde_json::from_str(raw) }\n}", 0),
    "scoped type alias": ("mod wire {\n    type Receipt = ChioReceipt;\n    fn f(t: &str) { serde_json::from_str::<Receipt>(t); }\n}", 1),
    "lazy static initializer": ("static RECEIPT: LazyLock<ChioReceipt> = LazyLock::new(|| serde_json::from_str(RAW).unwrap_or_default());", 1),
    "const of another type": ("static OTHER: LazyLock<Other> = LazyLock::new(|| serde_json::from_str(RAW).unwrap_or_default());", 0),
    "decode_document of a receipt": ("fn f(raw: &str) -> Result<ChioReceipt, E> { UntrustedJsonText::new(raw).decode_document() }", 1),
    "decode_document turbofish": ("fn f(raw: &str) { let r = UntrustedJsonText::new(raw).decode_document::<ChildRequestReceipt>(); }", 1),
    "decode_document of another type": ("fn f(raw: &str) -> Result<Other, E> { UntrustedJsonText::new(raw).decode_document() }", 0),
    "enum variant named like a strict type": ("struct Published { r: ChioReceipt }\nenum State {\n    Intent,\n    Published,\n    Conflict { actual: String },\n}\nfn f(t: &str) { serde_json::from_str::<State>(t); }", 0),
    "enum variant holding a strict type": ("enum State {\n    Intent,\n    Sealed(ChioReceipt),\n}\nfn f(t: &str) { serde_json::from_str::<State>(t); }", 1),
    "renamed import": ("use chio_core::receipt::body::ChioReceipt as Receipt;\nfn f(raw: &str) { serde_json::from_str::<Receipt>(raw); }", 1),
    "grouped renamed import": ("use chio_core::receipt::{body::ChioReceipt as Signed, lineage::ChildRequestReceipt};\nfn f(raw: &str) -> Result<Signed, E> { serde_json::from_str(raw) }", 1),
    "renamed import of another type": ("use other::Thing as Receipt;\nfn f(raw: &str) { serde_json::from_str::<Receipt>(raw); }", 0),
    "financial receipt metadata": ("fn f(raw: &str) { serde_json::from_str::<FinancialReceiptMetadata>(raw); }", 1),
    "wrapped fully qualified target": ("fn f(d: D) -> Result<(), E> { let r = <Option<ChioReceipt> as Deserialize>::deserialize(d)?; Ok(()) }", 1),
    "nested fully qualified target": ("fn f(d: D) { let r = <Vec<Option<ChildRequestReceipt>> as serde::Deserialize<'_>>::deserialize(d); }", 1),
    "wrapped fully qualified other type": ("fn f(d: D) { let r = <Option<Other> as Deserialize>::deserialize(d); }", 0),
    "grouped function alias": ("use serde_json::{from_str as decode, Value};\nfn f(raw: &str) { decode::<ChioReceipt>(raw); }", 1),
    "grouped module function alias": ("use serde_json::{de::from_slice as read_bytes, Value};\nfn f(raw: &[u8]) -> Result<ChioReceipt, E> { read_bytes(raw) }", 1),
    "grouped crate self alias": ("use serde_json::{self as json, Value};\nfn f(raw: &str) { json::from_str::<ChioReceipt>(raw); }", 1),
    "alias outside serde_json": ("use other::{from_str as decode};\nfn f(raw: &str) { decode::<ChioReceipt>(raw); }", 0),
    "de module path": ("fn f(raw: &str) { serde_json::de::from_str::<ChioReceipt>(raw); }", 1),
    "value module path": ("fn f(value: Value) -> Result<ChioReceipt, E> { serde_json::value::from_value(value) }", 1),
    "aliased crate module path": ("use serde_json as json;\nfn f(raw: &str) { json::de::from_str::<ChioReceipt>(raw); }", 1),
    "custom deserialize impl": ("impl<'de> Deserialize<'de> for Wrapper { fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> { ChioReceipt::deserialize(d).map(Wrapper) } }", 0),
}


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "crates/demo/src/lib.rs"
        source.parent.mkdir(parents=True)
        for label, (code, expected) in FIXTURES.items():
            source.write_text(code + "\n", encoding="utf-8")
            found = len(scan(root))
            if found != expected + len(ALLOWED):
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {found - len(ALLOWED)}")
        for label, name, expected in (("included fragment", "part.inc", 1), ("test fragment", "part_tests.inc", 0)):
            fragment = root / "crates/demo/src" / name
            fragment.write_text("fn f(t: &str) { serde_json::from_str::<ChioReceipt>(t); }\n", encoding="utf-8")
            source.write_text("\n", encoding="utf-8")
            found = len(scan(root)) - len(ALLOWED)
            fragment.unlink()
            if found != expected:
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {found}")
        manifest = root / "Cargo.toml"
        manifest.write_text('[workspace]\nmembers = ["crates/demo", "integrations/demo", "examples/demo"]\n', encoding="utf-8")
        for label, top, expected in (("workspace member outside crates", "integrations", 1), ("example member", "examples", 0)):
            member_source = root / top / "demo/src/lib.rs"
            member_source.parent.mkdir(parents=True, exist_ok=True)
            member_source.write_text("fn f(t: &str) { serde_json::from_str::<ChioReceipt>(t); }\n", encoding="utf-8")
            found = len(scan(root)) - len(ALLOWED)
            member_source.write_text("\n", encoding="utf-8")
            if found != expected:
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {found}")
        manifest.unlink()
        allowed = ALLOWED[0]
        target = root / allowed["path"]
        target.parent.mkdir(parents=True)
        source.write_text("\n", encoding="utf-8")
        signed = "UntrustedJsonText::new(raw).decode_signed()"
        for label, body, producer, expected in (
            ("approved call", "let receipt: ChioReceipt = serde_json::from_value(value)?;", signed, 0),
            ("raw text at the approved path", "let receipt: ChioReceipt = serde_json::from_str(raw)?;", signed, 2),
            ("producer regressed to a raw decode", "let receipt: ChioReceipt = serde_json::from_value(value)?;", "serde_json::from_str(raw)", 1),
            ("producer with a raw decode beside decode_signed", "let receipt: ChioReceipt = serde_json::from_value(value)?;", f"{{ let _: Value = serde_json::from_str(raw)?; {signed} }}", 1),
        ):
            target.write_text(
                f"fn decode_stored_json(raw: &str) -> Result<Value, E> {{ {producer} }}\n"
                f"fn {allowed['owner']}(raw: &str) -> Result<ChioReceipt, E> {{\n"
                f"    let value = decode_stored_json(raw)?;\n    {body}\n    Ok(receipt)\n}}\n",
                encoding="utf-8",
            )
            found = len(scan(root)) - (len(ALLOWED) - 1)
            if found != expected:
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {found}")
        target.write_text("\n", encoding="utf-8")
        other = root / "crates/other/src/lib.rs"
        other.parent.mkdir(parents=True)
        other.write_text("fn decode<T: DeserializeOwned>(t: &str) -> Result<T, E> { serde_json::from_str(t) }\n", encoding="utf-8")
        for label, code, expected in (
            ("same-named helper in another crate", "fn f(t: &str) -> Result<ChioReceipt, E> { crate::input::decode(t) }", 0),
            ("helper in the same crate", "fn decode<T: DeserializeOwned>(t: &str) -> Result<T, E> { serde_json::from_str(t) }\nfn f(t: &str) -> Result<ChioReceipt, E> { crate::input::decode(t) }", 1),
        ):
            source.write_text(code + "\n", encoding="utf-8")
            found = len(scan(root)) - len(ALLOWED)
            if found != expected:
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {found}")
        other.write_text("\n", encoding="utf-8")
        source.write_text("\n", encoding="utf-8")
        member = next(entry for entry in ALLOWED if entry["owner"] == "extract_financial_metadata")
        target = root / member["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        for label, read, expected in (
            ("receipt member", "receipt.metadata.as_ref()", 0),
            ("receipt member read from elsewhere", "other.as_ref()", 1),
        ):
            target.write_text(
                f"fn {member['owner']}(receipt: &ChioReceipt, other: Option<Value>) {{ let value = {read}; "
                f"let projection = {member['call']}; }}\n",
                encoding="utf-8",
            )
            matched = [error for error in scan(root) if member["owner"] in error]
            if len(matched) != expected:
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {matched}")
        target.write_text("\n", encoding="utf-8")
        helper_entry = next(entry for entry in ALLOWED if entry["owner"] == "verify_backfill_receipts")
        target = root / helper_entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        for label, reader, expected in (
            ("approved Value helper", "serde_json::from_value(value.clone())", 0),
            ("approved helper reading text", "serde_json::from_str(value.as_str())", 2),
        ):
            target.write_text(
                "fn load_and_build_report(bytes: &[u8]) { parse_shadow_migration_input(bytes); }\n"
                "fn parse_shadow_migration_input(bytes: &[u8]) -> R { UntrustedJsonText::from_wire(bytes, 1)?.decode_signed() }\n"
                f"fn strict_typed_value<T: DeserializeOwned>(value: &Value, label: &str) -> Result<T, E> {{ Ok({reader}?) }}\n"
                f"fn {helper_entry['owner']}(registered: Registered) -> Result<(), E> {{\n"
                f"    let receipt: ChioReceipt = strict_typed_value(&registered.receipt, \"label\")?;\n    Ok(())\n}}\n",
                encoding="utf-8",
            )
            found = len(scan(root)) - (len(ALLOWED) - 1)
            if found != expected:
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {found}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    self_test()
    errors = scan(args.root)
    if errors:
        print("raw JSON decode of a strict type outside decode_signed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"committed receipt raw decode: {len(STRICT_TYPES)} strict types, {len(ALLOWED)} pinned from_value calls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
