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
it (with `Self` read as the implementing type), either directly, through the
tail of an `if` branch, `match` arm or block, as the scrutinee of a tail
`match` or `if let`, or through an unannotated `let` binding that the function
returns. A `_` placeholder in a target is completed by that context. A decode
whose target is neither named nor completed by context is refused as inferred
unless ALLOWED_INFERRED names it with a reason. An extractor (`Json`, `Query`,
`Form`, or an import of axum's) is flagged when its type argument is strict.
A `macro_rules!` template decode is flagged when its concrete target is
strict, when a target that depends on a capture is expanded by an invocation
whose arguments name a strict type, and, for a template decode without a
target, at each expansion site whose context is strict. Each exception in ALLOWED names
one exact call in one function that reads an already parsed `Value`, together
with the duplicate-refusing reader that produced it. The script checks itself
against fixture trees on every run before it scans the workspace.

Every production workspace member is scanned: `crates/` and each other
declared member directory except `bench`, `examples` and `tests`. A renamed
import (`use path::ChioReceipt as Receipt`) is read as an alias.

The scan resolves lexical crate/module paths, type aliases and imports before
computing the strict wrapper closure, and resolves renamed `serde_json` crates,
modules, functions and `Deserializer` imports. It does not perform Rust type
inference, trait dispatch or general macro expansion, or follow generic helpers
in other crates; inferred targets it cannot name fail closed instead.
A pass is evidence for the listed forms only.
"""

from __future__ import annotations

import argparse
import functools
import importlib.util
import io
import re
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace

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
_resolution = _load("receipt_type_resolution", ROOT / "scripts/receipt_type_resolution.py")

# The receipt types that carry a serde_json::Value member (action parameters,
# metadata). Derived impls already refuse a duplicate field of a Chio object;
# only a Value member can keep the last of two duplicate keys.
EXCLUDED_TYPE_MODULES = {
    "crates/core/chio-core-types/src/_generated/chio_wire_v1":
        "Generated wire mirrors are decoded through the typed v1 decoder, outside raw receipt strictness.",
}

ALLOWED_TYPE_PATHS: dict[tuple[str, str], str] = {}

# Raw decodes whose target the scan cannot name (inferred from a use the scan
# does not follow), keyed by (path, function, whitespace-normalized call), each
# with the reason its inferred type holds no strict receipt type.
ALLOWED_INFERRED: dict[tuple[str, str, str], str] = {
    ("crates/core/chio-response-model/src/simulation.rs", "apply_effect", "decode(&effect.canonical_contribution)"):
        "Inferred SessionSuspensionSpec and SessionThrottleLimits, effect contribution members; neither holds a receipt type.",
    ("crates/guards/chio-guards/src/embedding_anomaly.rs", "from_json_file", ".decode_document()"):
        "Inferred Vec<PatternEntry> from from_entries; guard pattern rows hold no receipt type.",
    ("crates/kernel/chio-kernel/src/admission_operation/native_dispatch_binding.rs", "from_ledger", "serde_json::from_value(value.get().cloned().unwrap_or(serde_json::Value::Null),)"):
        "Inferred PersistedAdmissionOperationV1 member of a ledger Value already parsed by decode_signed in from_ledger.",
    ("crates/kernel/chio-kernel/src/kernel/session_ops.rs", "parse_tool_call_operation_dpop", "serde_json::from_value(value.clone())"):
        "Inferred DpopProof from the Option return type through map and transpose; a DPoP proof holds no receipt type.",
    ("crates/kernel/chio-kernel/src/tool_outcome/release/persistence.rs", "validate_zero_charge_records", "parse_artifact_value(&checked_artifacts[0])"):
        "Inferred PersistedToolOutcomeRecordV1 from ToolOutcomeRecordV1::from_persisted; it holds no receipt type.",
    ("crates/kernel/chio-kernel/src/tool_outcome/release/persistence.rs", "validate_zero_charge_records", "parse_artifact_value(&checked_artifacts[1])"):
        "Inferred PersistedPostReturnEvaluationRecordV1 from PostReturnEvaluationRecordV1::from_persisted; it holds no receipt type.",
    ("crates/kernel/chio-process/src/lib.rs", "tool_request", "serde_json::from_value(json!({:String::from_utf8(canonical_json_bytes(&arguments)?).map_err(|_|ProcessError::Invalid())?,}))"):
        "Inferred ToolCallRequest supplemental_authorization from a kernel-built json! object, not external input.",
    ("crates/kernel/chio-process/src/mailboxes/mod.rs", "dispatch", "serde_json::from_value(arguments)"):
        "Inferred mailbox Send, Receive and Acknowledge argument structs from the store calls; none holds a receipt type.",
    ("crates/kernel/chio-process/src/state_reader.rs", "checkpoint", "serde_json::from_str(&value.ok_or(ProcessError::Invalid())?,)"):
        "Inferred Checkpoint.value, a serde_json::Value.",
    ("crates/kernel/chio-process/src/store.rs", "read_process", "serde_json::from_str(&capability)"):
        "Inferred the stored process capability field, a CapabilityToken, not a receipt type.",
    ("crates/kernel/chio-process/src/store.rs", "read_process", "serde_json::from_str(&checkpoint)"):
        "Inferred Checkpoint.value, a serde_json::Value.",
    ("crates/kernel/chio-process/src/store.rs", "read_process", "serde_json::from_str(&limits)"):
        "Inferred the stored process limits field, a ProcessLimits.",
    ("crates/kernel/chio-process/src/store/children.rs", "waits", "serde_json::from_str(&children)"):
        "Inferred Vec<String> child ids from the BTreeMap<String, Vec<String>> return type.",
    ("crates/kernel/chio-process/src/store/children.rs", "work", "serde_json::from_str(&input)"):
        "Inferred ChildWork.input, a serde_json::Value.",
    ("crates/kernel/chio-process/src/store/children.rs", "worker_wait", "serde_json::from_str(&children)"):
        "Inferred WorkerWait.children, a Vec<String>.",
    ("crates/kernel/chio-runtime-core/src/admission_hook/treaty_evidence.rs", "verify_treaty_reference_from_store", "load_treaty_artifact::<_,CrossKernelContinuation>(store,,reference,,,)"):
        "The turbofish names CrossKernelContinuation; the placeholder fills the store parameter S.",
    ("crates/kernel/chio-runtime-core/src/admission_hook/treaty_evidence.rs", "verify_treaty_reference_from_store", "load_treaty_artifact::<_,ReceiptLineageBundle>(store,,reference,,,)"):
        "The turbofish names ReceiptLineageBundle, which holds no strict receipt type; the placeholder fills the store parameter S.",
    ("crates/kernel/chio-runtime-core/src/admission_hook/treaty_evidence.rs", "verify_treaty_reference_from_store", "load_treaty_artifact::<_,chio_federation::bilateral_dsse::DsseEnvelope>(store,,reference,,,)"):
        "The turbofish names DsseEnvelope; the placeholder fills the store parameter S.",
    ("crates/platform/chio-control-plane/src/fiscal_state_anchor.rs", "compare_and_swap", "serde_json::from_slice(advance.canonical_proof_bytes())"):
        "Inferred FiscalStateCasRequest.advance_proof, a serde_json::Value.",
    ("crates/products/chio-cli/src/cli/mcp/provision/discovery.rs", "discover_tool_surface", "serde_json::from_value(tools)"):
        "Inferred Vec<McpToolInfo> from the function return type through a closure; tool descriptors hold no receipt type.",
    ("crates/products/chio-cli/src/cli/process_host/call_evidence/outcomes_export.rs", "export", "serde_json::from_value(source[].clone())"):
        "Inferred Outcomes.authorities, a Vec<SwarmAuthorityBundle>, which holds no strict receipt type.",
    ("crates/products/chio-cli/src/cli/process_response_verify.rs", "response_nonce", "serde_json::from_value(value.clone())"):
        "Inferred SignedExecutionNonce from the Option return type; a nonce holds no receipt type.",
    ("crates/protocol/chio-a2a-edge/src/jsonrpc.rs", "handle_jsonrpc", ".decode_document()"):
        "Inferred serde_json::Value from handle_jsonrpc_value(message: Value).",
    ("crates/protocol/chio-acp-edge/src/jsonrpc.rs", "handle_jsonrpc", ".decode_document()"):
        "Inferred serde_json::Value from handle_jsonrpc_value(message: Value).",
    ("crates/protocol/chio-mcp-adapter/src/framing.rs", "read_jsonrpc_frame_with_admission", ".decode_document()"):
        "Inferred serde_json::Value from the Option<(Value, T)> return type.",
    ("crates/protocol/chio-mcp-adapter/src/transport/stdio_parts/transport.inc", "complete_prompt_argument", "serde_json::from_value(completion_value.clone())"):
        "Inferred CompletionResult from the Option return type.",
    ("crates/protocol/chio-mcp-adapter/src/transport/stdio_parts/transport.inc", "complete_resource_argument", "serde_json::from_value(completion_value.clone())"):
        "Inferred CompletionResult from the Option return type.",
    ("crates/protocol/chio-mcp-adapter/src/transport/stdio_parts/transport.inc", "get_prompt", "serde_json::from_value(result)"):
        "Inferred PromptResult from the Option return type.",
    ("crates/protocol/chio-mcp-adapter/src/transport/stdio_parts/transport.inc", "read_resource", "serde_json::from_value(contents_value.clone())"):
        "Inferred Vec<ResourceContent> from the Option return type.",
    ("crates/protocol/chio-mcp-edge/src/ingress/framing.rs", "read_document_frame_with_admission", ".decode_document()"):
        "Inferred serde_json::Value from the Option<(Value, T)> return type.",
    ("crates/protocol/chio-mcp-edge/src/runtime/protocol/parsing.rs", "parse_request_approval_artifacts", "serde_json::from_value(value.clone())"):
        "Inferred Option<GovernedApprovalToken> from the ParsedApprovalArtifacts tuple; an approval token holds no receipt type.",
    ("crates/protocol/chio-openapi/src/extensions.rs", "from_operation", "decode_extension(map,)"):
        "Inferred Option<Sensitivity> and Option<bool> extension members of the Self literal.",
    ("crates/protocol/chio-provider-adapter-core/src/input.rs", "arguments", "json_bounded(text.as_bytes(),MAX_ARGUMENT_BYTES)"):
        "Inferred serde_json::Value from argument_object(value: Value).",
    ("crates/sdk/chio-binding-helpers/src/signing.rs", "json_document", "text.decode_document()"):
        "Inferred serde_json::Value from the Result<Value> return type through and_then.",
    ("crates/security/chio-active-response-authority/src/store.rs", "prepare_logical_records", "serde_json::from_slice(&payload)"):
        "Inferred LogicalRecord.payload, a serde_json::Value.",
    ("crates/tooling/chio-conformance/src/native_suite.rs", "collect_native_scenarios", "serde_json::from_str(&content)"):
        "Inferred NativeScenarioDescriptor pushed into Vec<NativeScenarioDescriptor>; it holds no strict receipt type.",
    ("crates/tooling/chio-conformance/src/runner/restart_probe.rs", "parse_sse", "text.decode_document()"):
        "Inferred SseEvent.message, a serde_json::Value.",
    ("crates/tooling/chio-conformance/src/runner/restart_probe.rs", "validate_initialize", "text.decode_document()"):
        "Inferred serde_json::Value conformance responses filtered by their id member.",
    ("xtask/src/decision_model_compile.rs", "run", "read_json(rules)"):
        "Inferred RulesFile from compile(rules: &RulesFile, ..).",
    ("xtask/src/decision_model_compile.rs", "run", "read_json(thresholds)"):
        "Inferred ThresholdsFile from compile(.., thresholds: &ThresholdsFile).",
    ("xtask/src/recovery_authority_vectors.rs", "corpus", "typed(&grant[][])"):
        "Inferred the declassification claims body signed by SignedDeclassificationGrant::sign in xtask vector generation.",
    ("xtask/src/recovery_authority_vectors.rs", "sign_positive", "typed(&positive[][])"):
        "Inferred the provider finality body signed by SignedRecoveryProviderFinalityV1::sign in xtask vector generation.",
    ("xtask/src/recovery_authority_vectors.rs", "sign_positive", "typed(&proof[])"):
        "Inferred the coverage attestation body signed by SignedAuthorityCoverageAttestationV1::sign in xtask vector generation.",
}

ALLOWED_INCLUDES = {
    ("crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs", 'concat!(env!("OUT_DIR"),"/proof_fixture_files.rs")'):
        "proof_fixture_build.rs emits only the EmbeddedProofFixtureFile constant array, not types or decoders.",
    ("crates/products/chio-proof-room/src/lib.rs", 'concat!(env!("OUT_DIR"),"/proof_fixture_files.rs")'):
        "proof_fixture_build.rs emits only the EmbeddedProofFixtureFile constant array, not types or decoders.",
    ("crates/protocol/chio-a2a-adapter/src/lib.rs", '"fuzz.rs"'):
        "The fuzz-only source is outside the production decode gate, matching production_files exclusions.",
}

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
        "path": "crates/products/chio-cli/src/cli/process_host/call_evidence.rs",
        "owner": "verify_file",
        "call": "crate::input::project(signed.action.parameters.clone())",
        "custody": (
            ("crates/products/chio-cli/src/cli/process_host/call_evidence.rs", "verify_file", "verify_original_receipt("),
            ("crates/products/chio-cli/src/cli/receipt_verify.rs", "verify_original_receipt", "crate::input::decode("),
            ("crates/products/chio-cli/src/cli/input.rs", "decode", "decode_signed("),
        ),
    },
    {
        "path": "crates/products/chio-cli/src/cli/process_host/run_evidence.rs",
        "owner": "verify_file",
        "call": "serde_json::from_value(signed.action.parameters.clone())",
        "custody": (
            ("crates/products/chio-cli/src/cli/process_host/run_evidence.rs", "verify_file", "verify_original_receipt("),
            ("crates/products/chio-cli/src/cli/receipt_verify.rs", "verify_original_receipt", "crate::input::decode("),
            ("crates/products/chio-cli/src/cli/input.rs", "decode", "decode_signed("),
        ),
    },
    {
        "path": "crates/products/chio-cli/src/cli/process_host/call_evidence/outcomes.rs",
        "owner": "verify_outcomes",
        "call": "serde_json::from_value(signed_call.action.parameters.clone())",
        "custody": (
            ("crates/products/chio-cli/src/cli/process_host/call_evidence/outcomes.rs", "verify_file", "verify_outcomes("),
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
TRAIT_CALL = re.compile(
    r"(?<![\w:.])(?:::\s*)?(?:[a-z_]\w*\s*::\s*)*(?:Deserialize\b"
    r"|<\s*((?:[\w:&',\s$]|<(?:[^<>]|<[^<>]*>)*>)+?)(?:\s+as\s+[\w:]+(?:\s*<[^<>]*>)?)?\s*>|([A-Z]\w*))\s*::\s*deserialize\s*\("
)
GENERIC_BOUND = re.compile(r"\b([A-Z]\w*)\s*:\s*(?:for\s*<[^<>]*>|[^,>{])*?\bDeserialize")
STREAM_CALL = re.compile(
    r"(?<![\w.:])(?:::\s*)?(?:serde_json\s*::\s*)?(?:de\s*::\s*)?Deserializer\s*::\s*from_(?:str|slice|reader)\s*\("
)
INTO_ITER = re.compile(r"^\s*\.\s*into_iter\s*::\s*<")
FROM_REQUEST = re.compile(r"\bfrom_request(?:_parts)?\s*\(")
BODY_EXTRACTOR = re.compile(r"(?<![\w:])(?:::\s*)?(?:axum\s*::\s*)?(?:extract\s*::\s*)?(?:Json|Query|Form)\s*(?:::\s*)?<")
IMPL_HEADER = re.compile(r"\bimpl\b[^{};]*\{")
BLOCK_HEADER = re.compile(r"\b(?:impl|trait)\b[^{};]*\{")
USE_STATEMENT = re.compile(r"\buse\s[^;]*;")
VARIANT_NAME = re.compile(r"([{,]\s*(?:#\[[^\]]*\]\s*)*)[A-Z]\w*(?=\s*(?:[,{(}]|=))")
DOCUMENT_CALL = re.compile(r"\.\s*decode_document\s*(?=::|\()")
STATIC_ITEM = re.compile(r"\b(?:static|const)\s+(?:mut\s+)?(\w+)\s*:\s*([^=;]+?)\s*=(?![=>])")
LET = re.compile(r"\blet\s+(?:mut\s+)?([\w()\s,]+?)\s*(?::\s*([^=;]+?))?\s*=(?![=>])")
QUALIFIED_DECODE = re.compile(
    r"(?<![\w.:$])((?:::\s*)?[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*)\s*::\s*(from_(?:str|slice|reader|value))\s*(?=::|\()"
)
TYPE_APPLICATION = re.compile(r"(?<![\w.:$])((?:::\s*)?[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*)\s*(?:::\s*)?<")
PLACEHOLDER = re.compile(r"(?<![\w$'])_(?!\w)")
CAPTURE = re.compile(r"\$(?!crate\b)\w+")
MACRO_RULES = re.compile(r"\bmacro_rules!\s*(\w+)\s*\{")
INVOCATION = re.compile(r"(?<![\w$])(\w+)\s*!\s*([({\[])")
SERDE_JSON_DECODE_MODULES = frozenset({(), ("de",), ("value",)})
SERDE_JSON_STREAMS = frozenset({("Deserializer",), ("de", "Deserializer")})
AXUM_EXTRACTORS = frozenset({"Json", "Query", "Form"})


def production_cfg(expression: str):
    expression = expression.strip()
    if expression == "test":
        return False
    match = re.fullmatch(r"(all|any|not)\((.*)\)", expression, re.S)
    if not match:
        return None
    values = [production_cfg(part) for part in _resolution.split_arguments(match.group(2))]
    if match.group(1) == "not":
        return not values[0] if len(values) == 1 and values[0] is not None else None
    if match.group(1) == "all":
        return False if False in values else True if all(value is True for value in values) else None
    return True if True in values else False if all(value is False for value in values) else None


def without_test_items(code: str) -> str:
    """Blank every `#[cfg(test)]` item in code whose comments and literals are masked."""
    output = list(code)
    for match in re.finditer(r"#\[cfg\((.*?)\)\]", code, re.S):
        if production_cfg(match.group(1)) is not False:
            continue
        start = match.end()
        prefix = re.match(r"\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?", code[start:])
        fragment = start + prefix.end()
        item = re.match(r"(?:async\s+|unsafe\s+)?(?:fn|mod|struct|enum|impl|trait|type|const|static|use)\b", code[fragment:])
        if not item:
            macro = re.match(r"(?:::\s*)?\w+(?:\s*::\s*\w+)*\s*!\s*([({\[])", code[fragment:])
            if macro:
                opening = fragment + macro.end() - 1
                delimiter = code[opening]
                end = _contracts.closing(code, opening, delimiter, {"(": ")", "[": "]", "{": "}"}[delimiter])
                trailing = re.match(r"\s*;", code[end:])
                if trailing:
                    end += trailing.end()
            else:
                end = fragment
                depth = 0
                while end < len(code):
                    char = code[end]
                    if depth == 0 and char in ",;}":
                        end += char in ",;"
                        break
                    if char == "}" and depth == 1:
                        end += 1
                        break
                    depth += char in "([{"
                    depth -= char in ")]}" and depth > 0
                    end += 1
            output[match.start():end] = " " * (end - match.start())
            continue
        while start < len(code) and code[start] not in "{;":
            start += 1
        end = start + 1
        if start < len(code) and code[start] == "{":
            end = _contracts.closing(code, start, "{", "}")
        output[match.start():end] = " " * (end - match.start())
    return "".join(output)


NONPRODUCTION_ROOTS = frozenset({"bench", "examples", "tests"})


def production_roots(root: Path) -> list[str]:
    """Production crates and the declared non-crate workspace member directories."""
    roots = {"crates"}
    manifest = root / "Cargo.toml"
    if manifest.is_file():
        members = tomllib.loads(manifest.read_text(encoding="utf-8")).get("workspace", {}).get("members", [])
        roots |= {path.relative_to(root).as_posix() for member in members if member.split("/")[0] not in NONPRODUCTION_ROOTS | {"crates"} for path in root.glob(member) if path.is_dir()}
    return sorted(roots)


def production_code(path: Path) -> str:
    """Noise-blanked production source; a `fn $name` template item reads as `fn _name`."""
    code = without_test_items(_lexer.blank_rust_noise(path.read_text(encoding="utf-8")))
    return re.sub(r"\bfn(\s+)\$(?=\w)", lambda match: "fn" + match.group(1) + "_", code)


def production_files(root: Path) -> list[tuple[str, str]]:
    files = []
    paths = sorted({path for top in production_roots(root) for path in (root / top).rglob("*")})
    for path in paths:
        rel = path.relative_to(root).as_posix()
        if path.suffix not in {".rs", ".inc"} or not _gate.production(path) or "examples" in rel.split("/") or path.name == "fuzz.rs":
            continue
        files.append((rel, production_code(path)))
    seen = {rel for rel, _ in files}
    for rel, code in files:
        for _, child, expression in _resolution.include_paths(root, rel, code, _contracts, crate_of):
            if (rel, expression) in ALLOWED_INCLUDES or child is None or child in seen:
                continue
            path = root / child
            if path.is_file() and path.suffix in {".rs", ".inc"} and path.resolve().is_relative_to(root.resolve()):
                seen.add(child)
                files.append((child, production_code(path)))
    return _resolution.production_module_files(root, files, SimpleNamespace(**globals()))


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


def impl_parameters(code: str, offset: int) -> set[str]:
    """The generic parameter names of the innermost `impl` block holding `offset`."""
    found = set()
    for start, end, header in block_spans(code):
        if start < offset < end and header.startswith("impl"):
            text = header[4:-1].strip()
            found = set()
            if text.startswith("<"):
                inner, _ = angle_argument(text, 0)
                found = {match.group(1) for part in _resolution.split_arguments(inner) if (match := re.match(r"\s*(?:const\s+)?(\w+)", part))}
    return found


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


def call_end(code: str, offset: int) -> int:
    """The end of the call starting at `offset`, past any turbofish or qualified-path angles."""
    index = offset
    while index < len(code):
        if code[index] == "<":
            index = _contracts.closing(code, index, "<", ">")
        elif code[index] == "(":
            return _contracts.closing(code, index)
        elif code[index] in ";{}":
            return index
        else:
            index += 1
    return index


def condition_end(code: str, index: int):
    """The `{` that opens the block after an `if` or `match` head starting at `index`."""
    while index < len(code):
        char = code[index]
        if char in "([":
            index = _contracts.closing(code, index, char, ")" if char == "(" else "]")
            continue
        if char == "{":
            return index
        if char in ";}":
            return None
        index += 1
    return None


@functools.lru_cache(maxsize=4096)
def control_flow(fn_code: str) -> tuple:
    """(start, end, keyword, head end, branch block openings) for each `match` and `if` chain."""
    pairs = brace_pairs(fn_code)
    rows = []
    for match in re.finditer(r"\b(if|match)\b", fn_code):
        if match.group(1) == "if" and re.search(r"\belse\s*$", fn_code[max(0, match.start() - 16):match.start()]):
            continue
        opening = condition_end(fn_code, match.end())
        if opening is None or opening not in pairs:
            continue
        blocks = [opening]
        end = pairs[opening] + 1
        while match.group(1) == "if":
            chained = re.match(r"\s*else\b\s*", fn_code[end:])
            if not chained:
                break
            position = end + chained.end()
            if re.match(r"if\b", fn_code[position:]):
                opening = condition_end(fn_code, position + 2)
            else:
                opening = position if fn_code[position:position + 1] == "{" else None
            if opening is None or opening not in pairs:
                break
            blocks.append(opening)
            end = pairs[opening] + 1
        rows.append((match.start(), end, match.group(1), blocks[0], tuple(blocks)))
    return tuple(rows)


def value_prefix(prefix: str) -> bool:
    """Whether `prefix` only wraps the expression after it in constructor calls."""
    pieces = prefix.split("(")
    return not pieces[-1].strip() and all(re.fullmatch(r"\s*[A-Za-z_][\w:]*\s*", piece) for piece in pieces[:-1])


def postfix_end(code: str, index: int) -> int:
    """The first token after the `?`, `.await`, closing wrapper parens and method calls at `index`."""
    while True:
        while index < len(code) and code[index].isspace():
            index += 1
        if index < len(code) and code[index] in "?)":
            index += 1
            continue
        method = re.match(r"\.\s*(\w+)\s*(?:::\s*(?=<))?", code[index:])
        if not method:
            return index
        position = index + method.end()
        if method.group(1) == "await":
            index = position
            continue
        if code[position:position + 1] == "<":
            position = _contracts.closing(code, position, "<", ">")
            while position < len(code) and code[position].isspace():
                position += 1
        if code[position:position + 1] != "(":
            return index
        index = _contracts.closing(code, position)


def tail_value(fn_code: str, start: int, end: int, depth: int = 0) -> bool:
    """Whether the expression in `[start, end)` is the function's value.

    The expression is the value of a `return`, the function body's tail, or the
    tail of a block, `if` branch or `match` arm whose construct is itself the
    function's value."""
    if depth > 64:
        return False
    pairs = brace_pairs(fn_code)
    openings = {close: opening for opening, close in pairs.items()}
    statement_start = max(fn_code.rfind(char, 0, start) for char in ";{}") + 1
    prefix = fn_code[statement_start:start]
    if prefix.strip().startswith("return"):
        return True
    arm = "=>" in prefix
    if arm:
        prefix = prefix.rsplit("=>", 1)[1]
    if not value_prefix(prefix):
        return False
    following = postfix_end(fn_code, end)
    if following >= len(fn_code) or fn_code[following] not in ",}":
        return False
    constructs = control_flow(fn_code)
    if arm:
        holders = [row for row in constructs if row[2] == "match" and row[3] < start < pairs[row[3]]]
        if holders:
            row = max(holders, key=lambda row: row[3])
            if fn_code[following] == "," or following == pairs[row[3]]:
                return tail_value(fn_code, row[0], row[1], depth + 1)
    if fn_code[following] != "}":
        return False
    opening = openings.get(following)
    if opening is None:
        return False
    if following == len(fn_code.rstrip()) - 1:
        return True
    for row in constructs:
        if row[2] == "if" and opening in row[4]:
            return tail_value(fn_code, row[0], row[1], depth + 1)
    before = fn_code[:opening].rstrip()
    if before.endswith("=>"):
        holders = [row for row in constructs if row[2] == "match" and row[3] < opening < pairs[row[3]]]
        if holders:
            row = max(holders, key=lambda row: row[3])
            return tail_value(fn_code, row[0], row[1], depth + 1)
        return False
    if not before or before[-1] in ";{}" or re.search(r"\bunsafe$", before):
        return tail_value(fn_code, opening, following + 1, depth + 1)
    return False


def returned(fn_code: str, offset: int) -> bool:
    """Whether the call at `offset` is the function's value, or the scrutinee of a
    `match` or `if let` that is."""
    if tail_value(fn_code, offset, call_end(fn_code, offset)):
        return True
    for start, end, keyword, head, _ in control_flow(fn_code):
        if start < offset < head and (keyword == "match" or re.match(r"if\s+let\b", fn_code[start:head])):
            if tail_value(fn_code, start, end):
                return True
    return False


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


def decode_sites(fn_code: str, body_start: int, helpers: dict[str, str], resolve=None, aliases=None):
    """Yield (offset, explicit target or None, input kind) for each raw decode in a body.

    The input kind is "value" when the decode reads an already parsed Value and
    "text" when it reads wire text or a deserializer. `resolve(path, offset)`
    names the items a path reaches, so a renamed `serde_json` crate, module,
    function or `Deserializer` (matched by `aliases`) and a qualified helper path
    resolve to their source.
    """
    def turbofish(index):
        after = fn_code[index:].lstrip()
        return angle_argument(fn_code, fn_code.index("<", index))[0] if after.startswith("::") else None

    def stream(start, paren):
        end = _contracts.closing(fn_code, paren)
        if INTO_ITER.match(fn_code[end:]):
            return start, angle_argument(fn_code, fn_code.index("<", end))[0], "text"
        if re.match(r"\s*\.\s*into_iter\s*\(", fn_code[end:]):
            return start, None, "text"
        if "StreamDeserializer" in let_annotation(fn_code, start):
            return start, let_annotation(fn_code, start), "text"
        return None

    seen = set()
    for match in RAW_CALL.finditer(fn_code, body_start):
        seen.add(match.start())
        yield match.start(), turbofish(match.end()), "value" if match.group(0).rstrip().endswith("from_value") else "text"
    if resolve and aliases:
        for match in aliases.finditer(fn_code, body_start):
            paths = {key[2:] for key in resolve(match.group(1), match.start()) if key[:2] == (":external", "serde_json")}
            source = next((path[-1] for path in paths if path[:-1] in SERDE_JSON_DECODE_MODULES and path[-1:] and path[-1].startswith("from_")), None)
            if source:
                seen.add(match.start())
                yield match.start(), turbofish(match.end()), "value" if source == "from_value" else "text"
    for match in STREAM_CALL.finditer(fn_code, body_start):
        seen.add(match.start())
        site = stream(match.start(), match.end() - 1)
        if site:
            yield site
    if resolve:
        for match in QUALIFIED_DECODE.finditer(fn_code, body_start):
            if match.start() in seen:
                continue
            paths = {key[2:] for key in resolve(match.group(1), match.start()) if key[:2] == (":external", "serde_json")}
            if paths & SERDE_JSON_STREAMS:
                site = stream(match.start(), fn_code.index("(", match.end()))
                if site:
                    yield site
            elif paths & SERDE_JSON_DECODE_MODULES:
                yield match.start(), turbofish(match.end()), "value" if match.group(2) == "from_value" else "text"
    for match in TRAIT_CALL.finditer(fn_code, body_start):
        target = match.group(1)
        if target is None and match.group(2):
            target = re.sub(r"\s*::\s*deserialize\s*\($", "", match.group()).strip()
            if match.start() > 0 and fn_code[match.start() - 1] == "$":
                target = "$" + target
        yield match.start(), target, "text"
    for match in DOCUMENT_CALL.finditer(fn_code, body_start):
        yield receiver_start(fn_code, match.start()), turbofish(match.end()), "text"
    if helpers:
        pattern = re.compile(r"(?<![\w.])((?:\w+\s*::\s*)*)(" + "|".join(sorted(map(re.escape, helpers))) + r")\s*(?=::\s*<|\()")
        for match in pattern.finditer(fn_code, body_start):
            qualifier = tuple(part.strip() for part in match.group(1).split("::")[:-1])
            if resolve and not resolve.helper(qualifier, match.group(2), match.start()):
                continue
            yield match.start(), turbofish(match.end()), helpers[match.group(2)]


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
    """The decode target text: explicit, annotated, or the function's value type.

    An explicit target holding a `_` placeholder is completed by its context, and
    is empty, like an inferred target, when no context names the type."""
    if explicit is not None and not PLACEHOLDER.search(explicit):
        return explicit
    context = contextual_target(fn_code, offset, returns)
    if explicit is not None:
        return f"({explicit}, {context})" if context else ""
    return context


def placeholder_strict(explicit, mentions) -> bool:
    """Whether the named parts of a placeholder target already hold a strict type."""
    return explicit is not None and bool(PLACEHOLDER.search(explicit)) and mentions(PLACEHOLDER.sub("()", explicit))


def contextual_target(fn_code: str, offset: int, returns: str) -> str:
    annotation = let_annotation(fn_code, offset) or assigned_annotation(fn_code, offset)
    if annotation:
        return annotation
    if returned(fn_code, offset):
        return returns or "()"
    name = let_binding(fn_code, offset)
    if name and binding_returned(fn_code, offset, name):
        return returns or "()"
    return ""


def crate_of(rel: str) -> str:
    return rel.split("/src/")[0]


def generic_raw_helpers(files: list[tuple[str, str]], resolver=None, aliases=None):
    """Per crate, functions generic over a `Deserialize` parameter that raw decode it.

    Each helper maps to "value" when every such decode reads a Value, else "text".
    A decode whose target the scan cannot name counts as a decode of the
    parameter, so every caller is checked. The second value lists each helper
    definition as (path, offset, name, whether it is an associated function).
    """
    helpers: dict[str, dict[str, str]] = {}
    definitions = set()
    for rel, code in files:
        for row in _contracts.functions(code):
            fn_code = _contracts.owner_code(code, row)
            parameters = generic_parameters(fn_code)
            if not parameters:
                continue
            returns = return_type(fn_code)
            resolve = resolver(rel, row[1]) if resolver else None
            for offset, explicit, kind in decode_sites(fn_code, row[2] - row[1], {}, resolve, aliases):
                target = targets(fn_code, offset, explicit, returns)
                if not target or set(IDENTIFIER.findall(target)) & parameters:
                    crate = helpers.setdefault(crate_of(rel), {})
                    name = row[0].split("#")[0]
                    crate[name] = "text" if "text" in (kind, crate.get(name)) else "value"
                    definitions.add((rel, row[1], name, bool(implementing_type(code, row[1]))))
    return helpers, definitions


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
    by_path = dict(files)
    strict = _resolution.TypeResolver(root, files, SimpleNamespace(**globals()))
    templates = {}
    for rel, code in files:
        spans = []
        for match in MACRO_RULES.finditer(code):
            end = _contracts.closing(code, match.end() - 1, "{", "}")
            body = code[match.end():end]
            definitions = {}
            for definition in TYPE_DEFINITION.finditer(body):
                opening = definition.end() - 1
                closing = _contracts.closing(body, opening, body[opening], {"(": ")", "{": "}"}[body[opening]])
                fields = body[opening:closing]
                if definition.group().startswith("enum"):
                    fields = strict.enum_fields(fields)
                fields = re.sub(r"\bpub(?:\([^)]*\))?\s+", "", fields)
                fields = re.sub(r"\b\w+\s*:(?!:)", "", fields)
                definitions[definition.group(1)] = fields
            for alias in re.finditer(r"\btype\s+(\w+)\s*=([^;]+);", body):
                definitions[alias.group(1)] = alias.group(2)
            spans.append((match.start(), end, definitions, match.group(1), match.end()))
        templates[rel] = spans

    resolved = {}

    def resolve_path(text, rel, offset):
        path = tuple(part.strip() for part in text.split("::"))
        found = set()
        for scope in strict.scopes(rel, offset):
            if (path, scope) not in resolved:
                resolved[(path, scope)] = strict.resolve(path, scope)
            found |= resolved[(path, scope)]
        return found

    def function_paths(path, scope, seen=frozenset()):
        """The module paths a function path written in `scope` can name."""
        if not path or path[0] in {"crate", "self", "super", ""}:
            target = strict.absolute(path[1:] if path and path[0] == "" else path, scope) if path else None
            if not target:
                return set()
            for split in range(len(target) - 1, 0, -1):
                alias = strict.imports[target[:split]].get(target[split])
                if alias and (target[split], target[:split]) not in seen:
                    return function_paths(alias + target[split + 1:], target[:split], seen | {(target[split], target[:split])})
            return {target}
        current = scope
        while current:
            alias = strict.imports[current].get(path[0])
            if alias and (path[0], current) not in seen:
                return function_paths(alias + path[1:], current, seen | {(path[0], current)})
            if not current[-1].startswith("@"):
                break
            current = current[:-1]
        found = {strict.module(scope) + path}
        target = strict.absolute(path, scope)
        if target:
            found.add(target)
        current = scope
        while current:
            for glob in strict.globs[current]:
                if (("*",) + glob, current) not in seen:
                    found |= function_paths(glob + path, current, seen | {(("*",) + glob, current)})
            if not current[-1].startswith("@"):
                break
            current = current[:-1]
        return found

    helper_paths, associated_helpers = set(), set()
    known_functions = {
        strict.module(scope) + (row[0].split("#")[0],)
        for rel, code in files for row in _contracts.functions(code) for scope in strict.scopes(rel, row[1])
    }

    class Paths:
        """Item and function path resolution at offsets of one source body."""

        def __init__(self, rel, base):
            self.rel, self.base = rel, base

        def __call__(self, text, offset):
            return resolve_path(text, self.rel, self.base + offset)

        def helper(self, qualifier, name, offset):
            if qualifier and (qualifier[-1] == "Self" or qualifier[-1][:1].isupper()):
                return name in associated_helpers
            for scope in strict.scopes(self.rel, self.base + offset):
                paths = function_paths(qualifier + (name,), scope)
                if paths & helper_paths or paths and not paths & known_functions and all(path[0] != ":external" for path in paths):
                    return True
            return False

    def resolver(rel, base):
        return Paths(rel, base)

    alias_names = {
        alias for imports in strict.imports.values() for alias, path in imports.items()
        if path and re.fullmatch(r"from_(?:str|slice|reader|value)", path[-1]) and alias != path[-1]
    }
    aliases = re.compile(r"(?<![\w.:$])(" + "|".join(sorted(map(re.escape, alias_names))) + r")\s*(?=::|\()") if alias_names else None

    def template_at(rel, offset):
        return next((span for span in templates[rel] if span[0] <= offset < span[1]), None)

    def expand(text, definitions, seen=frozenset()):
        text = re.sub(r"\$crate\b", "crate", text)

        def replace(match):
            name = match.group()
            if name not in definitions:
                return name
            return "()" if name in seen else "(" + expand(definitions[name], definitions, seen | {name}) + ")"
        return _resolution.PATH.sub(replace, text)

    def expanded(target, rel, offset):
        span = template_at(rel, offset)
        return (expand(target, span[2]), span[3]) if span else (target, None)

    def mentions_target(target, rel, offset):
        return strict.mentions(CAPTURE.sub("()", expanded(target, rel, offset)[0]), rel, offset)

    macro_names = {span[3] for spans in templates.values() for span in spans}
    invocations = {name: [] for name in macro_names}
    for rel, code in files:
        for match in INVOCATION.finditer(code):
            if match.group(1) not in macro_names:
                continue
            opening = match.end() - 1
            delimiter = code[opening]
            end = _contracts.closing(code, opening, delimiter, {"(": ")", "[": "]", "{": "}"}[delimiter])
            invocations[match.group(1)].append((rel, match.start(), code[opening + 1:end - 1], normalized(code[match.start():end])))

    def invoked_with_strict(name):
        for rel, offset, arguments, text in invocations[name]:
            arguments = CAPTURE.sub("()", re.sub(r"\$crate\b", "crate", arguments))
            if any(strict.references(arguments, scope) & strict.strict for scope in strict.scopes(rel, offset)):
                yield rel, offset, text

    def owner_at(rel, offset, fallback):
        row = _contracts.function_at(by_path[rel], offset)
        return (row[0], row) if row else (fallback, None)

    findings, inferred = [], []

    def record(rel, owner, call, kind, target, offset):
        expansion, macro = expanded(target, rel, offset)
        if macro and CAPTURE.search(expansion):
            for invocation_rel, invocation_offset, text in invoked_with_strict(macro):
                findings.append((invocation_rel, owner_at(invocation_rel, invocation_offset, f"{macro}!")[0], f"{call} via {text}", "decode", kind))
        if mentions_target(target, rel, offset):
            findings.append((rel, owner, call, "decode", kind))
        elif not target:
            inferred.append((rel, owner, call))

    helpers, definitions = generic_raw_helpers(files, resolver, aliases)
    helper_paths.update(
        strict.module(scope) + (name,)
        for rel, offset, name, _ in definitions for scope in strict.scopes(rel, offset)
    )
    associated_helpers.update(name for _, _, name, associated in definitions if associated)
    for scope, imports in strict.imports.items():
        crate_helpers = helpers.get(scope[0], {})
        for alias, path in imports.items():
            if path[-1] in crate_helpers and alias not in crate_helpers:
                crate_helpers[alias] = crate_helpers[path[-1]]

    axum_names = {"axum", ""} | {
        alias for imports in strict.imports.values() for alias, path in imports.items()
        if path[0] == "axum" and (len(path) < 3 or path[-1] in AXUM_EXTRACTORS)
    }

    local_extractors = {}
    for rel, code in files:
        for start, end, header in block_spans(code):
            extractor = re.match(r"impl\s*<[^{]*?>\s*(?:[\w:]*::)?FromRequest(?:Parts)?\s*<[^{]*?>\s*for\s+(\w+)\s*<", header)
            if extractor and any(True for _ in decode_sites(code[start:end], 0, helpers.get(crate_of(rel), {}), resolver(rel, start), aliases)):
                local_extractors.setdefault(crate_of(rel), set()).add(extractor.group(1))

    def extractors(text, rel, offset, pattern):
        """(start, opening `<`) for each extractor type applied in `text`."""
        found = {match.start(): match.end() - 1 for match in pattern.finditer(text)}
        for match in TYPE_APPLICATION.finditer(text):
            segments = [part.strip() for part in match.group(1).split("::")]
            if segments[-1] in local_extractors.get(crate_of(rel), set()):
                found.setdefault(match.start(), match.end() - 1)
                continue
            if not ({segments[0], segments[-1]} & axum_names):
                continue
            if match.start() not in found and any(
                key[:2] == (":external", "axum") and key[-1] in AXUM_EXTRACTORS
                for key in resolve_path(match.group(1), rel, offset)
            ):
                found[match.start()] = match.end() - 1
        return sorted(found.items())

    for rel, code in files:
        crate_helpers = helpers.get(crate_of(rel), {})
        rows = _contracts.functions(code)
        for row in rows:
            owner = row[0]
            fn_code = _contracts.owner_code(code, row)
            arguments_start = fn_code.find("(")
            arguments = fn_code[arguments_start:_contracts.closing(fn_code, arguments_start)]
            for start, opening in extractors(arguments, rel, row[1], EXTRACTOR):
                target, _ = angle_argument(arguments, opening)
                if mentions_target(target, rel, row[1]):
                    findings.append((rel, owner, normalized(arguments[start:opening + 1] + target + ">"), "extractor", "text"))
            body_start = row[2] - row[1]
            for match in FROM_REQUEST.finditer(fn_code, body_start):
                statement_start = max(fn_code.rfind(c, 0, match.start()) for c in ";{}") + 1
                statement = fn_code[statement_start:match.start()] + " " + let_annotation(fn_code, match.start())
                for _, opening in extractors(statement, rel, row[1] + match.start(), BODY_EXTRACTOR):
                    target, _ = angle_argument(statement, opening)
                    if mentions_target(target, rel, row[1] + match.start()):
                        findings.append((rel, owner, call_text(fn_code, match.start()), "extractor", "text"))
                        break
            if owner.split("#")[0] == "deserialize" and in_deserialize_impl(code, row[1]):
                continue
            returns = return_type(fn_code)
            self_type = implementing_type(code, row[1])
            parameters = generic_parameters(fn_code)
            for offset, explicit, kind in decode_sites(fn_code, body_start, crate_helpers, resolver(rel, row[1]), aliases):
                target = targets(fn_code, offset, explicit, returns)
                if self_type:
                    target = re.sub(r"\bSelf\b", self_type, target)
                if not target and placeholder_strict(explicit, lambda text: mentions_target(text, rel, row[1] + offset)):
                    target = PLACEHOLDER.sub("()", explicit)
                if not target and parameters or set(IDENTIFIER.findall(target)) & impl_parameters(code, row[1]) - {"Self"}:
                    continue
                record(rel, owner, call_text(fn_code, offset), kind, target, row[1] + offset)
        for item in STATIC_ITEM.finditer(code):
            if any(row[1] < item.start() < row[3] for row in rows):
                continue
            initializer = code[item.start():statement_end(code, item.end())]
            for offset, explicit, kind in decode_sites(initializer, item.end() - item.start(), crate_helpers, resolver(rel, item.start()), aliases):
                target = explicit if explicit is not None and not PLACEHOLDER.search(explicit) else item.group(2) if explicit is None else f"({explicit}, {item.group(2)})"
                record(rel, f"static {item.group(1)}", call_text(initializer, offset), kind, target, item.start() + offset)
        for start, end, _, name, body_start in templates[rel]:
            body = list(code[body_start:end - 1])
            for row in rows:
                if body_start <= row[1] < end:
                    body[row[1] - body_start:row[3] - body_start] = " " * (row[3] - row[1])
            body = "".join(body)
            for offset, explicit, kind in decode_sites(body, 0, crate_helpers, resolver(rel, body_start), aliases):
                call = call_text(body, offset)
                target = targets_in_template(body, offset, explicit)
                if target:
                    record(rel, f"macro {name}!", call, kind, target, body_start + offset)
                    continue
                for invocation_rel, invocation_offset, _, text in invocations[name]:
                    invocation_owner, row = owner_at(invocation_rel, invocation_offset, f"{name}!")
                    context = ""
                    if row:
                        fn_code = _contracts.owner_code(by_path[invocation_rel], row)
                        context = contextual_target(fn_code, invocation_offset - row[1], return_type(fn_code))
                        self_type = implementing_type(by_path[invocation_rel], row[1])
                        if self_type:
                            context = re.sub(r"\bSelf\b", self_type, context)
                    if context and explicit is not None:
                        context = f"({explicit}, {context})"
                    record(invocation_rel, invocation_owner, f"{call} via {text}", kind, context, invocation_offset)
    errors = [f"{rel}: unresolved type path {path}" for rel, path in sorted(strict.unresolved)]
    remaining = list(findings)
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
    used = set()
    for rel, owner, call in sorted(set(inferred)):
        if ALLOWED_INFERRED.get((rel, owner, call), "").strip():
            used.add((rel, owner, call))
        else:
            errors.append(f"{rel}::{owner}: inferred decode target {call}")
    errors.extend(
        f"{rel}::{owner}: inferred decode allowance {call} matched no call"
        for rel, owner, call in sorted(set(ALLOWED_INFERRED) - used)
        if ALLOWED_INFERRED[(rel, owner, call)].strip()
    )
    return errors


def targets_in_template(body: str, offset: int, explicit) -> str:
    """A decode target inside a `macro_rules!` template outside any function.

    Without an explicit or annotated type the target comes from each expansion
    site, so this returns an empty string."""
    if explicit is not None and not PLACEHOLDER.search(explicit):
        return explicit
    annotation = let_annotation(body, offset) or assigned_annotation(body, offset)
    if explicit is not None:
        return f"({explicit}, {annotation})" if annotation else ""
    return annotation


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
    "inferred local not returned": ("fn f(t: &str) -> Result<ChioReceipt, E> { let other = serde_json::from_str(t)?; use_it(other); build() }", 1),
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
    global ALLOWED_INFERRED
    allowed, ALLOWED_INFERRED = ALLOWED_INFERRED, {}
    try:
        fixture_self_test()
    finally:
        ALLOWED_INFERRED = allowed


def fixture_self_test() -> None:
    def write_fixture(path, text, **kwargs):
        declarations = "type Other = (); type E = (); type R = (); type Value = serde_json::Value; use std::sync::LazyLock;\n"
        path.write_text(declarations + text, **kwargs)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "crates/demo/src/lib.rs"
        source.parent.mkdir(parents=True)
        other = root / "crates/other/src/lib.rs"
        other.parent.mkdir(parents=True, exist_ok=True)
        other.write_text("pub struct Thing {}\n", encoding="utf-8")
        for label, (code, expected) in FIXTURES.items():
            write_fixture(source, code + "\n", encoding="utf-8")
            found = len(scan(root))
            if found != expected + len(ALLOWED):
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {found - len(ALLOWED)}")
        for label, name, expected in (("included fragment", "part.inc", 1), ("test fragment", "part_tests.inc", 0)):
            fragment = root / "crates/demo/src" / name
            write_fixture(fragment, "fn f(t: &str) { serde_json::from_str::<ChioReceipt>(t); }\n", encoding="utf-8")
            write_fixture(source, "\n", encoding="utf-8")
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
        write_fixture(source, "\n", encoding="utf-8")
        signed = "UntrustedJsonText::new(raw).decode_signed()"
        for label, body, producer, expected in (
            ("approved call", "let receipt: ChioReceipt = serde_json::from_value(value)?;", signed, 0),
            ("raw text at the approved path", "let receipt: ChioReceipt = serde_json::from_str(raw)?;", signed, 2),
            ("producer regressed to a raw decode", "let receipt: ChioReceipt = serde_json::from_value(value)?;", "serde_json::from_str(raw)", 1),
            ("producer with a raw decode beside decode_signed", "let receipt: ChioReceipt = serde_json::from_value(value)?;", f"{{ let _: Value = serde_json::from_str(raw)?; {signed} }}", 1),
        ):
            write_fixture(target,
                f"fn decode_stored_json(raw: &str) -> Result<Value, E> {{ {producer} }}\n"
                f"fn {allowed['owner']}(raw: &str) -> Result<ChioReceipt, E> {{\n"
                f"    let value = decode_stored_json(raw)?;\n    {body}\n    Ok(receipt)\n}}\n",
                encoding="utf-8",
            )
            found = len(scan(root)) - (len(ALLOWED) - 1)
            if found != expected:
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {found}")
        write_fixture(target, "\n", encoding="utf-8")
        other = root / "crates/other/src/lib.rs"
        other.parent.mkdir(parents=True, exist_ok=True)
        other.write_text("fn decode<T: DeserializeOwned>(t: &str) -> Result<T, E> { serde_json::from_str(t) }\n", encoding="utf-8")
        for label, code, expected in (
            ("same-named helper in another crate", "fn f(t: &str) -> Result<ChioReceipt, E> { crate::input::decode(t) }", 0),
            ("helper in the same crate", "fn decode<T: DeserializeOwned>(t: &str) -> Result<T, E> { serde_json::from_str(t) }\nfn f(t: &str) -> Result<ChioReceipt, E> { crate::input::decode(t) }", 1),
        ):
            write_fixture(source, code + "\n", encoding="utf-8")
            found = len(scan(root)) - len(ALLOWED)
            if found != expected:
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {found}")
        other.write_text("\n", encoding="utf-8")
        write_fixture(source, "\n", encoding="utf-8")
        member = next(entry for entry in ALLOWED if entry["owner"] == "extract_financial_metadata")
        target = root / member["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        for label, read, expected in (
            ("receipt member", "receipt.metadata.as_ref()", 0),
            ("receipt member read from elsewhere", "other.as_ref()", 1),
        ):
            write_fixture(target,
                f"fn {member['owner']}(receipt: &ChioReceipt, other: Option<Value>) {{ let value = {read}; "
                f"let projection = {member['call']}; }}\n",
                encoding="utf-8",
            )
            matched = [error for error in scan(root) if member["owner"] in error]
            if len(matched) != expected:
                raise SystemExit(f"self-test {label}: expected {expected} findings, got {matched}")
        write_fixture(target, "\n", encoding="utf-8")
        helper_entry = next(entry for entry in ALLOWED if entry["owner"] == "verify_backfill_receipts")
        target = root / helper_entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        for label, reader, expected in (
            ("approved Value helper", "serde_json::from_value(value.clone())", 0),
            ("approved helper reading text", "serde_json::from_str(value.as_str())", 2),
        ):
            write_fixture(target,
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
    tests = _load("receipt_type_resolution_tests", ROOT / "scripts/test-committed-receipt-type-resolution.py")
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output).run(unittest.defaultTestLoader.loadTestsFromModule(tests))
    if not result.wasSuccessful():
        raise SystemExit(output.getvalue())
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
