//! Registry of the top-level keys of a receipt's `metadata` object.
//!
//! This is the one registry of receipt-metadata keys. Each key Chio writes, or
//! admits from caller metadata, is registered once with its origin and whether
//! its value may appear in a committed receipt. The reserved set is derived
//! from it: every `ChioInternal` key is reserved, and the kernel refuses caller
//! metadata that names one. The key table in `spec/PROTOCOL.md` 6.4 renders
//! this registry row for row.

use alloc::format;

use super::{
    BUDGET_AUTHORITY_METADATA_KEY, CHANNEL_METADATA_KEY, DECISION_MODEL_WITNESS_METADATA_KEY,
    DECISION_MODEL_WITNESS_SCHEMA, DELIVERY_CONTRACT_METADATA_KEY, DELIVERY_CONTRACT_SCHEMA,
    FINANCIAL_METADATA_KEY, FINDING_DELIVERY_METADATA_KEY, FINDING_DELIVERY_SCHEMA,
    FINDING_RECOVERY_METADATA_KEY, FINDING_RECOVERY_SCHEMA, GOVERNED_TRANSACTION_METADATA_KEY,
};
use crate::error::{Error, Result};
use crate::receipt::signing::{
    CHIO_RECEIPT_ORIGINAL_METADATA_KEY, CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY,
};

use MetadataDisclosure::{CommittedSafe, Unsafe};
use MetadataKeyOrigin::{CallerOrHook, ChioInternal};

/// Who writes a registered metadata key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataKeyOrigin {
    /// Only a Chio signer writes the key into the receipt it signs. The key is
    /// reserved: the kernel refuses caller metadata that names it, and a
    /// runtime-admission hook writes no key but `chio_runtime`.
    ChioInternal,
    /// The key reaches the receipt through caller metadata, including blocks a
    /// Chio host component presents as the caller. Its value is a caller
    /// value, so it is always `Unsafe`.
    CallerOrHook,
}

/// Whether a registered key's value may appear in a committed receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataDisclosure {
    /// Carries no argument or result value and no identifier or unsalted
    /// digest that confirms one, and a named reader needs it in plaintext.
    CommittedSafe,
    /// Carries an argument, result or caller value, an identifier or unsalted
    /// digest that confirms one, or has no reader; refused in the signed
    /// metadata of a committed receipt.
    Unsafe,
}

/// One registered top-level metadata key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataKeySpec {
    pub key: &'static str,
    pub origin: MetadataKeyOrigin,
    pub disclosure: MetadataDisclosure,
    /// Schema identifier the block pins, when it has one.
    pub schema: Option<&'static str>,
    /// What the block carries and the field audit behind `disclosure`.
    pub reason: &'static str,
}

const fn spec(
    key: &'static str,
    origin: MetadataKeyOrigin,
    disclosure: MetadataDisclosure,
    schema: Option<&'static str>,
    reason: &'static str,
) -> MetadataKeySpec {
    MetadataKeySpec {
        key,
        origin,
        disclosure,
        schema,
        reason,
    }
}

/// Every registered top-level receipt-metadata key. Keys are unique.
///
/// `active_defense_body`, `response_simulation_report`,
/// `security_event_projection`, `cage_receipt` and the cage and wall `schema`
/// key are not registered: each carries raw tenant, plan, subject or process
/// identifiers or an unsalted digest over process arguments, environment and
/// paths, and is refused until a committed-safe projection replaces it.
pub const RECEIPT_METADATA_KEYS: &[MetadataKeySpec] = &[
    spec(
        "admission_operation",
        ChioInternal,
        Unsafe,
        Some("chio.admission-receipt.v1"),
        "Durable admission projection: kernel-minted operation id, state and fences. request_binding_hash is an unsalted digest over the immutable request hash, which covers the tool-call arguments, and the unsalted parameter hash.",
    ),
    spec(
        "attribution",
        ChioInternal,
        Unsafe,
        None,
        "Capability subject and issuer keys, delegation depth and grant index. Under enterprise attribution subject_key is an unsalted SHA-256 over the provider scope and the canonical principal, which confirms a guessed principal.",
    ),
    spec(
        "chio_manifest_security_v1",
        ChioInternal,
        Unsafe,
        None,
        "Registry-validated entrypoint evidence naming the server and tool. No production reader.",
    ),
    spec(
        "protocol_admission",
        ChioInternal,
        Unsafe,
        None,
        "Security admission operation id and state. last_error is free text that can quote request values. No production reader.",
    ),
    spec(
        BUDGET_AUTHORITY_METADATA_KEY,
        ChioInternal,
        CommittedSafe,
        None,
        "Budget-authority lineage: kernel-minted hold, event, nonce and capability ids, grant index and authorized and terminal amounts. Read by the settlement observer and the authoritative-spend projection.",
    ),
    spec(
        "budget_denial_authority",
        ChioInternal,
        Unsafe,
        None,
        "Budget-authority lineage for a budget denial. No production writer.",
    ),
    spec(
        FINANCIAL_METADATA_KEY,
        ChioInternal,
        Unsafe,
        None,
        "Financial attribution and settlement. cost_breakdown copies the tool server's reported cost breakdown verbatim, a tool result value.",
    ),
    spec(
        GOVERNED_TRANSACTION_METADATA_KEY,
        ChioInternal,
        Unsafe,
        None,
        "Governed-transaction intent and approval. Carries caller-authored purpose text, the shared payment token id, the unsalted intent hash and caller-asserted call-chain context.",
    ),
    spec(
        "caller_delivery",
        ChioInternal,
        CommittedSafe,
        Some("chio.authenticated-caller-observation.v1"),
        "Authenticated caller observation report and authorization digests, executor and claim identity and times; no raw output. Read by the kernel's return-context, terminal and replay paths.",
    ),
    spec(
        "protocol_refusal",
        ChioInternal,
        Unsafe,
        None,
        "Session protocol refusal event. request_digest.sha256 is an unsalted digest of the original wire request, and method_sha256 and target_sha256 are unsalted digests of low-entropy values.",
    ),
    spec(
        "chio_runtime",
        ChioInternal,
        CommittedSafe,
        None,
        "Runtime admission reservations and federation runtime evidence: Chio-minted admission, workflow, lease and governance ids, trust digests and reservation flags. The only key a runtime-admission hook writes. Read by kernel dispatch, the drop guard and the ledger audit.",
    ),
    spec(
        super::SESSION_ANCHOR_METADATA_KEY,
        ChioInternal,
        CommittedSafe,
        Some(super::RECEIPT_SESSION_ANCHOR_SCHEMA),
        "The receipt's own session anchor as a domain-separated SHA-256 commitment over the anchor id and hash. The anchor id embeds the random session id, so the commitment confirms no guessed auth context. Every receipt signed under one session anchor carries the same commitment, which links them. Read by the persisted-parent continuation verifier.",
    ),
    spec(
        "receipt_context",
        ChioInternal,
        Unsafe,
        None,
        "Request id, request namespace digest and evaluation id. The request id can be caller-chosen, and the ACP form adds authorization_resource taken from the tool call.",
    ),
    spec(
        "governed_transaction_diagnostics",
        ChioInternal,
        Unsafe,
        None,
        "Governed-transaction diagnostics. Carries the caller-asserted call chain and its lineage references verbatim.",
    ),
    spec(
        "model_metadata",
        ChioInternal,
        Unsafe,
        None,
        "Model id, provider, safety tier and provenance class the request declared: caller values.",
    ),
    spec(
        CHANNEL_METADATA_KEY,
        ChioInternal,
        Unsafe,
        None,
        "Streamed-output channel accounting. No production writer.",
    ),
    spec(
        DELIVERY_CONTRACT_METADATA_KEY,
        ChioInternal,
        Unsafe,
        Some(DELIVERY_CONTRACT_SCHEMA),
        "Output-digest delivery evidence. observed_digest is the unsalted SHA-256 of the delivered output.",
    ),
    spec(
        FINDING_DELIVERY_METADATA_KEY,
        ChioInternal,
        CommittedSafe,
        Some(FINDING_DELIVERY_SCHEMA),
        "Purchased-finding delivery overlay: public finding and listing ids, kernel comparison results and Chio-minted reservation and payment operation ids. Read by open-market recovery and the remote admission projection.",
    ),
    spec(
        FINDING_RECOVERY_METADATA_KEY,
        ChioInternal,
        CommittedSafe,
        Some(FINDING_RECOVERY_SCHEMA),
        "Finding-recovery binding: recovery and finding ids, the original capability and delivery receipt ids and the purchase key. Read by the kernel's terminal and recovery-gate paths.",
    ),
    spec(
        "finding_purchase_replay_snapshot",
        ChioInternal,
        CommittedSafe,
        None,
        "Admission-verified purchase binding and status proof frozen for terminal replay. Read by the kernel's purchase gate and replay paths.",
    ),
    spec(
        "finding_recovery_replay_snapshot",
        ChioInternal,
        CommittedSafe,
        None,
        "Durable recovery binding and the live-status floor admitted before dispatch. Read by the kernel's recovery gate and replay paths.",
    ),
    spec(
        DECISION_MODEL_WITNESS_METADATA_KEY,
        ChioInternal,
        CommittedSafe,
        Some(DECISION_MODEL_WITNESS_SCHEMA),
        "Decision-model witness: model card and artifact digests, outcome (the verdict class), evaluated-or-fallback tag, closed fallback reason and the model-constant work count. No argument, result, atom or rule selection, or margin. Read by the kernel's replay path and the offline verifier.",
    ),
    spec(
        "findingDenial",
        ChioInternal,
        Unsafe,
        None,
        "Finding-market denial family code. No production reader.",
    ),
    spec(
        "stream",
        ChioInternal,
        Unsafe,
        None,
        "Streamed-output chunk counts and byte totals. chunk_hashes are unsalted SHA-256 digests of each output chunk.",
    ),
    spec(
        "threshold_approval",
        ChioInternal,
        CommittedSafe,
        None,
        "Threshold approval proposal id and hash, deadline and state for a pending call. The CLI response verifier reads the state.",
    ),
    spec(
        "memory_provenance",
        ChioInternal,
        Unsafe,
        None,
        "Memory write provenance. store and key are taken from the tool-call arguments.",
    ),
    spec(
        "post_invocation",
        ChioInternal,
        Unsafe,
        None,
        "Post-invocation guard results. escalations carry hook text that can describe the output.",
    ),
    spec(
        "execution_nonce",
        ChioInternal,
        CommittedSafe,
        None,
        "Execution-nonce stage and cleanup flags on a preflight denial: closed codes read by the CLI response verifier.",
    ),
    spec(
        "chio_kernel",
        ChioInternal,
        Unsafe,
        None,
        "Kernel rejection code on a refusal receipt. No production reader.",
    ),
    spec(
        "runtime_admission",
        ChioInternal,
        Unsafe,
        None,
        "The kernel's runtime-admission refusal record: hook name, acceptance flag and failure code. Never accepted from a hook. No production reader.",
    ),
    spec(
        "active_response_terminal_evidence",
        ChioInternal,
        CommittedSafe,
        None,
        "Executor receipt id, hash and key behind an active-response terminal receipt, read back by the kernel's admission terminal receipt check.",
    ),
    spec(
        "chio_http_receipt_v1",
        ChioInternal,
        Unsafe,
        None,
        "Embedded HTTP receipt written by the HTTP receipt projection, with raw request and session ids and nested metadata.",
    ),
    spec(
        CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY,
        ChioInternal,
        Unsafe,
        None,
        "The pre-binding receipt id the signing path folds into the signed body of every receipt. The ACP producer embeds an unsalted content hash in it.",
    ),
    spec(
        CHIO_RECEIPT_ORIGINAL_METADATA_KEY,
        ChioInternal,
        Unsafe,
        None,
        "Written by the signing path to wrap a non-object metadata value verbatim.",
    ),
    spec(
        "finding_pool_mutation",
        ChioInternal,
        Unsafe,
        None,
        "Finding-pool ledger mutation evidence. Duplicates the action parameters.",
    ),
    spec(
        "session_report",
        ChioInternal,
        Unsafe,
        None,
        "Session report event. operation_sha256 is an unsalted digest of the whole operation, arguments included.",
    ),
    spec(
        "prior_metadata",
        ChioInternal,
        Unsafe,
        None,
        "Written by a kernel rejection record to wrap a non-object metadata value verbatim.",
    ),
    spec(
        "lineageReferences",
        ChioInternal,
        Unsafe,
        None,
        "No production writer at top level; the kernel's lineage references are nested in governed_transaction_diagnostics. Reserved so that no caller value under this key stands in for kernel lineage.",
    ),
    spec(
        "chio_http_status_scope",
        ChioInternal,
        CommittedSafe,
        None,
        "HTTP receipt status scope, decision or final: a closed code read by the HTTP receipt projection.",
    ),
    spec(
        "chio_decision_receipt_id",
        ChioInternal,
        CommittedSafe,
        None,
        "Receipt id of the linked HTTP decision receipt, read by the API protection proxy.",
    ),
    spec(
        "chio_kernel_receipt_id",
        ChioInternal,
        CommittedSafe,
        None,
        "Receipt id of the linked kernel receipt, read by the HTTP authority.",
    ),
    spec(
        "otel",
        ChioInternal,
        Unsafe,
        None,
        "Span name, ids and attributes copied from an exported span, which can carry tool arguments and results.",
    ),
    spec(
        "correlation",
        ChioInternal,
        Unsafe,
        None,
        "Source Chio receipt id of an exported span. No production reader.",
    ),
    spec(
        "keyEnterpriseReceipt",
        ChioInternal,
        Unsafe,
        None,
        "Key-transition event, transaction and operator key ids. No production reader.",
    ),
    spec(
        "active_defense_evidence_id",
        ChioInternal,
        Unsafe,
        None,
        "Unsalted domain hash over the raw tenant id and plan identifiers.",
    ),
    spec(
        "occurred_at_unix_ms",
        ChioInternal,
        CommittedSafe,
        None,
        "Active-defense event time, bound by the lineage ingest and the native evidence reader.",
    ),
    spec(
        "response_simulation_evidence_id",
        ChioInternal,
        Unsafe,
        None,
        "Unsalted domain hash over the raw tenant and action ids.",
    ),
    spec(
        "scimLifecycle",
        ChioInternal,
        Unsafe,
        None,
        "SCIM provider, user ids, user names, principal, subject key and entitlements.",
    ),
    spec(
        "mercury",
        ChioInternal,
        Unsafe,
        None,
        "Raw business identifiers such as account and desk.",
    ),
    spec(
        "authorizationContext",
        ChioInternal,
        Unsafe,
        None,
        "Wall request actor and requested domains.",
    ),
    spec(
        "guardOutcome",
        ChioInternal,
        Unsafe,
        None,
        "Wall guard outcome text.",
    ),
    spec(
        "deniedAccessRecord",
        ChioInternal,
        Unsafe,
        None,
        "Wall record of the denied request.",
    ),
    spec(
        "policySnapshot",
        ChioInternal,
        Unsafe,
        None,
        "Wall policy identity snapshot. No production reader.",
    ),
    spec(
        "acp",
        ChioInternal,
        Unsafe,
        None,
        "ACP session and tool-call ids. authorizationResource is taken from the tool call.",
    ),
    spec(
        "agent_web_receipt_ref",
        ChioInternal,
        Unsafe,
        None,
        "Agent Web receipt reference read only by the proof fixture. No production writer.",
    ),
    spec(
        "parent_receipt_ids",
        ChioInternal,
        Unsafe,
        None,
        "Parent receipt ids. No production writer; only the CLI explain display reads it.",
    ),
    spec(
        "batch_witness",
        ChioInternal,
        Unsafe,
        None,
        "Batch witness reference with unaudited contents. No production writer; only the CLI explain display reads it.",
    ),
    spec(
        "native_launch",
        CallerOrHook,
        Unsafe,
        None,
        "Cage launch receipt id and SHA-256 presented by host attribution. The kernel checks its shape and, when it holds the launch, binds it and denies a different value.",
    ),
    spec(
        "provenance",
        CallerOrHook,
        Unsafe,
        None,
        "Caller OTel trace and span ids with an optional supply_chain object of any shape, validated by the kernel.",
    ),
    spec(
        "chio_process",
        CallerOrHook,
        Unsafe,
        None,
        "Process supervisor ids and request_sha256, an unsalted digest of the request. The kernel validates worker_profile.",
    ),
    spec(
        "route",
        CallerOrHook,
        Unsafe,
        None,
        "Bridge, protocol target and selected route names presented by the host, checked against the route plan by the swarm admission hook.",
    ),
    spec(
        "route_selection",
        CallerOrHook,
        Unsafe,
        None,
        "A client-supplied route selection the MCP edge copies verbatim.",
    ),
    spec(
        "source_receipt_context",
        CallerOrHook,
        Unsafe,
        None,
        "Copied verbatim from a source envelope.",
    ),
    spec(
        "workflow_id",
        CallerOrHook,
        Unsafe,
        None,
        "Harness and loopback workflow id, read by the runtime admission hook.",
    ),
    spec(
        "vendor_id",
        CallerOrHook,
        Unsafe,
        None,
        "Loopback vendor id.",
    ),
];

/// The registration of `key`, or `None` when `key` is not registered.
#[must_use]
pub fn metadata_key_spec(key: &str) -> Option<&'static MetadataKeySpec> {
    RECEIPT_METADATA_KEYS.iter().find(|spec| spec.key == key)
}

/// The reserved keys, in registry order: every `ChioInternal` key.
pub fn reserved_receipt_metadata_keys() -> impl Iterator<Item = &'static str> {
    RECEIPT_METADATA_KEYS
        .iter()
        .filter(|spec| spec.origin == ChioInternal)
        .map(|spec| spec.key)
}

/// Accepts Chio-internal receipt metadata only when it is a JSON object whose
/// every top-level key is registered `ChioInternal` and `CommittedSafe`.
pub fn check_internal_receipt_metadata(metadata: &serde_json::Value) -> Result<()> {
    let object = metadata
        .as_object()
        .ok_or_else(|| Error::CanonicalJson("receipt metadata must be a JSON object".into()))?;
    for key in object.keys() {
        let Some(spec) = metadata_key_spec(key) else {
            return Err(Error::CanonicalJson(format!(
                "receipt metadata key {key:?} is not registered"
            )));
        };
        if spec.origin != ChioInternal {
            return Err(Error::CanonicalJson(format!(
                "receipt metadata key {key:?} is caller or hook metadata"
            )));
        }
        if spec.disclosure != CommittedSafe {
            return Err(Error::CanonicalJson(format!(
                "receipt metadata key {key:?} is not committed-safe"
            )));
        }
    }
    Ok(())
}
