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
use MetadataForm::{Commitments, Plaintext, Projection, Removed};
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

/// The form a registered key takes in a committed receipt. `disclosure` states
/// what the key's writer emits today; a key is committed-safe only once its
/// writer emits this form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataForm {
    /// The whole value stays plaintext: a closed code, an entropy-backed or
    /// keyed id, or a time.
    Plaintext,
    /// A typed projection: fields a named reader needs stay plaintext, and
    /// every other field is a salted commitment.
    Projection,
    /// Every member is a salted commitment.
    Commitments,
    /// The key leaves signed metadata.
    Removed,
}

/// One registered top-level metadata key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataKeySpec {
    pub key: &'static str,
    pub origin: MetadataKeyOrigin,
    pub disclosure: MetadataDisclosure,
    pub form: MetadataForm,
    /// Schema identifier the block pins, when it has one.
    pub schema: Option<&'static str>,
    /// What the block carries and the field audit behind `disclosure`.
    pub reason: &'static str,
}

const fn spec(
    key: &'static str,
    origin: MetadataKeyOrigin,
    disclosure: MetadataDisclosure,
    form: MetadataForm,
    schema: Option<&'static str>,
    reason: &'static str,
) -> MetadataKeySpec {
    MetadataKeySpec {
        key,
        origin,
        disclosure,
        form,
        schema,
        reason,
    }
}

/// Every registered top-level receipt-metadata key. Keys are unique.
///
/// `active_defense_body`, `response_simulation_report`,
/// `security_event_projection` and the cage and wall `schema` key are not
/// registered: each carries raw tenant, plan or subject identifiers, and is
/// refused until a committed-safe projection replaces it.
pub const RECEIPT_METADATA_KEYS: &[MetadataKeySpec] = &[
    spec(
        "admission_operation",
        ChioInternal,
        Unsafe,
        Projection,
        Some("chio.admission-receipt.v1"),
        "Durable admission projection: kernel-minted operation id, state and fences. request_binding_hash is an unsalted digest over the immutable request hash, which covers the tool-call arguments, and the unsalted parameter hash. Target form: operation_id, projected_state and the other Chio state stay plaintext for the process host, call evidence, nonce evidence and completed-result readers; request_binding_hash becomes the commitment metadata.admission_operation.request_binding, and request_namespace_digest carries the receipt_context namespace commitment.",
    ),
    spec(
        "attribution",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Capability subject and issuer keys, delegation depth and grant index. Under enterprise attribution subject_key is an unsalted SHA-256 over the provider scope and the canonical principal, which confirms a guessed principal. Target form: real public keys stay plaintext; a derived subject_key becomes keyed output under the enterprise-subject purpose subkey.",
    ),
    spec(
        "chio_manifest_security_v1",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Registry-validated entrypoint evidence naming the server and tool. No production reader. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "protocol_admission",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Security admission operation id and state. last_error is free text that can quote request values. No production reader. Target form: last_error and last_error_code are salted commitments, because no reader needs them in plaintext.",
    ),
    spec(
        BUDGET_AUTHORITY_METADATA_KEY,
        ChioInternal,
        CommittedSafe,
        Projection,
        None,
        "Budget-authority lineage: kernel-minted hold, event, nonce and capability ids, grant index and authorized and terminal amounts. Read by the settlement observer and the authoritative-spend projection.",
    ),
    spec(
        "budget_denial_authority",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Budget-authority lineage for a budget denial. No production writer. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        FINANCIAL_METADATA_KEY,
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Financial attribution and settlement. cost_breakdown copies the tool server's reported cost breakdown verbatim, a tool result value. Target form: the Charged or RetainedAmbiguous settlement and accounting projection stays plaintext for the settlement observer and ledger, credit, channel, claim-log, SIEM and finding readers; the tool-reported breakdown becomes the commitment metadata.financial.reported_cost_breakdown.",
    ),
    spec(
        GOVERNED_TRANSACTION_METADATA_KEY,
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Governed-transaction intent and approval. Carries caller-authored purpose text, the shared payment token id, the unsalted intent hash and caller-asserted call-chain context. Target form: server_id, tool_name, the approval flag, approver key and approval artifact digest, the runtime-assurance closed codes and the economic accounting stay plaintext for the IOU, participant-evidence, claim-log and underwriting readers; purpose, the payment token, the intent hash, every call-chain member but evidence_class, metered billing and the other caller values become per-field commitments.",
    ),
    spec(
        "caller_delivery",
        ChioInternal,
        Unsafe,
        Projection,
        Some("chio.authenticated-caller-observation.v1"),
        "Authenticated caller observation; no raw output. authorization_digest, the executor id, key and epoch, claim_id and the two execution times are executor or operator values that no reader needs in plaintext. Read by the kernel's terminal return-context conflict check. Target form: schema and report_digest, a digest over the executor-signed report, stay plaintext for that check; authorization_digest, executor, claim_id and both execution times become commitments.",
    ),
    spec(
        "protocol_refusal",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Session protocol refusal event. request_digest.sha256 is an unsalted digest of the original wire request, and method_sha256 and target_sha256 are unsalted digests of low-entropy values. session_id is plaintext by design: it is the session-certificate join key and links receipts within one session only; it is agent-minted and may be low-entropy, so it is not secret. Target form: session_id and the refusal code stay plaintext for the session-certificate and compliance readers; request_digest.sha256, method_sha256 and target_sha256 become commitments.",
    ),
    spec(
        "chio_runtime",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Runtime admission and kernel runtime evidence. The admission bundle's admission, workflow, grant and lease ids are deterministic over plan, capability and caller values, its trust and verification-context digests are unsalted over provisioned artifacts, and the route, payment-unwind and treaty members carry plan, rail and treaty values. The only key a runtime-admission hook writes. Target form: accepted, identity_disposition, retryable_after_resume, post_effect_fault, operation_owned_replay.reference and verified_swarm_request_binding.capability_sha256 stay plaintext for the runtime-admission hook, refusal replay, the stop contract (8.3) and the CLI call, nonce, custody and run-evidence verifiers; the bundle ids and digests, the reserved and retained lease ids, the route metadata, the other request-binding members, the payment-unwind ids, the treaty DSSE references and the unread flags and dispositions become commitments.",
    ),
    spec(
        super::SESSION_ANCHOR_METADATA_KEY,
        ChioInternal,
        CommittedSafe,
        Projection,
        Some(super::RECEIPT_SESSION_ANCHOR_SCHEMA),
        "The receipt's own session anchor as a domain-separated SHA-256 commitment over the anchor id and hash. The raw anchor hash is an unsalted digest of the session auth context, and the receipt itself does not carry it. Every receipt signed under one session anchor carries the same commitment, which links them. Read by the persisted-parent continuation verifier.",
    ),
    spec(
        "receipt_context",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Request id, request namespace digest and evaluation id. The request id can be caller-chosen, and the ACP-Client form adds authorization_resource taken from the tool call. session_id is plaintext by design: it is the session-certificate join key and links receipts within one session only; it is agent-minted and may be low-entropy, so it is not secret. Target form: kernel-issued request, evaluation and session ids stay plaintext for the admission projection, call-evidence, run-evidence, response-verify, cross-protocol, trace-validate and ACP-Client readers; a caller-chosen request id, the request namespace digest and authorization_resource become commitments.",
    ),
    spec(
        "governed_transaction_diagnostics",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Governed-transaction diagnostics. Carries the caller-asserted call chain and its lineage references verbatim. Target form: each asserted call-chain and lineage member carries the commitment of the governed_transaction call-chain member it copies, read by the operator reports from the values rows.",
    ),
    spec(
        "model_metadata",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Model id, provider, safety tier and provenance class the request declared: caller values. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        CHANNEL_METADATA_KEY,
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Streamed-output channel accounting. No production writer. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        DELIVERY_CONTRACT_METADATA_KEY,
        ChioInternal,
        Unsafe,
        Projection,
        Some(DELIVERY_CONTRACT_SCHEMA),
        "Output-digest delivery evidence. observed_digest is the unsalted SHA-256 of the delivered output. Target form: the delivery result stays plaintext for its readers and observed_digest becomes a commitment.",
    ),
    spec(
        FINDING_DELIVERY_METADATA_KEY,
        ChioInternal,
        CommittedSafe,
        Projection,
        Some(FINDING_DELIVERY_SCHEMA),
        "Purchased-finding delivery overlay: public finding and listing ids, kernel comparison results and Chio-minted reservation and payment operation ids. Read by open-market recovery and the remote admission projection.",
    ),
    spec(
        FINDING_RECOVERY_METADATA_KEY,
        ChioInternal,
        CommittedSafe,
        Projection,
        Some(FINDING_RECOVERY_SCHEMA),
        "Finding-recovery binding: recovery and finding ids, the original capability and delivery receipt ids and the purchase key. Read by the kernel's terminal and recovery-gate paths.",
    ),
    spec(
        "finding_purchase_replay_snapshot",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Admission-verified purchase binding and status proof frozen for terminal replay. finding_id is an unsalted digest of the provider's finding body, payload_sha256 is the unsalted payload digest, and listing_id, the payload media type, the expected status feed id, the accepted price and the feed, epoch, root and operator-configuration members of the status proof are provider, configuration or low-entropy values. Read by the kernel's purchase gate on replay. Target form: schema, payer_key_hex, reservation_id, purchase_intent_id, authoritative_payment_operation_id, the accepted-bid and venue-admission envelope digests, status_epoch_artifact_sha256, proof_sha256 and non_inclusion_checked_at stay plaintext; finding_id, listing_id, payload_sha256, payload_media_type, expected_status_feed_id, accepted_price and the other status-proof members become commitments.",
    ),
    spec(
        "finding_recovery_replay_snapshot",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Durable recovery binding and the live-status floor admitted before dispatch. original_capability_id is the issuer's token id, and finding_id, listing_id, payload_sha256, expected_status_feed_id and the status-proof members are as in finding_purchase_replay_snapshot. Read by the kernel's recovery gate and terminal status revalidation. Target form: schema, request_binding_sha256, recovery_id, purchase_key, original_delivery_receipt_id, original_subject_key_hex, status_epoch_artifact_sha256, proof_sha256 and non_inclusion_checked_at stay plaintext; original_capability_id, finding_id, listing_id, payload_sha256, expected_status_feed_id and the other status-proof members become commitments.",
    ),
    spec(
        DECISION_MODEL_WITNESS_METADATA_KEY,
        ChioInternal,
        CommittedSafe,
        Projection,
        Some(DECISION_MODEL_WITNESS_SCHEMA),
        "Decision-model witness: model card and artifact digests, outcome (the verdict class), evaluated-or-fallback tag, closed fallback reason and the model-constant work count. No argument, result, atom or rule selection, or margin. Read by the kernel's replay path and the offline verifier.",
    ),
    spec(
        "findingDenial",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Finding-market denial family code. No production reader. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "stream",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Streamed-output chunk counts and byte totals. chunk_hashes are unsalted SHA-256 digests of each output chunk. Target form: chunks_received and total_bytes stay plaintext for compacted replay, the receipt signing path and the CLI response verifier; chunk_hashes and chunks_expected are removed, and the content commitment covers the stream.",
    ),
    spec(
        "threshold_approval",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Threshold approval marker for a pending call. proposal_id, proposal_hash and proposal_deadline have no reader that needs them in plaintext; the full proposal is the response output, covered by the content commitment. Read by the CLI response verifier (state). Target form: state stays plaintext; proposal_id, proposal_hash and proposal_deadline become commitments.",
    ),
    spec(
        "memory_provenance",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Memory write provenance. store and key are taken from the tool-call arguments. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "post_invocation",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Post-invocation guard results. escalations carry hook text that can describe the output. Target form: sanitized stays plaintext for the arena runtime and the conformance driver; escalations becomes the commitment metadata.post_invocation.escalations.",
    ),
    spec(
        "execution_nonce",
        ChioInternal,
        CommittedSafe,
        Projection,
        None,
        "Execution-nonce stage and cleanup flags on a preflight denial: closed codes read by the CLI response verifier.",
    ),
    spec(
        "chio_kernel",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Kernel rejection code and client denial code on a refusal receipt. Durable refusal replay reads client_denial_code, a closed denial code; rejection_code has no production reader. Target form: client_denial_code stays plaintext for durable refusal replay; rejection_code becomes a salted commitment.",
    ),
    spec(
        "runtime_admission",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "The kernel's runtime-admission refusal record: hook name, acceptance flag and failure code. Never accepted from a hook. No production reader. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "active_response_terminal_evidence",
        ChioInternal,
        CommittedSafe,
        Projection,
        None,
        "Executor receipt id, hash and key behind an active-response terminal receipt, read back by the kernel's admission terminal receipt check.",
    ),
    spec(
        "chio_http_receipt_v1",
        ChioInternal,
        Unsafe,
        Removed,
        None,
        "Embedded HTTP receipt written by the HTTP receipt projection, with raw request and session ids and nested metadata. Target form: removed with the embedded HTTP receipt.",
    ),
    spec(
        CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY,
        ChioInternal,
        Unsafe,
        Plaintext,
        None,
        "The pre-binding receipt id the signing path folds into the signed body of every receipt. The ACP-Client producer embeds an unsalted content hash in it. Target form: plaintext for the terminal, compacted-replay, settlement-prepare and web3 settlement readers, which require it to equal the governed receipt id; every producer mints it from the Rng seam with no content hash.",
    ),
    spec(
        CHIO_RECEIPT_ORIGINAL_METADATA_KEY,
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Written by the signing path to wrap a non-object metadata value verbatim. Target form: the wrapped value is a salted commitment, because it is a caller value with no reader.",
    ),
    spec(
        "finding_pool_mutation",
        ChioInternal,
        Unsafe,
        Removed,
        None,
        "Finding-pool ledger mutation evidence. Duplicates the action parameters. Target form: removed; the parameter commitment covers the mutation.",
    ),
    spec(
        "session_report",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Session report event. operation_sha256 is an unsalted digest of the whole operation, arguments included. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "prior_metadata",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Written by a kernel rejection record to wrap a non-object metadata value verbatim. Target form: the wrapped value is a salted commitment, because it is a caller value with no reader.",
    ),
    spec(
        "lineageReferences",
        ChioInternal,
        Unsafe,
        Removed,
        None,
        "No production writer at top level; the kernel's lineage references are nested in governed_transaction_diagnostics. Reserved so that no caller value under this key stands in for kernel lineage. Target form: removed; no reader takes lineage from this key.",
    ),
    spec(
        "chio_http_status_scope",
        ChioInternal,
        CommittedSafe,
        Plaintext,
        None,
        "HTTP receipt status scope, decision or final: a closed code read by the HTTP receipt projection.",
    ),
    spec(
        "chio_decision_receipt_id",
        ChioInternal,
        CommittedSafe,
        Plaintext,
        None,
        "Receipt id of the linked HTTP decision receipt, read by the API protection proxy.",
    ),
    spec(
        "chio_kernel_receipt_id",
        ChioInternal,
        CommittedSafe,
        Plaintext,
        None,
        "Receipt id of the linked kernel receipt, read by the HTTP authority.",
    ),
    spec(
        "otel",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Span name, ids and attributes copied from an exported span, which can carry tool arguments and results. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "correlation",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Source Chio receipt id of an exported span. No production reader. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "keyEnterpriseReceipt",
        ChioInternal,
        Unsafe,
        Removed,
        None,
        "Key-transition event, transaction and operator key ids. No production reader. Target form: removed; the content commitment covers the key enterprise receipt.",
    ),
    spec(
        "active_defense_evidence_id",
        ChioInternal,
        Unsafe,
        Plaintext,
        None,
        "Unsalted domain hash over the raw tenant id and plan identifiers. Target form: keyed output under the tenant index key set.",
    ),
    spec(
        "occurred_at_unix_ms",
        ChioInternal,
        CommittedSafe,
        Plaintext,
        None,
        "Active-defense event time, bound by the lineage ingest and the native evidence reader.",
    ),
    spec(
        "response_simulation_evidence_id",
        ChioInternal,
        Unsafe,
        Plaintext,
        None,
        "Unsalted domain hash over the raw tenant and action ids. Target form: keyed output under the tenant index key set.",
    ),
    spec(
        "scimLifecycle",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "SCIM provider, user ids, user names, principal, subject key and entitlements. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "mercury",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Raw business identifiers such as account and desk. Target form: closed codes, flags and times stay plaintext for the proof package; business ids and every other member become per-field commitments, carried with salt-only openings in the proof package.",
    ),
    spec(
        "authorizationContext",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Wall request actor and requested domains. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "guardOutcome",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Wall guard outcome text. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "deniedAccessRecord",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Wall record of the denied request. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "policySnapshot",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Wall policy identity snapshot. No production reader. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "acp",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "ACP-Client session and tool-call ids. authorizationResource is taken from the tool call. sessionId is plaintext by design: it is the session-certificate join key and links receipts within one session only; it is agent-minted and may be low-entropy, so it is not secret. Target form: sessionId stays plaintext for the session-certificate and compliance readers; authorizationResource and authorizationParameterHash share their receipt_context commitments, and every other member is a commitment.",
    ),
    spec(
        "agent_web_receipt_ref",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Agent Web receipt reference read only by the proof fixture. No production writer. Target form: every member is a salted commitment, because no reader needs it in plaintext.",
    ),
    spec(
        "parent_receipt_ids",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Parent receipt ids. No production writer; only the CLI explain display reads it. Target form: salted commitments; the explain display opens them from the values rows.",
    ),
    spec(
        "batch_witness",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Batch witness reference with unaudited contents. No production writer; only the CLI explain display reads it. Target form: salted commitments; the explain display opens them from the values rows.",
    ),
    spec(
        "active_defense",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Active-defense receipt projection: closed codes and keyed or entropy-backed digests, with every raw identifier a salted commitment under metadata.active_defense. Read by the active-response coordinator, the control-plane security store, lineage ingest and the security event consumer. No production writer emits it, so it is refused.",
    ),
    spec(
        "response_simulation",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Response-simulation report projection: closed codes and keyed digests, with every raw identifier a salted commitment under metadata.response_simulation. Read by the active-response coordinator. No production writer emits it, so it is refused.",
    ),
    spec(
        "security_event",
        ChioInternal,
        Unsafe,
        Projection,
        None,
        "Security event projection: closed codes and keyed digests, with the subject a salted commitment under metadata.security_event. Read by the control-plane security event consumer. No production writer emits it, so it is refused.",
    ),
    spec(
        "cage_receipt",
        ChioInternal,
        Unsafe,
        Projection,
        Some("chio.cage.receipt-metadata.v1"),
        "Cage receipt evidence. The cage producer writes the raw cage receipt body, whose plan, descriptor-table and profile digests are unsalted over process arguments, environment and paths. Target form: the cage projection, with manifest, helper and target identity, landlock and seccomp status, exit status, attempt, stage, state and times plaintext for the cage verifier and the native launch evidence check, and the raw body and every argument-derived digest salted commitments under metadata.cage_receipt.",
    ),
    spec(
        "guard_error",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Guard error detail: the commitment metadata.guard_error.detail over the guard's error text; the signed deny reason carries only the closed code. No production writer emits it, so it is refused.",
    ),
    spec(
        "refusal",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Kernel refusal detail: the commitment metadata.refusal.detail over dynamic refusal text; the signed reason carries only the closed code. No production writer emits it, so it is refused.",
    ),
    spec(
        "cancellation",
        ChioInternal,
        Unsafe,
        Commitments,
        None,
        "Cancellation detail: the commitment metadata.cancellation.detail over host-supplied cancellation text; the signed reason carries only the closed code. No production writer emits it, so it is refused.",
    ),
    spec(
        "native_launch",
        CallerOrHook,
        Unsafe,
        Removed,
        None,
        "Cage launch receipt id and SHA-256 presented by host attribution. The kernel checks its shape and, when it holds the launch, binds it and denies a different value. Target form: removed; receipt assembly drops every caller or hook key.",
    ),
    spec(
        "provenance",
        CallerOrHook,
        Unsafe,
        Removed,
        None,
        "Caller OTel trace and span ids with an optional supply_chain object of any shape, validated by the kernel. Target form: removed; receipt assembly drops every caller or hook key.",
    ),
    spec(
        "chio_process",
        CallerOrHook,
        Unsafe,
        Removed,
        None,
        "Process supervisor ids and request_sha256, an unsalted digest of the request. The kernel validates worker_profile. Target form: removed; receipt assembly drops every caller or hook key.",
    ),
    spec(
        "route",
        CallerOrHook,
        Unsafe,
        Removed,
        None,
        "Bridge, protocol target and selected route names presented by the host, checked against the route plan by the swarm admission hook. Target form: removed; receipt assembly drops every caller or hook key.",
    ),
    spec(
        "route_selection",
        CallerOrHook,
        Unsafe,
        Removed,
        None,
        "A client-supplied route selection the MCP edge copies verbatim. Target form: removed; receipt assembly drops every caller or hook key.",
    ),
    spec(
        "source_receipt_context",
        CallerOrHook,
        Unsafe,
        Removed,
        None,
        "Copied verbatim from a source envelope. Target form: removed; receipt assembly drops every caller or hook key.",
    ),
    spec(
        "workflow_id",
        CallerOrHook,
        Unsafe,
        Removed,
        None,
        "Harness and loopback workflow id, read by the runtime admission hook. Target form: removed; receipt assembly drops every caller or hook key.",
    ),
    spec(
        "vendor_id",
        CallerOrHook,
        Unsafe,
        Removed,
        None,
        "Loopback vendor id. Target form: removed; receipt assembly drops every caller or hook key.",
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
