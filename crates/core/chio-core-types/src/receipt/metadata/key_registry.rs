//! Registry of the top-level keys of a receipt's `metadata` object.
//!
//! Every key Chio writes into receipt metadata is registered here with the
//! writer it comes from and whether its value may appear in a committed
//! receipt. A key absent from the registry is not Chio-internal: a committed
//! receipt refuses it in Chio-internal metadata.

use alloc::format;

use crate::error::{Error, Result};

use MetadataDisclosure::{CommittedSafe, Unsafe};
use MetadataKeyOrigin::{CallerOrHook, ChioInternal};

/// Who writes a registered metadata key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataKeyOrigin {
    /// Written by a Chio signer while it builds the receipt.
    ChioInternal,
    /// Supplied through caller or hook metadata and passed through the
    /// kernel.
    CallerOrHook,
}

/// Whether a registered key's value may appear in a committed receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataDisclosure {
    /// Carries no argument or result value. `reason` records the field audit.
    CommittedSafe,
    /// Carries an argument or result value, or an identifier or digest that
    /// confirms one; refused in signed metadata.
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
    /// The field audit behind `disclosure`.
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
        CommittedSafe,
        Some("chio.admission-receipt.v1"),
        "Kernel-minted operation and request ids, versions, states and binding digests over kernel-retained rows; no argument or output value.",
    ),
    spec(
        "attribution",
        ChioInternal,
        CommittedSafe,
        None,
        "Capability subject and issuer public keys, delegation depth and grant index; all already public in the capability.",
    ),
    spec(
        "chio_manifest_security_v1",
        ChioInternal,
        CommittedSafe,
        None,
        "Registry-validated bridge security sidecar naming the server and tool; arguments are validated, never copied.",
    ),
    spec(
        "protocol_admission",
        ChioInternal,
        Unsafe,
        None,
        "Carries free-text last_error from the admission path, which can quote request values.",
    ),
    spec(
        "budget_authority",
        ChioInternal,
        CommittedSafe,
        None,
        "Kernel-minted hold, event, nonce and capability ids, grant index and authorized and terminal amounts.",
    ),
    spec(
        "budget_denial_authority",
        ChioInternal,
        CommittedSafe,
        None,
        "Reserved for kernel budget denials; written by no current producer.",
    ),
    spec(
        "financial",
        ChioInternal,
        Unsafe,
        None,
        "cost_breakdown copies the tool server's reported cost breakdown verbatim, a tool result value.",
    ),
    spec(
        "governed_transaction",
        ChioInternal,
        Unsafe,
        None,
        "Carries caller-authored purpose text, the shared payment token id and caller-asserted call-chain context.",
    ),
    spec(
        "governed_transaction_diagnostics",
        ChioInternal,
        Unsafe,
        None,
        "Carries the caller-asserted call chain verbatim.",
    ),
    spec(
        "model_metadata",
        ChioInternal,
        CommittedSafe,
        None,
        "Model id, provider, safety tier and provenance class from the request's model metadata.",
    ),
    spec(
        "channel",
        ChioInternal,
        CommittedSafe,
        None,
        "Streamed-output channel accounting; written by no current producer and reserved so callers cannot forge it.",
    ),
    spec(
        "caller_delivery",
        ChioInternal,
        CommittedSafe,
        Some("chio.authenticated-caller-observation.v1"),
        "Report and authorization digests, executor and claim identity and times; no raw output.",
    ),
    spec(
        "protocol_refusal",
        ChioInternal,
        CommittedSafe,
        None,
        "Session, agent and anchor ids, auth epoch, the SHA-256 of the request id and a refusal summary.",
    ),
    spec(
        "chio_runtime",
        ChioInternal,
        CommittedSafe,
        None,
        "Runtime admission, workflow, lease and governance ids, trust digests and reservation flags minted by Chio.",
    ),
    spec(
        "receipt_context",
        ChioInternal,
        Unsafe,
        None,
        "The kernel form holds the request id and namespace digest; the ACP producer form adds authorization_resource taken from the tool call.",
    ),
    spec(
        "delivery_contract",
        ChioInternal,
        Unsafe,
        Some("chio.delivery-contract.v1"),
        "On a match observed_digest is the unsalted SHA-256 of the delivered output.",
    ),
    spec(
        "finding_delivery",
        ChioInternal,
        CommittedSafe,
        Some("chio.finding.delivery.v1"),
        "Public finding and listing ids, kernel comparison results and Chio-minted reservation and payment operation ids.",
    ),
    spec(
        "finding_recovery",
        ChioInternal,
        CommittedSafe,
        Some("chio.finding.recovery.v1"),
        "Recovery id, finding id, original capability and delivery receipt ids and purchase key.",
    ),
    spec(
        "finding_purchase_replay_snapshot",
        ChioInternal,
        CommittedSafe,
        None,
        "Frozen kernel-verified purchase binding and status proof.",
    ),
    spec(
        "finding_recovery_replay_snapshot",
        ChioInternal,
        CommittedSafe,
        None,
        "Frozen kernel-verified recovery binding and status proof.",
    ),
    spec(
        "findingDenial",
        ChioInternal,
        CommittedSafe,
        None,
        "A closed denial code.",
    ),
    spec(
        "chio_receipt_signing_nonce",
        ChioInternal,
        Unsafe,
        None,
        "The pre-binding receipt id; the ACP producer embeds an unsalted content hash in it.",
    ),
    spec(
        "original_metadata",
        CallerOrHook,
        Unsafe,
        None,
        "Wraps a non-object caller metadata value verbatim.",
    ),
    spec(
        "prior_metadata",
        CallerOrHook,
        Unsafe,
        None,
        "Wraps non-object metadata on a rejection receipt verbatim.",
    ),
    spec(
        "stream",
        ChioInternal,
        Unsafe,
        None,
        "chunk_hashes are unsalted SHA-256 digests of each output chunk.",
    ),
    spec(
        "threshold_approval",
        ChioInternal,
        CommittedSafe,
        None,
        "Proposal id and hash, deadline and state.",
    ),
    spec(
        "memory_provenance",
        ChioInternal,
        Unsafe,
        None,
        "store and key are taken from the tool-call arguments.",
    ),
    spec(
        "post_invocation",
        ChioInternal,
        Unsafe,
        None,
        "escalations carry post-invocation hook text that can describe the output.",
    ),
    spec(
        "execution_nonce",
        ChioInternal,
        CommittedSafe,
        None,
        "Execution-nonce stage and cleanup flags.",
    ),
    spec(
        "chio_kernel",
        ChioInternal,
        CommittedSafe,
        None,
        "A closed rejection code.",
    ),
    spec(
        "runtime_admission",
        ChioInternal,
        CommittedSafe,
        None,
        "Runtime admission hook name, acceptance flag and failure code.",
    ),
    spec(
        "active_response_terminal_evidence",
        ChioInternal,
        CommittedSafe,
        None,
        "Executor receipt id, hash and key.",
    ),
    spec(
        "finding_pool_mutation",
        ChioInternal,
        Unsafe,
        None,
        "Carries finding-pool mutation parameters.",
    ),
    spec(
        "session_report",
        ChioInternal,
        Unsafe,
        None,
        "operation_sha256 is an unsalted digest of the whole operation, arguments included.",
    ),
    spec(
        "native_launch",
        ChioInternal,
        CommittedSafe,
        None,
        "Cage launch receipt id and its SHA-256; written by the kernel and by the process supervisor.",
    ),
    spec(
        "provenance",
        CallerOrHook,
        Unsafe,
        None,
        "Caller-supplied OTel ids with an optional supply_chain object of any shape.",
    ),
    spec(
        "chio_process",
        CallerOrHook,
        Unsafe,
        None,
        "Process supervisor ids and request_sha256, an unsalted digest of the request.",
    ),
    spec(
        "route",
        CallerOrHook,
        CommittedSafe,
        None,
        "Bridge, protocol target and selected route names.",
    ),
    spec(
        "route_selection",
        CallerOrHook,
        Unsafe,
        None,
        "The MCP edge copies a client-supplied object verbatim.",
    ),
    spec(
        "source_receipt_context",
        CallerOrHook,
        Unsafe,
        None,
        "Copied verbatim from a source envelope.",
    ),
    spec(
        "lineageReferences",
        CallerOrHook,
        CommittedSafe,
        None,
        "Session anchor id and hash.",
    ),
    spec(
        "workflow_id",
        CallerOrHook,
        CommittedSafe,
        None,
        "Harness and loopback workflow id.",
    ),
    spec(
        "vendor_id",
        CallerOrHook,
        CommittedSafe,
        None,
        "Loopback vendor id.",
    ),
    spec(
        "chio_http_receipt_v1",
        ChioInternal,
        Unsafe,
        None,
        "Embeds a whole HttpReceipt with raw request and session ids and nested metadata.",
    ),
    spec(
        "chio_http_status_scope",
        ChioInternal,
        CommittedSafe,
        None,
        "Decision or final status scope.",
    ),
    spec(
        "chio_decision_receipt_id",
        ChioInternal,
        CommittedSafe,
        None,
        "Linked decision receipt id.",
    ),
    spec(
        "chio_kernel_receipt_id",
        ChioInternal,
        CommittedSafe,
        None,
        "Linked kernel receipt id.",
    ),
    spec(
        "otel",
        ChioInternal,
        Unsafe,
        None,
        "Copies span attributes, which can carry tool arguments and results.",
    ),
    spec(
        "correlation",
        ChioInternal,
        CommittedSafe,
        None,
        "Source receipt, kernel and agent ids.",
    ),
    spec(
        "keyEnterpriseReceipt",
        ChioInternal,
        CommittedSafe,
        None,
        "Key-transition event, transaction and operator key ids.",
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
        "Event time.",
    ),
    spec(
        "response_simulation_evidence_id",
        ChioInternal,
        Unsafe,
        None,
        "Unsalted domain hash over the raw tenant and action ids.",
    ),
    spec(
        "active_defense_backfill_v1",
        ChioInternal,
        Unsafe,
        None,
        "Migration marker with unaudited contents.",
    ),
    spec(
        "scimLifecycle",
        ChioInternal,
        Unsafe,
        None,
        "User ids, user names and entitlements.",
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
        CommittedSafe,
        None,
        "Wall policy identity snapshot.",
    ),
    spec(
        "acp",
        ChioInternal,
        Unsafe,
        None,
        "authorizationResource is taken from the tool call.",
    ),
    spec(
        "agent_web_receipt_ref",
        ChioInternal,
        CommittedSafe,
        None,
        "Fixture receipt reference.",
    ),
    spec(
        "parent_receipt_ids",
        ChioInternal,
        CommittedSafe,
        None,
        "Parent receipt ids.",
    ),
    spec(
        "batch_witness",
        ChioInternal,
        Unsafe,
        None,
        "Unaudited witness contents.",
    ),
];

/// The registration of `key`, or `None` when `key` is not registered.
#[must_use]
pub fn metadata_key_spec(key: &str) -> Option<&'static MetadataKeySpec> {
    RECEIPT_METADATA_KEYS.iter().find(|spec| spec.key == key)
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
        if spec.origin != MetadataKeyOrigin::ChioInternal {
            return Err(Error::CanonicalJson(format!(
                "receipt metadata key {key:?} is caller or hook metadata"
            )));
        }
        if spec.disclosure != MetadataDisclosure::CommittedSafe {
            return Err(Error::CanonicalJson(format!(
                "receipt metadata key {key:?} is not committed-safe"
            )));
        }
    }
    Ok(())
}
