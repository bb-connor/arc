// DO NOT EDIT - regenerate via 'cargo run -p chio-spec-codegen -- --errors-only'.
//
// Source: spec/errors/registry.yaml
// Tool:   chio-spec-codegen
// Crate:  chio-spec-codegen
//
// Manual edits will be overwritten by the next regeneration.

use crate::{Domain, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCodeSpec {
    pub urn: &'static str,
    pub domain: Domain,
    pub severity: Severity,
    pub summary: &'static str,
    pub help: &'static str,
    pub string_code: &'static str,
    pub jsonrpc_code: Option<i32>,
    pub since: &'static str,
    pub stability: &'static str,
    pub consumed_by: &'static [&'static str],
}

pub const REGISTRY_SCHEMA: &str = "chio.error-urn-registry.v1";
pub const REGISTRY_VERSION: &str = "0.1.0";
pub const REGISTRY_UPDATED_AT: &str = "2026-07-14";

pub const TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:passport-schema-unsupported",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction passport schema is unsupported by the verifier.",
    help: "Reject the proof bundle and regenerate the passport with a registered transaction passport schema.",
    string_code: "CHIO-TRANSACTION-PASSPORT-SCHEMA-UNSUPPORTED",
    jsonrpc_code: Some(7100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_PASSPORT_HASH_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:passport-hash-mismatch",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction passport root digest does not match its bound evidence.",
    help: "Reject the proof bundle, rebuild the passport root, and retry with matching evidence graph, claim set, and policy digests.",
    string_code: "CHIO-TRANSACTION-PASSPORT-HASH-MISMATCH",
    jsonrpc_code: Some(7101),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_GRAPH_NOT_CLOSED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:graph-not-closed",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction evidence graph does not close over the required artifact references.",
    help: "Reject the proof bundle and include every required evidence, claim-set, policy, and receipt node in the graph.",
    string_code: "CHIO-TRANSACTION-GRAPH-NOT-CLOSED",
    jsonrpc_code: Some(7102),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_GRAPH_CYCLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:graph-cycle",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction evidence graph contains a cycle.",
    help: "Reject the proof bundle and emit an acyclic evidence graph whose dependency edges can be topologically verified.",
    string_code: "CHIO-TRANSACTION-GRAPH-CYCLE",
    jsonrpc_code: Some(7103),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_REQUIRED_CLAIM_MISSING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:required-claim-missing",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction verifier policy requires a claim that is not verified.",
    help: "Reject the proof bundle and add verified evidence for the required claim or remove the unsupported requirement.",
    string_code: "CHIO-TRANSACTION-REQUIRED-CLAIM-MISSING",
    jsonrpc_code: Some(7104),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_ARTIFACT_HASH_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:artifact-hash-mismatch",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction proof artifact digest does not match the passport or evidence graph.",
    help: "Reject the proof bundle, regenerate the artifact set, and retry with matching transaction evidence digests.",
    string_code: "CHIO-TRANSACTION-ARTIFACT-HASH-MISMATCH",
    jsonrpc_code: Some(7105),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_IDENTITY_NOT_BOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:identity-not-bound",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction evidence does not bind the required identity or subject.",
    help: "Reject the proof bundle and include identity evidence bound to the transaction passport subject and evidence graph.",
    string_code: "CHIO-TRANSACTION-IDENTITY-NOT-BOUND",
    jsonrpc_code: Some(7106),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_AUTHORIZATION_NOT_BOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:authorization-not-bound",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction evidence does not bind required authorization evidence.",
    help: "Reject the proof bundle and include capability, policy, approval, or guard evidence bound to the governed transaction.",
    string_code: "CHIO-TRANSACTION-AUTHORIZATION-NOT-BOUND",
    jsonrpc_code: Some(7107),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_RECEIPT_UNCHECKPOINTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:receipt-uncheckpointed",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction receipt evidence is not checkpointed or included in the required receipt lineage.",
    help: "Reject the proof bundle and provide checkpointed receipt or inclusion evidence for the transaction receipt.",
    string_code: "CHIO-TRANSACTION-RECEIPT-UNCHECKPOINTED",
    jsonrpc_code: Some(7108),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_RUNTIME_PROOF_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:runtime-proof-rejected",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Runtime proof evidence required by the transaction verifier was rejected.",
    help: "Reject the proof bundle and regenerate runtime security, parity, lease, nonce, revocation, sandbox, ack, and terminal receipt evidence.",
    string_code: "CHIO-TRANSACTION-RUNTIME-PROOF-REJECTED",
    jsonrpc_code: Some(7109),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_BUYER_REVIEW_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:buyer-review-rejected",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Buyer review evidence required by the transaction verifier was rejected.",
    help: "Reject the proof bundle and regenerate buyer review evidence that matches the transaction passport and verifier policy.",
    string_code: "CHIO-TRANSACTION-BUYER-REVIEW-REJECTED",
    jsonrpc_code: Some(7110),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_SETTLEMENT_UNVERIFIED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:settlement-unverified",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Settlement evidence required by the transaction verifier is absent or unverified.",
    help: "Reject the proof bundle and include settlement evidence bound to the transaction order, amount, currency, rail, and receipt lineage.",
    string_code: "CHIO-TRANSACTION-SETTLEMENT-UNVERIFIED",
    jsonrpc_code: Some(7111),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_DISPUTE_UNBOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:dispute-unbound",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Dispute, refund, or remediation evidence is not bound to the transaction.",
    help: "Reject the proof bundle and bind dispute, refund, remediation, and settlement reversal evidence to the transaction passport and receipts.",
    string_code: "CHIO-TRANSACTION-DISPUTE-UNBOUND",
    jsonrpc_code: Some(7112),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const TRANSACTION_TRANSPARENCY_PREVIEW_NOT_ALLOWED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transaction:transparency-preview-not-allowed",
    domain: Domain::Transaction,
    severity: Severity::Error,
    summary: "Transaction transparency evidence is only preview or advisory when verified transparency is required.",
    help: "Reject the proof bundle and provide verified transparency inclusion evidence or remove the transparency claim.",
    string_code: "CHIO-TRANSACTION-TRANSPARENCY-PREVIEW-NOT-ALLOWED",
    jsonrpc_code: Some(7113),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-transaction-passport", "chio-cli", "chio-proof-room"],
};

pub const CAPABILITY_SCOPE_EXCEEDED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:scope-exceeded",
    domain: Domain::Capability,
    severity: Severity::Error,
    summary: "Capability scope does not allow the requested tool, resource, or prompt.",
    help: "Issue a capability that explicitly grants the requested scope, or change the request to fit the granted scope.",
    string_code: "CHIO-KERNEL-OUT-OF-SCOPE-TOOL",
    jsonrpc_code: Some(2100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-cli", "chio-control-plane"],
};

pub const CAPABILITY_EXPIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:expired",
    domain: Domain::Capability,
    severity: Severity::Error,
    summary: "Capability token expired before the kernel evaluated the request.",
    help: "Obtain or issue a fresh time-bounded capability before retrying the operation.",
    string_code: "CHIO-KERNEL-CAPABILITY-EXPIRED",
    jsonrpc_code: Some(2101),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-cli", "chio-control-plane"],
};

pub const CAPABILITY_REVOKED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:revoked",
    domain: Domain::Capability,
    severity: Severity::Error,
    summary: "Capability token was revoked and must not be retried.",
    help: "Resolve the revocation reason and request a newly issued capability.",
    string_code: "CHIO-KERNEL-CAPABILITY-REVOKED",
    jsonrpc_code: Some(2102),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-cli", "chio-control-plane"],
};

pub const CAPABILITY_NOT_YET_VALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:not-yet-valid",
    domain: Domain::Capability,
    severity: Severity::Error,
    summary: "Capability token is not valid at the current evaluation time.",
    help: "Retry after the not-before timestamp or issue a capability with the intended validity window.",
    string_code: "CHIO-KERNEL-CAPABILITY-NOT-YET-VALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-cli"],
};

pub const CAPABILITY_SUBJECT_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:subject-mismatch",
    domain: Domain::Capability,
    severity: Severity::Error,
    summary: "Capability subject does not match the requesting actor.",
    help: "Bind the capability to the correct subject DID or use credentials for the subject named by the token.",
    string_code: "CHIO-KERNEL-SUBJECT-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-credentials"],
};

pub const CAPABILITY_SIGNATURE_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:capability:signature-invalid",
    domain: Domain::Capability,
    severity: Severity::Fatal,
    summary: "Capability signature verification failed.",
    help: "Reject the capability, verify issuer trust, and reissue the token with canonical JSON signing.",
    string_code: "CHIO-KERNEL-INVALID-SIGNATURE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-credentials"],
};

pub const POLICY_DECISION_DENIED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:policy:decision-denied",
    domain: Domain::Policy,
    severity: Severity::Error,
    summary: "Policy evaluation denied the requested action.",
    help: "Inspect the policy rule path and update the request or policy inputs before retrying.",
    string_code: "CHIO-CLI-POLICY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-policy", "chio-cli", "chio-control-plane"],
};

pub const POLICY_COMPILE_FAILED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:policy:compile-failed",
    domain: Domain::Policy,
    severity: Severity::Error,
    summary: "Policy document failed to compile.",
    help: "Fix the policy syntax or schema issue reported by the compiler and reload the policy.",
    string_code: "CHIO-CLI-POLICY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-policy", "chio-cli"],
};

pub const POLICY_CONSTRAINT_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:policy:constraint-invalid",
    domain: Domain::Policy,
    severity: Severity::Error,
    summary: "Policy constraint was syntactically valid but semantically invalid.",
    help: "Regenerate or edit the constraint so every referenced scope, resource, and operator is supported.",
    string_code: "CHIO-KERNEL-INVALID-CONSTRAINT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-policy", "chio-kernel"],
};

pub const POLICY_GOVERNANCE_DENIED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:policy:governance-denied",
    domain: Domain::Policy,
    severity: Severity::Error,
    summary: "Governance policy denied a governed transaction.",
    help: "Follow the governance approval path or remove the governed operation from the request.",
    string_code: "CHIO-KERNEL-GOVERNED-TRANSACTION-DENIED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-governance", "chio-kernel"],
};

pub const GUARD_DENIED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:guard:denied",
    domain: Domain::Guard,
    severity: Severity::Error,
    summary: "Guard pipeline denied the request or response.",
    help: "Inspect the guard verdict and adjust the prompt, tool input, policy, or output before retrying.",
    string_code: "CHIO-KERNEL-GUARD-DENIED",
    jsonrpc_code: Some(3100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-guards", "chio-cli"],
};

pub const GUARD_INPUT_REDACTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:guard:input-redacted",
    domain: Domain::Guard,
    severity: Severity::Warning,
    summary: "Guard redacted sensitive input before it crossed a trust boundary.",
    help: "Review the redaction receipt and provide lower-risk input if the tool requires the removed field.",
    string_code: "CHIO-GUARD-INPUT-REDACTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-data-guards", "chio-guards"],
};

pub const GUARD_OUTPUT_REDACTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:guard:output-redacted",
    domain: Domain::Guard,
    severity: Severity::Warning,
    summary: "Guard redacted sensitive output before it crossed a trust boundary.",
    help: "Review the guard receipt and update the downstream consumer to handle redacted fields.",
    string_code: "CHIO-GUARD-OUTPUT-REDACTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-data-guards", "chio-guards"],
};

pub const GUARD_WASM_TRAP: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:guard:wasm-trap",
    domain: Domain::Guard,
    severity: Severity::Fatal,
    summary: "WASM guard trapped during evaluation.",
    help: "Fail closed, inspect the guard bundle, and republish a guard that completes deterministically.",
    string_code: "CHIO-GUARD-WASM-TRAP",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-wasm-guards", "chio-guard-sdk"],
};

pub const ATTEST_RECEIPT_SIGNING_FAILED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:attest:receipt-signing-failed",
    domain: Domain::Attest,
    severity: Severity::Fatal,
    summary: "Kernel could not sign the receipt for a decision or tool call.",
    help:
        "Treat the operation as failed and repair the signing key, key store, or canonical payload.",
    string_code: "CHIO-KERNEL-RECEIPT-SIGNING-FAILED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-attest-verify"],
};

pub const ATTEST_QUOTE_VERIFICATION_FAILED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:attest:quote-verification-failed",
    domain: Domain::Attest,
    severity: Severity::Fatal,
    summary: "TEE quote verification failed.",
    help: "Reject the attestation and refresh the quote or verifier trust roots before retrying.",
    string_code: "CHIO-ATTEST-QUOTE-VERIFICATION-FAILED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-attest-verify", "chio-tee"],
};

pub const ATTEST_PROVENANCE_MISSING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:attest:provenance-missing",
    domain: Domain::Attest,
    severity: Severity::Error,
    summary: "Required provenance evidence was missing from the receipt context.",
    help: "Regenerate the evidence bundle and include provenance before submitting the operation.",
    string_code: "CHIO-ATTEST-PROVENANCE-MISSING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-attest-verify", "chio-otel-receipt-exporter"],
};

pub const REPLAY_TRACE_NOT_FOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:replay:trace-not-found",
    domain: Domain::Replay,
    severity: Severity::Error,
    summary: "Replay trace could not be found.",
    help: "Check the replay corpus path and regenerate the trace if it was not archived.",
    string_code: "CHIO-REPLAY-TRACE-NOT-FOUND",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-replay-corpus", "chio-cli"],
};

pub const REPLAY_DETERMINISTIC_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:replay:deterministic-mismatch",
    domain: Domain::Replay,
    severity: Severity::Error,
    summary: "Replay produced a deterministic output mismatch.",
    help: "Compare the recorded receipt, model fixture, and guard bundle versions before accepting the replay.",
    string_code: "CHIO-REPLAY-DETERMINISTIC-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-replay-corpus", "chio-conformance"],
};

pub const REPLAY_FIXTURE_DRIFT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:replay:fixture-drift",
    domain: Domain::Replay,
    severity: Severity::Warning,
    summary: "Replay fixture no longer matches the registry or schema it was recorded against.",
    help: "Regenerate the fixture from the current registry and rerun replay validation.",
    string_code: "CHIO-REPLAY-FIXTURE-DRIFT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-replay-corpus", "chio-spec-codegen"],
};

pub const PROVIDER_TOOL_SERVER_ERROR: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:provider:tool-server-error",
    domain: Domain::Provider,
    severity: Severity::Error,
    summary: "Tool server returned an adapter or execution error.",
    help: "Retry with bounded backoff only when the provider marks the failure as transient.",
    string_code: "CHIO-KERNEL-TOOL-SERVER",
    jsonrpc_code: Some(5100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-kernel",
        "chio-tool-call-fabric",
        "chio-provider-conformance",
    ],
};

pub const PROVIDER_OPENAI: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:provider:openai",
    domain: Domain::Provider,
    severity: Severity::Error,
    summary: "OpenAI provider adapter returned a normalized provider error.",
    help: "Inspect the provider error details and retry only when the adapter marks the failure transient.",
    string_code: "CHIO-PROVIDER-OPENAI",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["deferred-openai-adapter-ticket", "chio-provider-conformance"],
};

pub const PROVIDER_ANTHROPIC: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:provider:anthropic",
    domain: Domain::Provider,
    severity: Severity::Error,
    summary: "Anthropic provider adapter returned a normalized provider error.",
    help: "Inspect the provider error details and retry only when the adapter marks the failure transient.",
    string_code: "CHIO-PROVIDER-ANTHROPIC",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-anthropic-tools-adapter", "chio-provider-conformance"],
};

pub const PROVIDER_BEDROCK: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:provider:bedrock",
    domain: Domain::Provider,
    severity: Severity::Error,
    summary: "Bedrock Converse provider adapter returned a normalized provider error.",
    help: "Inspect the provider error details and retry only when the adapter marks the failure transient.",
    string_code: "CHIO-PROVIDER-BEDROCK",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-bedrock-converse-adapter", "chio-provider-conformance"],
};

pub const MANIFEST_SCHEMA_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:manifest:schema-invalid",
    domain: Domain::Manifest,
    severity: Severity::Error,
    summary: "Manifest did not validate against the expected schema.",
    help: "Fix the manifest shape and rerun schema validation before loading it.",
    string_code: "CHIO-CLI-YAML",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-manifest", "chio-cli", "chio-spec-validate"],
};

pub const MANIFEST_SIGNATURE_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:manifest:signature-invalid",
    domain: Domain::Manifest,
    severity: Severity::Fatal,
    summary: "Manifest signature verification failed.",
    help:
        "Reject the manifest and republish it with the expected signing key and canonical payload.",
    string_code: "CHIO-MANIFEST-SIGNATURE-INVALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-manifest", "chio-guard-registry"],
};

pub const MANIFEST_TOOL_NOT_REGISTERED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:manifest:tool-not-registered",
    domain: Domain::Manifest,
    severity: Severity::Error,
    summary: "Requested tool is not registered in the active manifest.",
    help: "Register the tool in the manifest or request a tool that is present.",
    string_code: "CHIO-KERNEL-TOOL-NOT-REGISTERED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-manifest", "chio-kernel"],
};

pub const MANIFEST_RESOURCE_ROOT_DENIED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:manifest:resource-root-denied",
    domain: Domain::Manifest,
    severity: Severity::Error,
    summary: "Requested resource root is not allowed by the manifest.",
    help: "Grant the resource root in the manifest or request a resource under an allowed root.",
    string_code: "CHIO-KERNEL-RESOURCE-ROOT-DENIED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-manifest", "chio-kernel"],
};

pub const KERNEL_INTERNAL_ERROR: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:internal-error",
    domain: Domain::Kernel,
    severity: Severity::Fatal,
    summary: "Kernel hit an internal error while evaluating the request.",
    help: "Retry with bounded backoff only after preserving the receipt and diagnostic context.",
    string_code: "CHIO-KERNEL-INTERNAL",
    jsonrpc_code: Some(6100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-cli"],
};

pub const KERNEL_RUNTIME_ADMISSION_READINESS_TIMEOUT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:runtime-admission-readiness-timeout",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Runtime admission readiness did not resolve before the dispatch deadline.",
    help: "Restore the runtime admission dependency or increase the bounded readiness timeout before retrying.",
    string_code: "CHIO-KERNEL-RUNTIME-ADMISSION-READINESS-TIMEOUT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_SESSION_NOT_INITIALIZED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:session-not-initialized",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Request arrived before the session was initialized.",
    help: "Open a new session and complete initialization before retrying the operation.",
    string_code: "CHIO-KERNEL-UNKNOWN-SESSION",
    jsonrpc_code: Some(1001),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-http-session"],
};

pub const KERNEL_SESSION_ALREADY_EXISTS: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:session-already-exists",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Session creation attempted to reuse an existing session identifier.",
    help: "Choose a new session identifier or attach to the existing session.",
    string_code: "CHIO-KERNEL-SESSION-ALREADY-EXISTS",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-http-session"],
};

pub const KERNEL_REQUEST_INCOMPLETE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:request-incomplete",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Kernel request is missing required fields.",
    help: "Provide every required request field before dispatching the operation.",
    string_code: "CHIO-KERNEL-REQUEST-INCOMPLETE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-core-types"],
};

pub const KERNEL_REQUEST_CANCELLED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:request-cancelled",
    domain: Domain::Kernel,
    severity: Severity::Warning,
    summary: "Kernel request was cancelled before completion.",
    help: "Treat any partial tool output as invalid and retry with a new request if work is still required.",
    string_code: "CHIO-KERNEL-REQUEST-CANCELLED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-tool-call-fabric"],
};

pub const KERNEL_BUDGET_EXHAUSTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:budget-exhausted",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Kernel budget for the requested operation was exhausted.",
    help: "Retry only after replenishing the budget, widening the grant, or reconciling billing state.",
    string_code: "CHIO-KERNEL-BUDGET-EXHAUSTED",
    jsonrpc_code: Some(4100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-metering", "chio-cli"],
};

pub const KERNEL_BUDGET_AUTHORIZE_REPLAY: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:budget-authorize-replay",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Kernel rejected a replayed budget authorization event.",
    help: "Retry only with a fresh request identity that produces a unique budget authorization event.",
    string_code: "CHIO-KERNEL-BUDGET-AUTHORIZE-REPLAY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-metering", "chio-control-plane"],
};

pub const KERNEL_DELIVERY_CONTRACT_UNSUPPORTED_CARRIER: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:delivery-contract-unsupported-carrier",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Request carried an output-digest delivery contract the evaluator cannot enforce.",
    help: "Route the request to an output-aware durable terminal, or drop the output_digest_sha256 constraint before retrying.",
    string_code: "CHIO-KERNEL-DELIVERY-CONTRACT-UNSUPPORTED-CARRIER",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel", "chio-conformance"],
};

pub const KERNEL_DELIVERY_CONTRACT_DIGEST_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:delivery-contract-digest-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Delivered output did not hash to the frozen expected digest of the delivery contract.",
    help: "The delivery is rejected and no money moves. Re-run the tool so the output matches the expected digest before retrying.",
    string_code: "CHIO-KERNEL-DELIVERY-CONTRACT-DIGEST-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel", "chio-conformance"],
};

pub const KERNEL_FINDING_PURCHASE_UNSUPPORTED_ADMISSION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:finding-purchase-unsupported-admission",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Grant carried a finding-purchase marker the evaluator cannot admit.",
    help: "Route the reveal to a deployment with purchase-aware admission, or drop the require_finding_purchase marker before retrying.",
    string_code: "CHIO-KERNEL-FINDING-PURCHASE-UNSUPPORTED-ADMISSION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel", "chio-conformance"],
};

pub const KERNEL_FINDING_PURCHASE_CONTEXT_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:finding-purchase-context-invalid",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Finding-purchase marker or its signed purchase context failed verification.",
    help: "Present a well-formed local reversible-hold marker with the matching signed purchase context, the exact offered token, and a finding_id argument equal to the marked sale.",
    string_code: "CHIO-KERNEL-FINDING-PURCHASE-CONTEXT-INVALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel", "chio-conformance"],
};

pub const KERNEL_FINDING_DELIVERY_MEDIA_TYPE_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:finding-delivery-media-type-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Revealed finding payload did not carry the media type the signed finding advertises.",
    help: "The reveal is rejected and the hold is released. Re-run the reveal so the delivered envelope carries the advertised media type.",
    string_code: "CHIO-KERNEL-FINDING-DELIVERY-MEDIA-TYPE-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel", "chio-conformance"],
};

pub const TRANSPORT_PROTOCOL_VERSION_UNSUPPORTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:protocol-version-unsupported",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "Peer requested an unsupported protocol version.",
    help: "Negotiate a supported Chio protocol version before retrying.",
    string_code: "CHIO-CLI-TRANSPORT",
    jsonrpc_code: Some(1000),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-http-core", "chio-mcp-edge", "chio-a2a-edge"],
};

pub const TRANSPORT_INVALID_REQUEST_SHAPE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:invalid-request-shape",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "Request payload did not match the expected wire shape.",
    help: "Correct the JSON-RPC or HTTP request shape before retrying.",
    string_code: "CHIO-CLI-JSON",
    jsonrpc_code: Some(1002),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-http-core", "chio-spec-validate"],
};

pub const TRANSPORT_AUTH_MISSING_OR_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:auth-missing-or-invalid",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "Transport authentication was missing, expired, or invalid.",
    help: "Refresh credentials and resend the request with valid transport authentication.",
    string_code: "CHIO-CLI-CREDENTIAL",
    jsonrpc_code: Some(1100),
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-http-core", "chio-credentials"],
};

pub const TRANSPORT_HTTP_FAILED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:http-failed",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "HTTP transport failed before the kernel could evaluate the request.",
    help: "Check endpoint reachability, TLS configuration, and response body diagnostics before retrying.",
    string_code: "CHIO-CLI-HTTP",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-http-core", "chio-cli"],
};

pub const TRANSPORT_DPOP_VERIFICATION_FAILED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:dpop-verification-failed",
    domain: Domain::Transport,
    severity: Severity::Fatal,
    summary: "DPoP proof verification failed.",
    help: "Reject the request and require a fresh proof bound to the correct method, URI, and key.",
    string_code: "CHIO-KERNEL-DPOP-VERIFICATION-FAILED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-http-core"],
};

pub const TRANSPORT_UPSTREAM_FAILURE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:upstream-failure",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "Wrapped upstream MCP server returned an error while handling a relayed tool call or listing.",
    help: "Inspect the upstream MCP server response; retry only when the upstream marks the failure transient.",
    string_code: "CHIO-TRANSPORT-UPSTREAM-FAILURE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli"],
};

pub const TRANSPORT_METHOD_NOT_FOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:method-not-found",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "JSON-RPC method is not supported by the Chio MCP wrapper.",
    help: "Call a recognized method; the MCP wrapper supports tools/list, tools/call, initialize, ping, and JSON-RPC notifications.",
    string_code: "CHIO-TRANSPORT-METHOD-NOT-FOUND",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli"],
};

pub const CLI_IO: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:io",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "CLI failed while reading or writing local data.",
    help: "Check the path, permissions, and filesystem state before retrying.",
    string_code: "CHIO-CLI-IO",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-cli", "chio-control-plane"],
};

pub const CLI_JSON: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:json",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "CLI failed to parse or render JSON.",
    help: "Fix the JSON payload or output template and rerun the command.",
    string_code: "CHIO-CLI-JSON",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-cli", "chio-control-plane"],
};

pub const CLI_YAML: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:yaml",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "CLI failed to parse or render YAML.",
    help: "Fix the YAML document and rerun the command.",
    string_code: "CHIO-CLI-YAML",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-cli", "chio-control-plane"],
};

pub const CLI_SQLITE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:sqlite",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "CLI SQLite store operation failed.",
    help: "Check the database path, schema version, and write permissions before retrying.",
    string_code: "CHIO-CLI-SQLITE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-cli", "chio-store-sqlite"],
};

pub const CLI_OTHER: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:other",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "CLI returned an uncategorized compatibility error.",
    help: "Preserve the original message and migrate the call site to a specific registry code when touched.",
    string_code: "CHIO-CLI-OTHER",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "deprecated",
    consumed_by: &["chio-cli", "chio-control-plane"],
};

pub const CLI_DOCTOR_TOOLCHAIN_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:doctor-toolchain-mismatch",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "chio doctor toolchain probe found a Rust toolchain mismatch.",
    help: "Install the workspace MSRV (or the version pinned in rust-toolchain.toml) and rerun chio doctor.",
    string_code: "CHIO-CLI-DOCTOR-TOOLCHAIN-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli"],
};

pub const CLI_DOCTOR_OCI_UNREACHABLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:doctor-oci-unreachable",
    domain: Domain::Cli,
    severity: Severity::Warning,
    summary: "chio doctor OCI registry reachability probe could not reach the configured registry.",
    help: "Verify the registry URL, network egress, and credentials, or run with CHIO_DOCTOR_SKIP_NETWORK=1 to bypass.",
    string_code: "CHIO-CLI-DOCTOR-OCI-UNREACHABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli", "chio-guard-registry"],
};

pub const CLI_DOCTOR_COSIGN_STALE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:doctor-cosign-stale",
    domain: Domain::Cli,
    severity: Severity::Warning,
    summary: "chio doctor cosign freshness probe found a stale or unverifiable guard-bundle signature.",
    help: "Re-pull the guard bundle and verify its sigstore signature against the trusted identity set.",
    string_code: "CHIO-CLI-DOCTOR-COSIGN-STALE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli", "chio-attest-verify"],
};

pub const CLI_DOCTOR_OTEL_UNRESOLVED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:doctor-otel-unresolved",
    domain: Domain::Cli,
    severity: Severity::Warning,
    summary: "chio doctor OTEL probe could not resolve the OTLP endpoint or kernel runtime metrics.",
    help: "Set OTEL_EXPORTER_OTLP_ENDPOINT and ensure the chio-tower /metrics endpoint exposes chio_kernel_dispatch_inflight.",
    string_code: "CHIO-CLI-DOCTOR-OTEL-UNRESOLVED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli"],
};

pub const CLI_DOCTOR_CHIO_YAML_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:doctor-chio-yaml-invalid",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "chio doctor schema probe found chio.yaml validation errors.",
    help: "Repair the document at the reported line and column and rerun chio doctor.",
    string_code: "CHIO-CLI-DOCTOR-CHIO-YAML-INVALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli"],
};

pub const CLI_DOCTOR_PROBE_FAILED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:cli:doctor-probe-failed",
    domain: Domain::Cli,
    severity: Severity::Error,
    summary: "chio doctor reported one or more failing probes.",
    help: "Inspect the per-probe diagnostics, fix the reported issues, and rerun chio doctor.",
    string_code: "CHIO-CLI-DOCTOR-PROBE-FAILED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-cli"],
};

pub const DELEGATION_CHAIN_REVOKED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:delegation:chain-revoked",
    domain: Domain::Delegation,
    severity: Severity::Error,
    summary: "Delegation chain includes a revoked link.",
    help: "Rebuild the chain from non-revoked grants before retrying delegated execution.",
    string_code: "CHIO-KERNEL-DELEGATION-CHAIN-REVOKED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel", "chio-federation"],
};

pub const ADVERSARIAL_ESCAPE_DETECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:adversarial:escape-detected",
    domain: Domain::Adversarial,
    severity: Severity::Fatal,
    summary: "Adversarial suite detected an escape from the intended guard boundary.",
    help: "Fail the run, preserve artifacts, and tighten the guard or sandbox before rerunning.",
    string_code: "CHIO-ADVERSARIAL-ESCAPE-DETECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-conformance", "chio-guards"],
};

pub const THREAT_COVERAGE_GAP: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:threat:coverage-gap",
    domain: Domain::Threat,
    severity: Severity::Warning,
    summary: "Threat model coverage check found an uncovered failure mode.",
    help: "Add a mapped test, fixture, or documented deferral before closing the coverage finding.",
    string_code: "CHIO-THREAT-COVERAGE-GAP",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-conformance", "chio-spec-validate"],
};

pub const ARENA_REPLAY_DIVERGENCE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:arena:replay-divergence",
    domain: Domain::Arena,
    severity: Severity::Error,
    summary: "Arena replay produced a verdict divergence.",
    help: "Compare the replay receipt, policy, guard bundle, and provider fixture before accepting the run.",
    string_code: "CHIO-ARENA-REPLAY-DIVERGENCE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-replay-corpus", "chio-conformance"],
};

pub const ECONOMY_METERING_UNAVAILABLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:economy:metering-unavailable",
    domain: Domain::Economy,
    severity: Severity::Error,
    summary: "Metering or balance state was unavailable for an economic decision.",
    help: "Retry after the metering backend or settlement ledger is reachable and current.",
    string_code: "CHIO-ECONOMY-METERING-UNAVAILABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-metering", "chio-settle", "chio-credit"],
};

pub const LINEAGE_ANCESTOR_MISSING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:lineage:ancestor-missing",
    domain: Domain::Lineage,
    severity: Severity::Error,
    summary: "Lineage graph references an ancestor that cannot be resolved.",
    help: "Repair the lineage edge or import the missing receipt before accepting the graph.",
    string_code: "CHIO-LINEAGE-ANCESTOR-MISSING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-anchor", "chio-otel-receipt-exporter"],
};

pub const CUSTODY_HARDWARE_KEY_UNAVAILABLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:hardware-key-unavailable",
    domain: Domain::Custody,
    severity: Severity::Fatal,
    summary: "Required hardware custody key was unavailable.",
    help: "Do not fall back to a software key; restore the custody key path and retry.",
    string_code: "CHIO-CUSTODY-HARDWARE-KEY-UNAVAILABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-tee", "chio-attest-verify"],
};

pub const CUSTODY_ASSERTION_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:assertion-rejected",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "WebAuthn assertion failed structural or signature verification.",
    help:
        "Treat the assertion as untrusted; do not retry without a fresh challenge from the issuer.",
    string_code: "CHIO-CUSTODY-ASSERTION-REJECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-control-plane"],
};

pub const MOBILE_RECEIPT_POST_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:mobile:receipt-post-rejected",
    domain: Domain::Mobile,
    severity: Severity::Error,
    summary: "Hosted oracle rejected a mobile receipt after a successful network POST.",
    help: "Preserve the queued receipt, surface the oracle response, and do not retry until the tenant, signature, or capability binding is repaired.",
    string_code: "CHIO-MOBILE-RECEIPT-POST-REJECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel-mobile", "chio-custody-hw"],
};

pub const MOBILE_RECEIPT_SCHEMA_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:mobile:receipt-schema-invalid",
    domain: Domain::Mobile,
    severity: Severity::Error,
    summary: "Mobile receipt export did not validate against the audit-log export schema.",
    help: "Keep the receipt in the offline queue and regenerate the export envelope against spec/audit-log/export-schema.v1.json before retrying.",
    string_code: "CHIO-MOBILE-RECEIPT-SCHEMA-INVALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel-mobile", "chio-siem"],
};

pub const MOBILE_ORACLE_UNREACHABLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:mobile:oracle-unreachable",
    domain: Domain::Mobile,
    severity: Severity::Warning,
    summary: "Mobile SDK could not reach the hosted receipt oracle within the retry budget.",
    help: "Keep the receipt in the encrypted offline queue and retry with bounded backoff after connectivity returns.",
    string_code: "CHIO-MOBILE-ORACLE-UNREACHABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-kernel-mobile", "chio-control-plane"],
};

pub const CUSTODY_AUDIENCE_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:audience-mismatch",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Capability presented to a different audience than it was minted for.",
    help: "Issue or request a capability whose audience pin matches the verifier identity.",
    string_code: "CHIO-CUSTODY-AUDIENCE-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel"],
};

pub const CUSTODY_REPLAY_DETECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:replay-detected",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "WebAuthn challenge nonce was previously redeemed for this credential.",
    help: "Obtain a fresh challenge from the issuer; replayed assertions are denied fail-closed.",
    string_code: "CHIO-CUSTODY-REPLAY-DETECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-control-plane"],
};

pub const CUSTODY_CAPABILITY_EXPIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:capability-expired",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Passkey capability expired before the verifier evaluated the request.",
    help: "Mint a fresh capability; passkey capabilities are pinned to a five-minute lifetime.",
    string_code: "CHIO-CUSTODY-CAPABILITY-EXPIRED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel"],
};

pub const CUSTODY_CREDENTIAL_REVOKED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:credential-revoked",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "WebAuthn credential bound to this capability has been revoked.",
    help: "Re-enroll the user's authenticator and request a freshly-issued capability.",
    string_code: "CHIO-CUSTODY-CREDENTIAL-REVOKED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel", "chio-revocation-oracle"],
};

pub const CUSTODY_USER_VERIFICATION_REQUIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:user-verification-required",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "WebAuthn assertion verified cryptographically but did not report user verification.",
    help: "Re-attempt the ceremony with a user-verifying gesture (PIN, biometric); custody issuance requires UV.",
    string_code: "CHIO-CUSTODY-USER-VERIFICATION-REQUIRED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-control-plane"],
};

pub const CUSTODY_INTERNAL_ENCODING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:internal-encoding",
    domain: Domain::Custody,
    severity: Severity::Fatal,
    summary: "Custody surface failed to canonicalize, encode, or decode an envelope.",
    help: "Treat as an internal error; do not retry until the encoding bug is resolved. No fresh challenge will help.",
    string_code: "CHIO-CUSTODY-INTERNAL-ENCODING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw"],
};

pub const CUSTODY_RATE_LIMITED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:rate-limited",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Capability issuance was denied because the subject exceeded its rate budget.",
    help: "Retry after the rate window elapses; the mint is denied fail-closed before the revocation oracle, nonce store, or signing backend are consulted.",
    string_code: "CHIO-CUSTODY-RATE-LIMITED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw"],
};

pub const CUSTODY_MOBILE_CHALLENGE_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:mobile-challenge-invalid",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Mobile attestation challenge state, binding, or validity is invalid.",
    help: "Reject the attestation and obtain a fresh server-issued challenge bound to the exact application and audience.",
    string_code: "CHIO-CUSTODY-MOBILE-CHALLENGE-INVALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw"],
};

pub const CUSTODY_MOBILE_CHALLENGE_REPLAYED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:mobile-challenge-replayed",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Mobile attestation challenge was already consumed.",
    help: "Reject the replay and obtain a fresh server-issued challenge; consumed challenges are never reusable.",
    string_code: "CHIO-CUSTODY-MOBILE-CHALLENGE-REPLAYED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw"],
};

pub const CUSTODY_MOBILE_CHALLENGE_STORE_UNAVAILABLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:mobile-challenge-store-unavailable",
    domain: Domain::Custody,
    severity: Severity::Fatal,
    summary: "Durable mobile attestation challenge or counter state is unavailable or untrusted.",
    help: "Deny issuance until durable challenge custody and file identity are healthy; do not retry through an in-memory fallback.",
    string_code: "CHIO-CUSTODY-MOBILE-CHALLENGE-STORE-UNAVAILABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw"],
};

pub const CUSTODY_APP_ATTEST_INVALID_CBOR: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-invalid-cbor",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest statement failed to decode as valid CBOR or was missing a required field.",
    help: "Reject the attestation; do not retry without a freshly generated App Attest statement from the device.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-INVALID-CBOR",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_INVALID_ROOT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-invalid-root",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest certificate chain did not anchor to the pinned Apple App Attestation root.",
    help: "Reject the attestation; verify the device produced a genuine Apple App Attest statement and that the pinned root is current.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-INVALID-ROOT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_APP_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-app-mismatch",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest app-identifier hash did not match the expected application identity.",
    help: "Reject the attestation; the statement was minted for a different app identifier than the verifier expects.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-APP-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_CHALLENGE_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-challenge-mismatch",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest challenge hash did not match the issued challenge.",
    help: "Reject the attestation and reissue a fresh challenge; replayed or mismatched challenges are denied fail-closed.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-CHALLENGE-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_KEY_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-key-mismatch",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest key identifier did not match the credential bound to this capability.",
    help: "Reject the attestation; the statement was produced by a different hardware key than the one enrolled.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-KEY-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_CREDENTIAL_KEY_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-credential-key-mismatch",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest leaf certificate public key did not match the credential public key in authenticator data (WebAuthn registration step 6).",
    help: "Reject the attestation; the attested hardware key is not bound to the enrolled credential public key and is denied fail-closed.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-CREDENTIAL-KEY-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_COUNTER_ROLLBACK: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-counter-rollback",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest assertion counter went backwards relative to the last accepted value.",
    help: "Reject the assertion; a counter rollback indicates replay or a cloned key and is denied fail-closed.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-COUNTER-ROLLBACK",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_APP_ATTEST_CERT_CHAIN_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:app-attest-cert-chain-invalid",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Apple App Attest certificate chain failed signature or structural verification.",
    help: "Reject the attestation; the certificate chain did not verify against the pinned Apple roots.",
    string_code: "CHIO-CUSTODY-APP-ATTEST-CERT-CHAIN-INVALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_PLAY_INTEGRITY_INVALID_TOKEN: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:play-integrity-invalid-token",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Google Play Integrity token failed to decode or verify.",
    help: "Reject the attestation; do not retry without a freshly minted Play Integrity token from the device.",
    string_code: "CHIO-CUSTODY-PLAY-INTEGRITY-INVALID-TOKEN",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_PLAY_INTEGRITY_NONCE_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:play-integrity-nonce-mismatch",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Google Play Integrity token nonce did not match the issued challenge.",
    help: "Reject the attestation and reissue a fresh nonce; replayed or mismatched nonces are denied fail-closed.",
    string_code: "CHIO-CUSTODY-PLAY-INTEGRITY-NONCE-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_PLAY_INTEGRITY_APP_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:play-integrity-app-rejected",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Google Play Integrity verdict rejected the application (unrecognized or tampered package).",
    help: "Reject the attestation; the Play Integrity verdict did not recognize the app as a genuine, unmodified install.",
    string_code: "CHIO-CUSTODY-PLAY-INTEGRITY-APP-REJECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const CUSTODY_PLAY_INTEGRITY_DEVICE_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:custody:play-integrity-device-rejected",
    domain: Domain::Custody,
    severity: Severity::Error,
    summary: "Google Play Integrity verdict rejected the device integrity signal.",
    help: "Reject the attestation; the Play Integrity verdict did not attest a trustworthy device.",
    string_code: "CHIO-CUSTODY-PLAY-INTEGRITY-DEVICE-REJECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-custody-hw", "chio-kernel-mobile"],
};

pub const WEIGHTS_MODEL_CARD_MISSING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:model-card-missing",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Model weights or runtime artifact lacks a required model card.",
    help: "Attach the signed model card and verify its hash before running the workload.",
    string_code: "CHIO-WEIGHTS-MODEL-CARD-MISSING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-tee-frame", "chio-attest-verify"],
};

pub const WEIGHTS_CARD_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:card-mismatch",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Provider's loaded weights_hash does not match the signed model card.",
    help: "Re-sign a card whose weights_hash matches the loaded weights blob, or rebind the provider with the correct weights.",
    string_code: "CHIO-WEIGHTS-CARD-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights", "chio-kernel", "chio-cli"],
};

pub const WEIGHTS_SCOPE_NOT_SUBSET: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:scope-not-subset",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Requested capability scope set is not a subset of the model card's allowed_capability_set.",
    help: "Bind under a card whose allowed_capability_set covers the requested scope, or narrow the request.",
    string_code: "CHIO-WEIGHTS-SCOPE-NOT-SUBSET",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights", "chio-kernel", "chio-cli"],
};

pub const WEIGHTS_TOOL_BANNED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:tool-banned",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Requested tool intersects the model card's banned_tools.",
    help: "The card explicitly forbids the requested tool. Bind under a card that does not list the tool as banned, or remove the tool from the request.",
    string_code: "CHIO-WEIGHTS-TOOL-BANNED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights", "chio-kernel", "chio-cli"],
};

pub const WEIGHTS_CARD_EXPIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:card-expired",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Model card expired before the verifier evaluated it.",
    help: "Mint a fresh card; cards bind to issued_at / expires_at and the kernel rejects past expiry.",
    string_code: "CHIO-WEIGHTS-CARD-EXPIRED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights", "chio-kernel"],
};

pub const WEIGHTS_BUNDLE_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:bundle-rejected",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Cosign bundle for the model card failed cryptographic verification.",
    help: "Treat the card as untrusted; do not rebind without a fresh, correctly-signed cosign bundle.",
    string_code: "CHIO-WEIGHTS-BUNDLE-REJECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights", "chio-kernel", "chio-cli"],
};

pub const WEIGHTS_SCHEMA_REJECTED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:schema-rejected",
    domain: Domain::Weights,
    severity: Severity::Error,
    summary: "Model card structural validation failed (bad weights_hash, missing required field, or invalid issued_at / expires_at window).",
    help: "Re-mint the card with a valid v1 schema; check weights_hash is 64 lowercase hex chars and expires_at >= issued_at.",
    string_code: "CHIO-WEIGHTS-SCHEMA-REJECTED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights"],
};

pub const WEIGHTS_INTERNAL_ENCODING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:weights:internal-encoding",
    domain: Domain::Weights,
    severity: Severity::Fatal,
    summary: "Model card surface failed to canonicalize, encode, or decode an envelope.",
    help: "Treat as an internal error; do not retry until the encoding bug is resolved. No fresh challenge will help.",
    string_code: "CHIO-WEIGHTS-INTERNAL-ENCODING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "unstable",
    consumed_by: &["chio-weights"],
};

pub const KERNEL_RESPONSE_CANONICAL_BODY: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-canonical-body",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response canonical body.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-CANONICAL-BODY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_CANONICAL_ENCODING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-canonical-encoding",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response canonical encoding.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-CANONICAL-ENCODING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_CANONICAL_IDENTIFIER: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-canonical-identifier",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response canonical identifier.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-CANONICAL-IDENTIFIER",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_CANONICAL_RECEIPT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-canonical-receipt",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response canonical receipt.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-CANONICAL-RECEIPT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_CANONICAL_VALUE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-canonical-value",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response canonical value.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-CANONICAL-VALUE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_DISPATCH_APPROVAL_REQUIREMENT_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-dispatch-approval-requirement-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response dispatch approval requirement mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-DISPATCH-APPROVAL-REQUIREMENT-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_DISPATCH_AUTHORIZATION_OUTSIDE_WINDOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-dispatch-authorization-outside-window",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response dispatch authorization outside window.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-DISPATCH-AUTHORIZATION-OUTSIDE-WINDOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_DISPATCH_CAPABILITY_DIGEST_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-dispatch-capability-digest-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response dispatch capability digest mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-DISPATCH-CAPABILITY-DIGEST-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_DISPATCH_EXECUTION_BINDING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-dispatch-execution-binding",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response dispatch execution binding.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-DISPATCH-EXECUTION-BINDING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_DISPATCH_EXECUTION_MODE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-dispatch-execution-mode",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response dispatch execution mode.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-DISPATCH-EXECUTION-MODE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_DISPATCH_LEASE_OUTSIDE_WINDOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-dispatch-lease-outside-window",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response dispatch lease outside window.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-DISPATCH-LEASE-OUTSIDE-WINDOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_DISPATCH_RESUME_REQUIRES_GOVERNED_APPROVAL: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-dispatch-resume-requires-governed-approval",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response dispatch resume requires governed approval.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-DISPATCH-RESUME-REQUIRES-GOVERNED-APPROVAL",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_DISPATCH_SNAPSHOT_ALREADY_AUTHORIZED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-dispatch-snapshot-already-authorized",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response dispatch snapshot already authorized.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-DISPATCH-SNAPSHOT-ALREADY-AUTHORIZED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_DISPATCH_SNAPSHOT_WITHOUT_EXECUTION_DISPATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-dispatch-snapshot-without-execution-dispatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response dispatch snapshot without execution dispatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-DISPATCH-SNAPSHOT-WITHOUT-EXECUTION-DISPATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_DISPATCH_ZERO_ADMISSION_OPERATION_VERSION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-dispatch-zero-admission-operation-version",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response dispatch zero admission operation version.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-DISPATCH-ZERO-ADMISSION-OPERATION-VERSION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_DISPATCH_ZERO_EXECUTOR_GENERATION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-dispatch-zero-executor-generation",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response dispatch zero executor generation.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-DISPATCH-ZERO-EXECUTOR-GENERATION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_ACTIVE_EVIDENCE_BINDING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-active-evidence-binding",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor active evidence binding.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-ACTIVE-EVIDENCE-BINDING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_ACTIVE_EVIDENCE_ENCODING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-active-evidence-encoding",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor active evidence encoding.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-ACTIVE-EVIDENCE-ENCODING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_ACTIVE_EVIDENCE_MUTATION_BOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-active-evidence-mutation-bound",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor active evidence mutation bound.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-ACTIVE-EVIDENCE-MUTATION-BOUND",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_APPROVAL_REQUIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-approval-required",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor approval required.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-APPROVAL-REQUIRED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_ATTEMPT_OVERFLOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-attempt-overflow",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor attempt overflow.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-ATTEMPT-OVERFLOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_EFFECT_JOURNAL_DECODE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-effect-journal-decode",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor effect journal decode.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-EFFECT-JOURNAL-DECODE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_EFFECT_JOURNAL_ENCODING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-effect-journal-encoding",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor effect journal encoding.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-EFFECT-JOURNAL-ENCODING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_EFFECT_OUTCOME_UNKNOWN: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-effect-outcome-unknown",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor effect outcome unknown.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-EFFECT-OUTCOME-UNKNOWN",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_GENERATION_OVERFLOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-generation-overflow",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor generation overflow.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-GENERATION-OVERFLOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_GENERATION_WIDTH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-generation-width",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor generation width.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-GENERATION-WIDTH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_INVALID_ACTIVE_EVIDENCE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-invalid-active-evidence",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor invalid active evidence.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-INVALID-ACTIVE-EVIDENCE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_INVALID_EFFECT_JOURNAL: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-invalid-effect-journal",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor invalid effect journal.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-INVALID-EFFECT-JOURNAL",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_INVALID_EFFECT_RESULT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-invalid-effect-result",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor invalid effect result.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-INVALID-EFFECT-RESULT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_RECEIPT_LINEAGE_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-receipt-lineage-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor receipt lineage mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-RECEIPT-LINEAGE-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_STALE_LEASE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-stale-lease",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor stale lease.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-STALE-LEASE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_EXECUTOR_WORK_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-executor-work-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response executor work mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-EXECUTOR-WORK-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_AFFECTED_IDS: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-affected-ids",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan affected ids.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-AFFECTED-IDS",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_AFFECTED_SET_HASH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-affected-set-hash",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan affected set hash.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-AFFECTED-SET-HASH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_AFFECTED_SET_HASH_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-affected-set-hash-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan affected set hash mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-AFFECTED-SET-HASH-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_CONTRIBUTION_HASH_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-contribution-hash-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan contribution hash mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-CONTRIBUTION-HASH-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_CONTRIBUTION_NOT_CANONICAL: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-contribution-not-canonical",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan contribution not canonical.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-CONTRIBUTION-NOT-CANONICAL",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_CONTRIBUTION_NOT_JSON: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-contribution-not-json",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan contribution not json.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-CONTRIBUTION-NOT-JSON",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_EFFECT_BOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-effect-bound",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan effect bound.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-EFFECT-BOUND",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_EFFECT_ID_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-effect-id-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan effect id mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-EFFECT-ID-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_EFFECT_ORDINAL_OVERFLOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-effect-ordinal-overflow",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan effect ordinal overflow.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-EFFECT-ORDINAL-OVERFLOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_EXPIRY_OVERFLOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-expiry-overflow",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan expiry overflow.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-EXPIRY-OVERFLOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_FREEZE_ACQUISITION_NOT_EXACT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-freeze-acquisition-not-exact",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan freeze acquisition not exact.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-FREEZE-ACQUISITION-NOT-EXACT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_FREEZE_BINDING_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-freeze-binding-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan freeze binding mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-FREEZE-BINDING-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_FREEZE_CONTRIBUTION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-freeze-contribution",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan freeze contribution.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-FREEZE-CONTRIBUTION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_FREEZE_TARGET_NOT_LINEAGE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-freeze-target-not-lineage",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan freeze target not lineage.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-FREEZE-TARGET-NOT-LINEAGE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_NO_EFFECTS: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-no-effects",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan no effects.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-NO-EFFECTS",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_PLAN_BODY_HASH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-plan-body-hash",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan plan body hash.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-PLAN-BODY-HASH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_PLAN_BODY_HASH_ENCODING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-plan-body-hash-encoding",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan plan body hash encoding.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-PLAN-BODY-HASH-ENCODING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_PLAN_HASH_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-plan-hash-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan plan hash mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-PLAN-HASH-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_TOO_MANY_EFFECTS: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-too-many-effects",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan too many effects.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-TOO-MANY-EFFECTS",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_PLAN_ZERO_TTL: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-plan-zero-ttl",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response plan zero ttl.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-PLAN-ZERO-TTL",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_RECORD_ACTION_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-record-action-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response record action mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-RECORD-ACTION-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_RECORD_BODY_HASH_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-record-body-hash-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response record body hash mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-RECORD-BODY-HASH-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_RECORD_DECODE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-record-decode",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response record decode.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-RECORD-DECODE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_RECORD_DUE_AT_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-record-due-at-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response record due at mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-RECORD-DUE-AT-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_RECORD_EMPTY_MUTATION_LOG: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-record-empty-mutation-log",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response record empty mutation log.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-RECORD-EMPTY-MUTATION-LOG",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_RECORD_GENERATION_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-record-generation-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response record generation mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-RECORD-GENERATION-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_RECORD_LIFECYCLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-record-lifecycle",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response record lifecycle.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-RECORD-LIFECYCLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_RECORD_MISSING_APPLYING_LEASE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-record-missing-applying-lease",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response record missing applying lease.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-RECORD-MISSING-APPLYING-LEASE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_RECORD_NOT_CANONICAL: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-record-not-canonical",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response record not canonical.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-RECORD-NOT-CANONICAL",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_RECORD_STATE_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-record-state-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response record state mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-RECORD-STATE-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_RECORD_TENANT_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-record-tenant-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response record tenant mismatch.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-RECORD-TENANT-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_RECORD_ZERO_MUTATION_GENERATION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-record-zero-mutation-generation",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response record zero mutation generation.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-RECORD-ZERO-MUTATION-GENERATION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_STATE_GENERATION_OVERFLOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-state-generation-overflow",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response state generation overflow.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-STATE-GENERATION-OVERFLOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_STATE_INCOMPLETE_APPLICATION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-state-incomplete-application",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response state incomplete application.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-STATE-INCOMPLETE-APPLICATION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_STATE_INVALID_EFFECT_LIFECYCLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-state-invalid-effect-lifecycle",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response state invalid effect lifecycle.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-STATE-INVALID-EFFECT-LIFECYCLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_STATE_INVALID_FAILURE_RECORD: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-state-invalid-failure-record",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response state invalid failure record.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-STATE-INVALID-FAILURE-RECORD",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_STATE_INVALID_TIMING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-state-invalid-timing",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response state invalid timing.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-STATE-INVALID-TIMING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_STATE_INVALID_TRANSITION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-state-invalid-transition",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response state invalid transition.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-STATE-INVALID-TRANSITION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_STATE_MUTATION_LIMIT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-state-mutation-limit",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response state mutation limit.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-STATE-MUTATION-LIMIT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_STATE_NOT_DUE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-state-not-due",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response state not due.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-STATE-NOT-DUE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_STATE_SHAPE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-state-shape",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response state shape.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-STATE-SHAPE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_STATE_STALE_GENERATION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-state-stale-generation",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response state stale generation.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-STATE-STALE-GENERATION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_STATE_UNKNOWN_EFFECT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-state-unknown-effect",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response state unknown effect.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-STATE-UNKNOWN-EFFECT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_RESPONSE_STATE_UNRESTORED_EFFECTS: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:response-state-unrestored-effects",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Response refused: response state unrestored effects.",
    help: "Inspect the named rule and durable evidence; never bypass the refusal or widen authority on retry.",
    string_code: "CHIO-KERNEL-RESPONSE-STATE-UNRESTORED-EFFECTS",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-security-types", "chio-quarantine", "chio-control-plane"],
};

pub const KERNEL_CLOCK_UNAVAILABLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:clock-unavailable",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Trusted time refused: clock-unavailable.",
    help: "Restore a trusted nonregressing clock; retain the original authority deadline.",
    string_code: "CHIO-KERNEL-CLOCK-UNAVAILABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-security-types",
        "chio-kernel-core",
        "chio-control-plane",
    ],
};

pub const KERNEL_CLOCK_BEFORE_EPOCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:clock-before-epoch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Trusted time refused: clock-before-epoch.",
    help: "Restore a trusted nonregressing clock; retain the original authority deadline.",
    string_code: "CHIO-KERNEL-CLOCK-BEFORE-EPOCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-security-types",
        "chio-kernel-core",
        "chio-control-plane",
    ],
};

pub const KERNEL_CLOCK_OVERFLOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:clock-overflow",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Trusted time refused: clock-overflow.",
    help: "Restore a trusted nonregressing clock; retain the original authority deadline.",
    string_code: "CHIO-KERNEL-CLOCK-OVERFLOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-security-types",
        "chio-kernel-core",
        "chio-control-plane",
    ],
};

pub const KERNEL_CLOCK_WALL_CLOCK_REGRESSION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:clock-wall-clock-regression",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Trusted time refused: clock-wall-clock-regression.",
    help: "Restore a trusted nonregressing clock; retain the original authority deadline.",
    string_code: "CHIO-KERNEL-CLOCK-WALL-CLOCK-REGRESSION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-security-types",
        "chio-kernel-core",
        "chio-control-plane",
    ],
};

pub const KERNEL_CLOCK_MONOTONIC_REGRESSION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:clock-monotonic-regression",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Trusted time refused: clock-monotonic-regression.",
    help: "Restore a trusted nonregressing clock; retain the original authority deadline.",
    string_code: "CHIO-KERNEL-CLOCK-MONOTONIC-REGRESSION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-security-types",
        "chio-kernel-core",
        "chio-control-plane",
    ],
};

pub const KERNEL_CLOCK_EXPIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:clock-expired",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Trusted time refused: clock-expired.",
    help: "Restore a trusted nonregressing clock; retain the original authority deadline.",
    string_code: "CHIO-KERNEL-CLOCK-EXPIRED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-security-types",
        "chio-kernel-core",
        "chio-control-plane",
    ],
};

pub const KERNEL_CLOCK_NOT_YET_VALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:clock-not-yet-valid",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Trusted time refused: clock-not-yet-valid.",
    help: "Restore a trusted nonregressing clock; retain the original authority deadline.",
    string_code: "CHIO-KERNEL-CLOCK-NOT-YET-VALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-security-types",
        "chio-kernel-core",
        "chio-control-plane",
    ],
};

pub const KERNEL_CLOCK_INVALID_WINDOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:clock-invalid-window",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Trusted time refused: clock-invalid-window.",
    help: "Restore a trusted nonregressing clock; retain the original authority deadline.",
    string_code: "CHIO-KERNEL-CLOCK-INVALID-WINDOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-security-types",
        "chio-kernel-core",
        "chio-control-plane",
    ],
};

pub const TRANSPORT_RESPONSE_AUTHORITY_FRAME_BOUND: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:response-authority-frame-bound",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The authority envelope exceeds its byte limit.",
    help: "Reject this request; verify the pinned authority context and original signed envelope.",
    string_code: "CHIO-TRANSPORT-RESPONSE-AUTHORITY-FRAME-BOUND",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-control-plane"],
};

pub const TRANSPORT_RESPONSE_AUTHORITY_DECODE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:response-authority-decode",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The authority envelope cannot be decoded.",
    help: "Reject this request; verify the pinned authority context and original signed envelope.",
    string_code: "CHIO-TRANSPORT-RESPONSE-AUTHORITY-DECODE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-control-plane"],
};

pub const TRANSPORT_RESPONSE_AUTHORITY_CANONICAL: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:response-authority-canonical",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The authority envelope is not canonical JSON.",
    help: "Reject this request; verify the pinned authority context and original signed envelope.",
    string_code: "CHIO-TRANSPORT-RESPONSE-AUTHORITY-CANONICAL",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-control-plane"],
};

pub const TRANSPORT_RESPONSE_AUTHORITY_SCHEMA: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:response-authority-schema",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The authority envelope schema is unsupported.",
    help: "Reject this request; verify the pinned authority context and original signed envelope.",
    string_code: "CHIO-TRANSPORT-RESPONSE-AUTHORITY-SCHEMA",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-control-plane"],
};

pub const TRANSPORT_RESPONSE_AUTHORITY_DEPLOYMENT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:response-authority-deployment",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The authority envelope is bound to a different deployment.",
    help: "Reject this request; verify the pinned authority context and original signed envelope.",
    string_code: "CHIO-TRANSPORT-RESPONSE-AUTHORITY-DEPLOYMENT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-control-plane"],
};

pub const TRANSPORT_RESPONSE_AUTHORITY_STORE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:response-authority-store",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The authority envelope is bound to a different store.",
    help: "Reject this request; verify the pinned authority context and original signed envelope.",
    string_code: "CHIO-TRANSPORT-RESPONSE-AUTHORITY-STORE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-control-plane"],
};

pub const TRANSPORT_RESPONSE_AUTHORITY_TIME_OVERFLOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:response-authority-time-overflow",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The authority freshness window overflows.",
    help: "Reject this request; verify the pinned authority context and original signed envelope.",
    string_code: "CHIO-TRANSPORT-RESPONSE-AUTHORITY-TIME-OVERFLOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-control-plane"],
};

pub const TRANSPORT_RESPONSE_AUTHORITY_FRESHNESS: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:response-authority-freshness",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The authority envelope is outside its freshness window.",
    help: "Reject this request; verify the pinned authority context and original signed envelope.",
    string_code: "CHIO-TRANSPORT-RESPONSE-AUTHORITY-FRESHNESS",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-control-plane"],
};

pub const TRANSPORT_RESPONSE_AUTHORITY_CLIENT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:response-authority-client",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The authority envelope names a different client.",
    help: "Reject this request; verify the pinned authority context and original signed envelope.",
    string_code: "CHIO-TRANSPORT-RESPONSE-AUTHORITY-CLIENT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-control-plane"],
};

pub const TRANSPORT_RESPONSE_AUTHORITY_ALGORITHM: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:response-authority-algorithm",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The authority envelope signature algorithm differs from its key.",
    help: "Reject this request; verify the pinned authority context and original signed envelope.",
    string_code: "CHIO-TRANSPORT-RESPONSE-AUTHORITY-ALGORITHM",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-control-plane"],
};

pub const TRANSPORT_RESPONSE_AUTHORITY_SIGNATURE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:response-authority-signature",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The authority envelope signature is invalid.",
    help: "Reject this request; verify the pinned authority context and original signed envelope.",
    string_code: "CHIO-TRANSPORT-RESPONSE-AUTHORITY-SIGNATURE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-control-plane"],
};

pub const ATTEST_SIGNED_JSON_TOO_LARGE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:attest:signed-json-too-large",
    domain: Domain::Attest,
    severity: Severity::Error,
    summary: "Signed JSON exceeds the owning byte bound.",
    help: "Reject the input and check the original signed bytes and authenticated read context.",
    string_code: "CHIO-ATTEST-SIGNED-JSON-TOO-LARGE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-core-types",
        "chio-keyring",
        "chio-secret-broker",
        "chio-manifest",
        "chio-store-sqlite",
        "chio-active-response-authority",
    ],
};

pub const ATTEST_SIGNED_JSON_NOT_UTF8: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:attest:signed-json-not-utf8",
    domain: Domain::Attest,
    severity: Severity::Error,
    summary: "Signed JSON is not UTF-8 text.",
    help: "Reject the input and check the original signed bytes and authenticated read context.",
    string_code: "CHIO-ATTEST-SIGNED-JSON-NOT-UTF8",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-core-types",
        "chio-keyring",
        "chio-secret-broker",
        "chio-manifest",
        "chio-store-sqlite",
        "chio-active-response-authority",
    ],
};

pub const ATTEST_SIGNED_JSON_INVALID_INPUT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:attest:signed-json-invalid-input",
    domain: Domain::Attest,
    severity: Severity::Error,
    summary: "Signed JSON contains duplicate keys or lossy numeric tokens.",
    help: "Reject the input and check the original signed bytes and authenticated read context.",
    string_code: "CHIO-ATTEST-SIGNED-JSON-INVALID-INPUT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-core-types",
        "chio-keyring",
        "chio-secret-broker",
        "chio-manifest",
        "chio-store-sqlite",
        "chio-active-response-authority",
    ],
};

pub const ATTEST_SIGNED_JSON_INVALID_SHAPE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:attest:signed-json-invalid-shape",
    domain: Domain::Attest,
    severity: Severity::Error,
    summary: "Signed JSON does not match the owning record shape.",
    help: "Reject the input and check the original signed bytes and authenticated read context.",
    string_code: "CHIO-ATTEST-SIGNED-JSON-INVALID-SHAPE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-core-types",
        "chio-keyring",
        "chio-secret-broker",
        "chio-manifest",
        "chio-store-sqlite",
        "chio-active-response-authority",
    ],
};

pub const ATTEST_SIGNED_JSON_CANONICALIZATION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:attest:signed-json-canonicalization",
    domain: Domain::Attest,
    severity: Severity::Error,
    summary: "Signed JSON cannot be canonicalized under its numeric contract.",
    help: "Reject the input and check the original signed bytes and authenticated read context.",
    string_code: "CHIO-ATTEST-SIGNED-JSON-CANONICALIZATION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-core-types",
        "chio-keyring",
        "chio-secret-broker",
        "chio-manifest",
        "chio-store-sqlite",
        "chio-active-response-authority",
    ],
};

pub const ATTEST_SIGNED_JSON_NONCANONICAL: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:attest:signed-json-noncanonical",
    domain: Domain::Attest,
    severity: Severity::Error,
    summary: "Signed JSON differs from its required canonical wire encoding.",
    help: "Reject the input and check the original signed bytes and authenticated read context.",
    string_code: "CHIO-ATTEST-SIGNED-JSON-NONCANONICAL",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &[
        "chio-core-types",
        "chio-keyring",
        "chio-secret-broker",
        "chio-manifest",
        "chio-store-sqlite",
        "chio-active-response-authority",
    ],
};

pub const KERNEL_RECEIPT_READ_CONTEXT_MISSING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:receipt-read-context-missing",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Receipt read has no authenticated or local operator context.",
    help: "Reject the input and check the original signed bytes and authenticated read context.",
    string_code: "CHIO-KERNEL-RECEIPT-READ-CONTEXT-MISSING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_RECEIPT_READ_TENANT_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:receipt-read-tenant-invalid",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Receipt read tenant is empty or has surrounding whitespace.",
    help: "Reject the input and check the original signed bytes and authenticated read context.",
    string_code: "CHIO-KERNEL-RECEIPT-READ-TENANT-INVALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_RECEIPT_READ_SCOPE_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:receipt-read-scope-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Receipt query attempts to widen the authenticated tenant scope.",
    help: "Reject the input and check the original signed bytes and authenticated read context.",
    string_code: "CHIO-KERNEL-RECEIPT-READ-SCOPE-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_RECEIPT_READ_QUERY_INVALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:receipt-read-query-invalid",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Receipt read query has invalid cost or currency filters.",
    help: "Reject the input and check the original signed bytes and authenticated read context.",
    string_code: "CHIO-KERNEL-RECEIPT-READ-QUERY-INVALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_RECEIPT_READ_PROJECTION_MISMATCH: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:receipt-read-projection-mismatch",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Receipt tenant projection differs from its signed body.",
    help: "Reject the input and check the original signed bytes and authenticated read context.",
    string_code: "CHIO-KERNEL-RECEIPT-READ-PROJECTION-MISMATCH",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_EXECUTION_NONCE_SCHEMA: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:execution-nonce-schema",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Execution nonce refused: schema.",
    help:
        "Preserve replay custody and present a fresh nonce bound to the exact authorized request.",
    string_code: "CHIO-KERNEL-EXECUTION-NONCE-SCHEMA",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_EXECUTION_NONCE_EXPIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:execution-nonce-expired",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Execution nonce refused: expired.",
    help:
        "Preserve replay custody and present a fresh nonce bound to the exact authorized request.",
    string_code: "CHIO-KERNEL-EXECUTION-NONCE-EXPIRED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_EXECUTION_NONCE_BINDING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:execution-nonce-binding",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Execution nonce refused: binding.",
    help:
        "Preserve replay custody and present a fresh nonce bound to the exact authorized request.",
    string_code: "CHIO-KERNEL-EXECUTION-NONCE-BINDING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_EXECUTION_NONCE_SIGNATURE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:execution-nonce-signature",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Execution nonce refused: signature.",
    help:
        "Preserve replay custody and present a fresh nonce bound to the exact authorized request.",
    string_code: "CHIO-KERNEL-EXECUTION-NONCE-SIGNATURE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_EXECUTION_NONCE_REPLAYED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:execution-nonce-replayed",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Execution nonce refused: replayed.",
    help:
        "Preserve replay custody and present a fresh nonce bound to the exact authorized request.",
    string_code: "CHIO-KERNEL-EXECUTION-NONCE-REPLAYED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_EXECUTION_NONCE_ENCODING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:execution-nonce-encoding",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Execution nonce refused: encoding.",
    help:
        "Preserve replay custody and present a fresh nonce bound to the exact authorized request.",
    string_code: "CHIO-KERNEL-EXECUTION-NONCE-ENCODING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_EXECUTION_NONCE_STORE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:execution-nonce-store",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Execution nonce refused: store.",
    help:
        "Preserve replay custody and present a fresh nonce bound to the exact authorized request.",
    string_code: "CHIO-KERNEL-EXECUTION-NONCE-STORE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_EXECUTION_NONCE_CAPACITY: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:execution-nonce-capacity",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Execution nonce refused: capacity.",
    help:
        "Preserve replay custody and present a fresh nonce bound to the exact authorized request.",
    string_code: "CHIO-KERNEL-EXECUTION-NONCE-CAPACITY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel", "chio-store-sqlite"],
};

pub const KERNEL_EXECUTION_NONCE_WINDOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:execution-nonce-window",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Authority window refused: execution-nonce-window.",
    help: "Obtain fresh evidence within the original signed authority window.",
    string_code: "CHIO-KERNEL-EXECUTION-NONCE-WINDOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_EXECUTION_NONCE_NOT_YET_VALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:execution-nonce-not-yet-valid",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Authority window refused: execution-nonce-not-yet-valid.",
    help: "Obtain fresh evidence within the original signed authority window.",
    string_code: "CHIO-KERNEL-EXECUTION-NONCE-NOT-YET-VALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_REVOCATION_SNAPSHOT_FUTURE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:revocation-snapshot-future",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Authority window refused: revocation-snapshot-future.",
    help: "Obtain fresh evidence within the original signed authority window.",
    string_code: "CHIO-KERNEL-REVOCATION-SNAPSHOT-FUTURE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_REVOCATION_SNAPSHOT_STALE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:revocation-snapshot-stale",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Authority window refused: revocation-snapshot-stale.",
    help: "Obtain fresh evidence within the original signed authority window.",
    string_code: "CHIO-KERNEL-REVOCATION-SNAPSHOT-STALE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_GOVERNED_APPROVAL_LIFETIME: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:governed-approval-lifetime",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Authority window refused: governed-approval-lifetime.",
    help: "Obtain fresh evidence within the original signed authority window.",
    string_code: "CHIO-KERNEL-GOVERNED-APPROVAL-LIFETIME",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_APPROVAL_REPLAY_CAPACITY: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:approval-replay-capacity",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: approval-replay-capacity.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-APPROVAL-REPLAY-CAPACITY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_APPROVAL_REPLAY_EXPIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:approval-replay-expired",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: approval-replay-expired.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-APPROVAL-REPLAY-EXPIRED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_APPROVAL_REPLAY_IDENTITY: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:approval-replay-identity",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: approval-replay-identity.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-APPROVAL-REPLAY-IDENTITY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_APPROVAL_REPLAY_UNAVAILABLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:approval-replay-unavailable",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: approval-replay-unavailable.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-APPROVAL-REPLAY-UNAVAILABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_ACCOUNTING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-accounting",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-accounting.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-ACCOUNTING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_ACTION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-action",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-action.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-ACTION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_CAPABILITY: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-capability",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-capability.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-CAPABILITY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_CAPABILITY_CAPACITY: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-capability-capacity",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-capability-capacity.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-CAPABILITY-CAPACITY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_CAPACITY: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-capacity",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-capacity.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-CAPACITY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_ENCODING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-encoding",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-encoding.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-ENCODING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_EXPIRED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-expired",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-expired.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-EXPIRED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_IDENTITY_CAPACITY: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-identity-capacity",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-identity-capacity.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-IDENTITY-CAPACITY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_IDENTITY_LIMIT: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-identity-limit",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-identity-limit.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-IDENTITY-LIMIT",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_IDENTITY_OVERFLOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-identity-overflow",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-identity-overflow.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-IDENTITY-OVERFLOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_MISSING_CONFIGURATION: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-missing-configuration",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-missing-configuration.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-MISSING-CONFIGURATION",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_MISSING_PROOF: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-missing-proof",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-missing-proof.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-MISSING-PROOF",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_MISSING_STORE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-missing-store",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-missing-store.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-MISSING-STORE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_NOT_YET_VALID: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-not-yet-valid",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-not-yet-valid.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-NOT-YET-VALID",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_REPLAYED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-replayed",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-replayed.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-REPLAYED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_SCHEMA: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-schema",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-schema.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-SCHEMA",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_SENDER: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-sender",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-sender.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-SENDER",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_SERVER: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-server",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-server.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-SERVER",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_SIGNATURE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-signature",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-signature.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-SIGNATURE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_SIGNING: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-signing",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-signing.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-SIGNING",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_TOOL: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-tool",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-tool.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-TOOL",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_UNAVAILABLE: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-unavailable",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-unavailable.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-UNAVAILABLE",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_WINDOW_OVERFLOW: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-window-overflow",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: dpop-window-overflow.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-DPOP-WINDOW-OVERFLOW",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_FINANCIAL_BUDGET_EXCEEDED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:financial-budget-exceeded",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "Security boundary refused: financial-budget-exceeded.",
    help: "Restore the named invariant and present fresh evidence for the exact request.",
    string_code: "CHIO-KERNEL-FINANCIAL-BUDGET-EXCEEDED",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const KERNEL_DPOP_RESERVATION_OWNERSHIP: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:kernel:dpop-reservation-ownership",
    domain: Domain::Kernel,
    severity: Severity::Error,
    summary: "DPoP reservation ownership was not confirmed at commit.",
    help: "Retain the marker and reconcile the original operation before retrying.",
    string_code: "CHIO-KERNEL-DPOP-RESERVATION-OWNERSHIP",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-kernel"],
};

pub const TRANSPORT_TASK_CAPACITY_EXCEEDED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:task-capacity-exceeded",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The bounded deferred-task registry has no available capacity.",
    help: "Wait for pending work to complete or expire before submitting another task.",
    string_code: "CHIO-MCP-TASK-CAPACITY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-mcp-edge", "chio-mcp-adapter"],
};

pub const TRANSPORT_STREAM_CAPACITY_EXCEEDED: ErrorCodeSpec = ErrorCodeSpec {
    urn: "urn:chio:error:transport:stream-capacity-exceeded",
    domain: Domain::Transport,
    severity: Severity::Error,
    summary: "The provider stream exceeded its bounded frame count.",
    help: "Use a bounded response or split the operation before retrying.",
    string_code: "CHIO-PROVIDER-STREAM-CAPACITY",
    jsonrpc_code: None,
    since: "0.1.0",
    stability: "stable",
    consumed_by: &["chio-provider-adapter-core", "chio-openai-adapter"],
};

pub static ERROR_CODES: &[ErrorCodeSpec] = &[
    TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
    TRANSACTION_PASSPORT_HASH_MISMATCH,
    TRANSACTION_GRAPH_NOT_CLOSED,
    TRANSACTION_GRAPH_CYCLE,
    TRANSACTION_REQUIRED_CLAIM_MISSING,
    TRANSACTION_ARTIFACT_HASH_MISMATCH,
    TRANSACTION_IDENTITY_NOT_BOUND,
    TRANSACTION_AUTHORIZATION_NOT_BOUND,
    TRANSACTION_RECEIPT_UNCHECKPOINTED,
    TRANSACTION_RUNTIME_PROOF_REJECTED,
    TRANSACTION_BUYER_REVIEW_REJECTED,
    TRANSACTION_SETTLEMENT_UNVERIFIED,
    TRANSACTION_DISPUTE_UNBOUND,
    TRANSACTION_TRANSPARENCY_PREVIEW_NOT_ALLOWED,
    CAPABILITY_SCOPE_EXCEEDED,
    CAPABILITY_EXPIRED,
    CAPABILITY_REVOKED,
    CAPABILITY_NOT_YET_VALID,
    CAPABILITY_SUBJECT_MISMATCH,
    CAPABILITY_SIGNATURE_INVALID,
    POLICY_DECISION_DENIED,
    POLICY_COMPILE_FAILED,
    POLICY_CONSTRAINT_INVALID,
    POLICY_GOVERNANCE_DENIED,
    GUARD_DENIED,
    GUARD_INPUT_REDACTED,
    GUARD_OUTPUT_REDACTED,
    GUARD_WASM_TRAP,
    ATTEST_RECEIPT_SIGNING_FAILED,
    ATTEST_QUOTE_VERIFICATION_FAILED,
    ATTEST_PROVENANCE_MISSING,
    REPLAY_TRACE_NOT_FOUND,
    REPLAY_DETERMINISTIC_MISMATCH,
    REPLAY_FIXTURE_DRIFT,
    PROVIDER_TOOL_SERVER_ERROR,
    PROVIDER_OPENAI,
    PROVIDER_ANTHROPIC,
    PROVIDER_BEDROCK,
    MANIFEST_SCHEMA_INVALID,
    MANIFEST_SIGNATURE_INVALID,
    MANIFEST_TOOL_NOT_REGISTERED,
    MANIFEST_RESOURCE_ROOT_DENIED,
    KERNEL_INTERNAL_ERROR,
    KERNEL_RUNTIME_ADMISSION_READINESS_TIMEOUT,
    KERNEL_SESSION_NOT_INITIALIZED,
    KERNEL_SESSION_ALREADY_EXISTS,
    KERNEL_REQUEST_INCOMPLETE,
    KERNEL_REQUEST_CANCELLED,
    KERNEL_BUDGET_EXHAUSTED,
    KERNEL_BUDGET_AUTHORIZE_REPLAY,
    KERNEL_DELIVERY_CONTRACT_UNSUPPORTED_CARRIER,
    KERNEL_DELIVERY_CONTRACT_DIGEST_MISMATCH,
    KERNEL_FINDING_PURCHASE_UNSUPPORTED_ADMISSION,
    KERNEL_FINDING_PURCHASE_CONTEXT_INVALID,
    KERNEL_FINDING_DELIVERY_MEDIA_TYPE_MISMATCH,
    TRANSPORT_PROTOCOL_VERSION_UNSUPPORTED,
    TRANSPORT_INVALID_REQUEST_SHAPE,
    TRANSPORT_AUTH_MISSING_OR_INVALID,
    TRANSPORT_HTTP_FAILED,
    TRANSPORT_DPOP_VERIFICATION_FAILED,
    TRANSPORT_UPSTREAM_FAILURE,
    TRANSPORT_METHOD_NOT_FOUND,
    CLI_IO,
    CLI_JSON,
    CLI_YAML,
    CLI_SQLITE,
    CLI_OTHER,
    CLI_DOCTOR_TOOLCHAIN_MISMATCH,
    CLI_DOCTOR_OCI_UNREACHABLE,
    CLI_DOCTOR_COSIGN_STALE,
    CLI_DOCTOR_OTEL_UNRESOLVED,
    CLI_DOCTOR_CHIO_YAML_INVALID,
    CLI_DOCTOR_PROBE_FAILED,
    DELEGATION_CHAIN_REVOKED,
    ADVERSARIAL_ESCAPE_DETECTED,
    THREAT_COVERAGE_GAP,
    ARENA_REPLAY_DIVERGENCE,
    ECONOMY_METERING_UNAVAILABLE,
    LINEAGE_ANCESTOR_MISSING,
    CUSTODY_HARDWARE_KEY_UNAVAILABLE,
    CUSTODY_ASSERTION_REJECTED,
    MOBILE_RECEIPT_POST_REJECTED,
    MOBILE_RECEIPT_SCHEMA_INVALID,
    MOBILE_ORACLE_UNREACHABLE,
    CUSTODY_AUDIENCE_MISMATCH,
    CUSTODY_REPLAY_DETECTED,
    CUSTODY_CAPABILITY_EXPIRED,
    CUSTODY_CREDENTIAL_REVOKED,
    CUSTODY_USER_VERIFICATION_REQUIRED,
    CUSTODY_INTERNAL_ENCODING,
    CUSTODY_RATE_LIMITED,
    CUSTODY_MOBILE_CHALLENGE_INVALID,
    CUSTODY_MOBILE_CHALLENGE_REPLAYED,
    CUSTODY_MOBILE_CHALLENGE_STORE_UNAVAILABLE,
    CUSTODY_APP_ATTEST_INVALID_CBOR,
    CUSTODY_APP_ATTEST_INVALID_ROOT,
    CUSTODY_APP_ATTEST_APP_MISMATCH,
    CUSTODY_APP_ATTEST_CHALLENGE_MISMATCH,
    CUSTODY_APP_ATTEST_KEY_MISMATCH,
    CUSTODY_APP_ATTEST_CREDENTIAL_KEY_MISMATCH,
    CUSTODY_APP_ATTEST_COUNTER_ROLLBACK,
    CUSTODY_APP_ATTEST_CERT_CHAIN_INVALID,
    CUSTODY_PLAY_INTEGRITY_INVALID_TOKEN,
    CUSTODY_PLAY_INTEGRITY_NONCE_MISMATCH,
    CUSTODY_PLAY_INTEGRITY_APP_REJECTED,
    CUSTODY_PLAY_INTEGRITY_DEVICE_REJECTED,
    WEIGHTS_MODEL_CARD_MISSING,
    WEIGHTS_CARD_MISMATCH,
    WEIGHTS_SCOPE_NOT_SUBSET,
    WEIGHTS_TOOL_BANNED,
    WEIGHTS_CARD_EXPIRED,
    WEIGHTS_BUNDLE_REJECTED,
    WEIGHTS_SCHEMA_REJECTED,
    WEIGHTS_INTERNAL_ENCODING,
    KERNEL_RESPONSE_CANONICAL_BODY,
    KERNEL_RESPONSE_CANONICAL_ENCODING,
    KERNEL_RESPONSE_CANONICAL_IDENTIFIER,
    KERNEL_RESPONSE_CANONICAL_RECEIPT,
    KERNEL_RESPONSE_CANONICAL_VALUE,
    KERNEL_RESPONSE_DISPATCH_APPROVAL_REQUIREMENT_MISMATCH,
    KERNEL_RESPONSE_DISPATCH_AUTHORIZATION_OUTSIDE_WINDOW,
    KERNEL_RESPONSE_DISPATCH_CAPABILITY_DIGEST_MISMATCH,
    KERNEL_RESPONSE_DISPATCH_EXECUTION_BINDING,
    KERNEL_RESPONSE_DISPATCH_EXECUTION_MODE,
    KERNEL_RESPONSE_DISPATCH_LEASE_OUTSIDE_WINDOW,
    KERNEL_RESPONSE_DISPATCH_RESUME_REQUIRES_GOVERNED_APPROVAL,
    KERNEL_RESPONSE_DISPATCH_SNAPSHOT_ALREADY_AUTHORIZED,
    KERNEL_RESPONSE_DISPATCH_SNAPSHOT_WITHOUT_EXECUTION_DISPATCH,
    KERNEL_RESPONSE_DISPATCH_ZERO_ADMISSION_OPERATION_VERSION,
    KERNEL_RESPONSE_DISPATCH_ZERO_EXECUTOR_GENERATION,
    KERNEL_RESPONSE_EXECUTOR_ACTIVE_EVIDENCE_BINDING,
    KERNEL_RESPONSE_EXECUTOR_ACTIVE_EVIDENCE_ENCODING,
    KERNEL_RESPONSE_EXECUTOR_ACTIVE_EVIDENCE_MUTATION_BOUND,
    KERNEL_RESPONSE_EXECUTOR_APPROVAL_REQUIRED,
    KERNEL_RESPONSE_EXECUTOR_ATTEMPT_OVERFLOW,
    KERNEL_RESPONSE_EXECUTOR_EFFECT_JOURNAL_DECODE,
    KERNEL_RESPONSE_EXECUTOR_EFFECT_JOURNAL_ENCODING,
    KERNEL_RESPONSE_EXECUTOR_EFFECT_OUTCOME_UNKNOWN,
    KERNEL_RESPONSE_EXECUTOR_GENERATION_OVERFLOW,
    KERNEL_RESPONSE_EXECUTOR_GENERATION_WIDTH,
    KERNEL_RESPONSE_EXECUTOR_INVALID_ACTIVE_EVIDENCE,
    KERNEL_RESPONSE_EXECUTOR_INVALID_EFFECT_JOURNAL,
    KERNEL_RESPONSE_EXECUTOR_INVALID_EFFECT_RESULT,
    KERNEL_RESPONSE_EXECUTOR_RECEIPT_LINEAGE_MISMATCH,
    KERNEL_RESPONSE_EXECUTOR_STALE_LEASE,
    KERNEL_RESPONSE_EXECUTOR_WORK_MISMATCH,
    KERNEL_RESPONSE_PLAN_AFFECTED_IDS,
    KERNEL_RESPONSE_PLAN_AFFECTED_SET_HASH,
    KERNEL_RESPONSE_PLAN_AFFECTED_SET_HASH_MISMATCH,
    KERNEL_RESPONSE_PLAN_CONTRIBUTION_HASH_MISMATCH,
    KERNEL_RESPONSE_PLAN_CONTRIBUTION_NOT_CANONICAL,
    KERNEL_RESPONSE_PLAN_CONTRIBUTION_NOT_JSON,
    KERNEL_RESPONSE_PLAN_EFFECT_BOUND,
    KERNEL_RESPONSE_PLAN_EFFECT_ID_MISMATCH,
    KERNEL_RESPONSE_PLAN_EFFECT_ORDINAL_OVERFLOW,
    KERNEL_RESPONSE_PLAN_EXPIRY_OVERFLOW,
    KERNEL_RESPONSE_PLAN_FREEZE_ACQUISITION_NOT_EXACT,
    KERNEL_RESPONSE_PLAN_FREEZE_BINDING_MISMATCH,
    KERNEL_RESPONSE_PLAN_FREEZE_CONTRIBUTION,
    KERNEL_RESPONSE_PLAN_FREEZE_TARGET_NOT_LINEAGE,
    KERNEL_RESPONSE_PLAN_NO_EFFECTS,
    KERNEL_RESPONSE_PLAN_PLAN_BODY_HASH,
    KERNEL_RESPONSE_PLAN_PLAN_BODY_HASH_ENCODING,
    KERNEL_RESPONSE_PLAN_PLAN_HASH_MISMATCH,
    KERNEL_RESPONSE_PLAN_TOO_MANY_EFFECTS,
    KERNEL_RESPONSE_PLAN_ZERO_TTL,
    KERNEL_RESPONSE_RECORD_ACTION_MISMATCH,
    KERNEL_RESPONSE_RECORD_BODY_HASH_MISMATCH,
    KERNEL_RESPONSE_RECORD_DECODE,
    KERNEL_RESPONSE_RECORD_DUE_AT_MISMATCH,
    KERNEL_RESPONSE_RECORD_EMPTY_MUTATION_LOG,
    KERNEL_RESPONSE_RECORD_GENERATION_MISMATCH,
    KERNEL_RESPONSE_RECORD_LIFECYCLE,
    KERNEL_RESPONSE_RECORD_MISSING_APPLYING_LEASE,
    KERNEL_RESPONSE_RECORD_NOT_CANONICAL,
    KERNEL_RESPONSE_RECORD_STATE_MISMATCH,
    KERNEL_RESPONSE_RECORD_TENANT_MISMATCH,
    KERNEL_RESPONSE_RECORD_ZERO_MUTATION_GENERATION,
    KERNEL_RESPONSE_STATE_GENERATION_OVERFLOW,
    KERNEL_RESPONSE_STATE_INCOMPLETE_APPLICATION,
    KERNEL_RESPONSE_STATE_INVALID_EFFECT_LIFECYCLE,
    KERNEL_RESPONSE_STATE_INVALID_FAILURE_RECORD,
    KERNEL_RESPONSE_STATE_INVALID_TIMING,
    KERNEL_RESPONSE_STATE_INVALID_TRANSITION,
    KERNEL_RESPONSE_STATE_MUTATION_LIMIT,
    KERNEL_RESPONSE_STATE_NOT_DUE,
    KERNEL_RESPONSE_STATE_SHAPE,
    KERNEL_RESPONSE_STATE_STALE_GENERATION,
    KERNEL_RESPONSE_STATE_UNKNOWN_EFFECT,
    KERNEL_RESPONSE_STATE_UNRESTORED_EFFECTS,
    KERNEL_CLOCK_UNAVAILABLE,
    KERNEL_CLOCK_BEFORE_EPOCH,
    KERNEL_CLOCK_OVERFLOW,
    KERNEL_CLOCK_WALL_CLOCK_REGRESSION,
    KERNEL_CLOCK_MONOTONIC_REGRESSION,
    KERNEL_CLOCK_EXPIRED,
    KERNEL_CLOCK_NOT_YET_VALID,
    KERNEL_CLOCK_INVALID_WINDOW,
    TRANSPORT_RESPONSE_AUTHORITY_FRAME_BOUND,
    TRANSPORT_RESPONSE_AUTHORITY_DECODE,
    TRANSPORT_RESPONSE_AUTHORITY_CANONICAL,
    TRANSPORT_RESPONSE_AUTHORITY_SCHEMA,
    TRANSPORT_RESPONSE_AUTHORITY_DEPLOYMENT,
    TRANSPORT_RESPONSE_AUTHORITY_STORE,
    TRANSPORT_RESPONSE_AUTHORITY_TIME_OVERFLOW,
    TRANSPORT_RESPONSE_AUTHORITY_FRESHNESS,
    TRANSPORT_RESPONSE_AUTHORITY_CLIENT,
    TRANSPORT_RESPONSE_AUTHORITY_ALGORITHM,
    TRANSPORT_RESPONSE_AUTHORITY_SIGNATURE,
    ATTEST_SIGNED_JSON_TOO_LARGE,
    ATTEST_SIGNED_JSON_NOT_UTF8,
    ATTEST_SIGNED_JSON_INVALID_INPUT,
    ATTEST_SIGNED_JSON_INVALID_SHAPE,
    ATTEST_SIGNED_JSON_CANONICALIZATION,
    ATTEST_SIGNED_JSON_NONCANONICAL,
    KERNEL_RECEIPT_READ_CONTEXT_MISSING,
    KERNEL_RECEIPT_READ_TENANT_INVALID,
    KERNEL_RECEIPT_READ_SCOPE_MISMATCH,
    KERNEL_RECEIPT_READ_QUERY_INVALID,
    KERNEL_RECEIPT_READ_PROJECTION_MISMATCH,
    KERNEL_EXECUTION_NONCE_SCHEMA,
    KERNEL_EXECUTION_NONCE_EXPIRED,
    KERNEL_EXECUTION_NONCE_BINDING,
    KERNEL_EXECUTION_NONCE_SIGNATURE,
    KERNEL_EXECUTION_NONCE_REPLAYED,
    KERNEL_EXECUTION_NONCE_ENCODING,
    KERNEL_EXECUTION_NONCE_STORE,
    KERNEL_EXECUTION_NONCE_CAPACITY,
    KERNEL_EXECUTION_NONCE_WINDOW,
    KERNEL_EXECUTION_NONCE_NOT_YET_VALID,
    KERNEL_REVOCATION_SNAPSHOT_FUTURE,
    KERNEL_REVOCATION_SNAPSHOT_STALE,
    KERNEL_GOVERNED_APPROVAL_LIFETIME,
    KERNEL_APPROVAL_REPLAY_CAPACITY,
    KERNEL_APPROVAL_REPLAY_EXPIRED,
    KERNEL_APPROVAL_REPLAY_IDENTITY,
    KERNEL_APPROVAL_REPLAY_UNAVAILABLE,
    KERNEL_DPOP_ACCOUNTING,
    KERNEL_DPOP_ACTION,
    KERNEL_DPOP_CAPABILITY,
    KERNEL_DPOP_CAPABILITY_CAPACITY,
    KERNEL_DPOP_CAPACITY,
    KERNEL_DPOP_ENCODING,
    KERNEL_DPOP_EXPIRED,
    KERNEL_DPOP_IDENTITY_CAPACITY,
    KERNEL_DPOP_IDENTITY_LIMIT,
    KERNEL_DPOP_IDENTITY_OVERFLOW,
    KERNEL_DPOP_MISSING_CONFIGURATION,
    KERNEL_DPOP_MISSING_PROOF,
    KERNEL_DPOP_MISSING_STORE,
    KERNEL_DPOP_NOT_YET_VALID,
    KERNEL_DPOP_REPLAYED,
    KERNEL_DPOP_SCHEMA,
    KERNEL_DPOP_SENDER,
    KERNEL_DPOP_SERVER,
    KERNEL_DPOP_SIGNATURE,
    KERNEL_DPOP_SIGNING,
    KERNEL_DPOP_TOOL,
    KERNEL_DPOP_UNAVAILABLE,
    KERNEL_DPOP_WINDOW_OVERFLOW,
    KERNEL_FINANCIAL_BUDGET_EXCEEDED,
    KERNEL_DPOP_RESERVATION_OWNERSHIP,
    TRANSPORT_TASK_CAPACITY_EXCEEDED,
    TRANSPORT_STREAM_CAPACITY_EXCEEDED,
];

#[must_use]
pub fn lookup_error_code(urn: &str) -> Option<&'static ErrorCodeSpec> {
    ERROR_CODES.iter().find(|entry| entry.urn == urn)
}

#[must_use]
pub fn lookup_string_code(code: &str) -> Option<&'static ErrorCodeSpec> {
    let mut matches = lookup_string_code_matches(code);
    let first = matches.next()?;
    if matches.next().is_some() {
        None
    } else {
        Some(first)
    }
}

pub fn lookup_string_code_matches(code: &str) -> impl Iterator<Item = &'static ErrorCodeSpec> + '_ {
    ERROR_CODES
        .iter()
        .filter(move |entry| entry.string_code == code)
}

#[must_use]
pub fn lookup_jsonrpc_code(code: i32) -> Option<&'static ErrorCodeSpec> {
    ERROR_CODES
        .iter()
        .find(|entry| entry.jsonrpc_code == Some(code))
}
