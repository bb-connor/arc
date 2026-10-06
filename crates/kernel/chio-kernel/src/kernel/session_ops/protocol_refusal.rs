//! Session-scoped protocol observations with no admission or execution authority.

use super::*;
use chio_core::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core::receipt::signing::ReceiptSigningHandle;
use serde::Serialize;

/// Host-classified protocol refusal. Peer error text is never a reason source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolRefusalReason {
    CapabilityNotMatched,
    CapabilityMatcherInvalid,
    SessionCredentialToolRestricted,
    SessionCredentialMethodRestricted,
}

impl ProtocolRefusalReason {
    /// Fixed, bounded diagnostic label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityNotMatched => "capability_not_matched",
            Self::CapabilityMatcherInvalid => "capability_matcher_invalid",
            Self::SessionCredentialToolRestricted => "session_credential_tool_restricted",
            Self::SessionCredentialMethodRestricted => "session_credential_method_restricted",
        }
    }
}

/// The bytes available at the trusted protocol ingress boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolRequestDigestSource {
    OriginalWire,
    DecodedJson,
}

/// Hash-only request identity. Fields are sealed and cannot be decoded from
/// caller metadata. In-process callers explicitly lack original wire identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolRequestDigest {
    sha256: String,
    source: ProtocolRequestDigestSource,
}

impl ProtocolRequestDigest {
    pub fn from_wire_bytes(bytes: &[u8]) -> Self {
        Self {
            sha256: sha256_hex(bytes),
            source: ProtocolRequestDigestSource::OriginalWire,
        }
    }

    pub fn from_decoded_json(value: &serde_json::Value) -> Result<Self, KernelError> {
        inspect_decoded_request(value, 0, &mut 0, &mut 0)?;
        let mut writer = DigestWriter {
            state: chio_core::Sha256State::new(),
            bytes: 0,
        };
        serde_json::to_writer(&mut writer, value).map_err(|_| digest_limit_error())?;
        Ok(Self {
            sha256: writer.state.finalize().to_hex(),
            source: ProtocolRequestDigestSource::DecodedJson,
        })
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn source(&self) -> ProtocolRequestDigestSource {
        self.source
    }
}

const MAX_DIGEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIGEST_NODES: usize = 1024 * 1024;
const MAX_DIGEST_DEPTH: usize = 128;

fn digest_limit_error() -> KernelError {
    KernelError::InvalidReceiptMetadata("protocol request exceeds scoped digest limits".into())
}

// Validate the complete tree before entering the recursive serializer. The
// recursive walk itself stops at a fixed depth and every visit consumes budget.
fn inspect_decoded_request(
    value: &serde_json::Value,
    depth: usize,
    nodes: &mut usize,
    text_bytes: &mut usize,
) -> Result<(), KernelError> {
    if depth > MAX_DIGEST_DEPTH {
        return Err(digest_limit_error());
    }
    *nodes = nodes
        .checked_add(1)
        .filter(|nodes| *nodes <= MAX_DIGEST_NODES)
        .ok_or_else(digest_limit_error)?;
    match value {
        serde_json::Value::String(text) => account_digest_text(text_bytes, text.len())?,
        serde_json::Value::Array(values) => {
            for value in values {
                inspect_decoded_request(value, depth + 1, nodes, text_bytes)?;
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                account_digest_text(text_bytes, key.len())?;
                inspect_decoded_request(value, depth + 1, nodes, text_bytes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn account_digest_text(total: &mut usize, length: usize) -> Result<(), KernelError> {
    *total = total
        .checked_add(length)
        .filter(|bytes| *bytes <= MAX_DIGEST_BYTES)
        .ok_or_else(digest_limit_error)?;
    Ok(())
}

struct DigestWriter {
    state: chio_core::Sha256State,
    bytes: usize,
}

impl std::io::Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|bytes| *bytes <= MAX_DIGEST_BYTES)
            .ok_or_else(|| std::io::Error::other("protocol request digest capacity exceeded"))?;
        self.state.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Fixed refusal facts. Identifiers are hashed before retention and the type
/// accepts no capability, financial state, credentials, arguments or raw error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolRefusalSummary {
    reason: ProtocolRefusalReason,
    method_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_sha256: Option<String>,
    request_digest: ProtocolRequestDigest,
}

impl ProtocolRefusalSummary {
    pub fn new(
        reason: ProtocolRefusalReason,
        method: &str,
        target: Option<&str>,
        request_digest: ProtocolRequestDigest,
    ) -> Self {
        Self {
            reason,
            method_sha256: sha256_hex(method.as_bytes()),
            target_sha256: target.map(|target| sha256_hex(target.as_bytes())),
            request_digest,
        }
    }

    pub fn reason(&self) -> ProtocolRefusalReason {
        self.reason
    }

    pub fn request_digest(&self) -> &ProtocolRequestDigest {
        &self.request_digest
    }
}

#[derive(Serialize)]
struct ProtocolRefusalMetadata<'a> {
    schema: &'static str,
    session_id: &'a SessionId,
    agent_id: &'a str,
    session_anchor_id: &'a str,
    auth_epoch: u64,
    request_id_sha256: String,
    #[serde(flatten)]
    summary: &'a ProtocolRefusalSummary,
}

impl ChioKernel {
    /// Persist a protocol refusal for the validated owning session using the
    /// boot receipt authority. This observation does not begin or finish a
    /// request, mint or consume an execution nonce, or settle or release holds.
    /// Success is returned only after the configured persistence contract.
    pub fn record_session_protocol_refusal(
        &self,
        context: &OperationContext,
        summary: &ProtocolRefusalSummary,
    ) -> Result<ChioReceipt, KernelError> {
        let snapshot = self.with_session(&context.session_id, |session| {
            session.validate_context(context)?;
            let snapshot = session.session_anchor_snapshot();
            if let Some(lineage) = session.request_lineage(&context.request_id) {
                if lineage.session_anchor_id != snapshot.session_anchor.id() {
                    return Err(KernelError::ReceiptSigningFailed(
                        "protocol refusal cannot rebind existing request lineage to a different authentication epoch".into(),
                    ));
                }
            }
            Ok(snapshot)
        })?;
        self.ensure_receipt_persistence_ready()?;
        let authority = self.signing_authority.backend.as_ref();
        if !self
            .signing_authority
            .floor
            .allowed_signing_algorithms()
            .contains(&authority.algorithm())
        {
            return Err(KernelError::ReceiptSigningFailed(
                "receipt authority does not satisfy the boot signing floor".into(),
            ));
        }
        let encode_error =
            |error: chio_core::error::Error| KernelError::ReceiptSigningFailed(error.to_string());
        let event = ProtocolRefusalMetadata {
            schema: "chio.session.protocol-refusal.v1",
            session_id: &snapshot.session_id,
            agent_id: &snapshot.agent_id,
            session_anchor_id: snapshot.session_anchor.id(),
            auth_epoch: snapshot.session_anchor.auth_epoch(),
            request_id_sha256: sha256_hex(context.request_id.as_str().as_bytes()),
            summary,
        };
        let content = canonical_json_bytes(&event).map_err(encode_error)?;
        let event = serde_json::to_value(event).map_err(|_| {
            KernelError::ReceiptSigningFailed("protocol refusal encoding failed".into())
        })?;
        let action =
            ToolCallAction::from_parameters(serde_json::to_value(summary).map_err(|_| {
                KernelError::ReceiptSigningFailed("protocol refusal encoding failed".into())
            })?)
            .map_err(encode_error)?;
        let body = ChioReceiptBody {
            id: next_receipt_id("rcpt-protocol-refusal")?,
            timestamp: self.trusted_now_millis()?.as_secs(),
            capability_id: String::new(),
            tool_server: "session".into(),
            tool_name: "protocol/refusal".into(),
            action,
            decision: None,
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: sha256_hex(&content),
            policy_hash: self.config.policy_hash.clone(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({"protocol_refusal": event})),
            trust_level: TrustLevel::Verified,
            tenant_id: extract_tenant_id_from_auth_context(&snapshot.auth_context),
            kernel_key: authority.public_key(),
            bbs_projection_version: None,
        };
        let receipt = chio_kernel_core::sign_receipt_with_handle(
            body,
            authority,
            ReceiptSigningHandle::from_content_preimage(content),
        )
        .map_err(|error| {
            KernelError::ReceiptSigningFailed(format!("protocol refusal signing failed: {error:?}"))
        })?;
        self.record_chio_receipt_without_settlement(&receipt)?;
        Ok(receipt)
    }
}
