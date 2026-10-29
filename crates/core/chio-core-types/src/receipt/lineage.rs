use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::CanonicalBytes;
use crate::capability::governance::ProvenanceEvidenceClass;
use crate::crypto::{
    canonical_json_bytes, sha256_hex, verify_wrapped, wrapped_verdict, Keypair, PublicKey,
    Signature, SigningBackend,
};
use crate::error::Result;
use crate::schema_binding::ensure_schema_matches;
use crate::session::{
    OperationKind, OperationTerminalState, RequestId, SessionAnchorReference, SessionId,
};
use crate::signer_binding::{
    ensure_backend_matches_embedded_key, ensure_keypair_matches_embedded_key,
    sign_wrapped_for_embedded_key,
};

use super::crypto_floor::{
    ensure_receipt_signature_algorithm_allowed, ReceiptCryptoFloor, ReceiptFloorVerifyError,
};

/// Signing-wrapper schema id of a child-request receipt.
pub const CHIO_CHILD_REQUEST_RECEIPT_SCHEMA: &str = "chio.child-request-receipt.v1";

/// Signed audit record for a nested child request handled under a parent tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRequestReceipt {
    pub id: String,
    pub timestamp: u64,
    pub session_id: SessionId,
    pub parent_request_id: RequestId,
    pub request_id: RequestId,
    pub operation_kind: OperationKind,
    pub terminal_state: OperationTerminalState,
    pub outcome_hash: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub kernel_key: PublicKey,
    pub signature: Signature,
}

/// The body of a child-request receipt (everything except the signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildRequestReceiptBody {
    pub id: String,
    pub timestamp: u64,
    pub session_id: SessionId,
    pub parent_request_id: RequestId,
    pub request_id: RequestId,
    pub operation_kind: OperationKind,
    pub terminal_state: OperationTerminalState,
    pub outcome_hash: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub kernel_key: PublicKey,
}

/// Hybrid logical clock carried by receipts for cross-kernel ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptHybridLogicalClock {
    pub wall_seconds: u64,
    pub logical: u64,
    pub kernel_id: String,
}

impl ReceiptHybridLogicalClock {
    #[must_use]
    pub fn advance_from_parent(
        local_now: u64,
        local_kernel_id: impl Into<String>,
        parent: &Self,
    ) -> Self {
        let wall_seconds = local_now.max(parent.wall_seconds);
        let logical = if wall_seconds == parent.wall_seconds {
            parent.logical.saturating_add(1)
        } else {
            0
        };
        Self {
            wall_seconds,
            logical,
            kernel_id: local_kernel_id.into(),
        }
    }
}

/// Minimal parent descriptor needed to check receipt DAG ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptDagParent {
    pub receipt_id: String,
    pub chain_id: String,
    pub dag_ordinal: u64,
}

/// Canonical sort and dedupe parent receipt IDs before signing.
#[must_use]
pub fn canonical_parent_receipt_ids(mut parent_receipt_ids: Vec<String>) -> Vec<String> {
    parent_receipt_ids.sort();
    parent_receipt_ids.dedup();
    parent_receipt_ids
}

/// Compute `parent_set_hash = H(canonical(sort(parent_receipt_ids)))`.
pub fn parent_set_hash(parent_receipt_ids: &[String]) -> Result<String> {
    let normalized = canonical_parent_receipt_ids(parent_receipt_ids.to_vec());
    parent_set_hash_for_normalized(&normalized)
}

fn parent_set_hash_for_normalized(parent_receipt_ids: &[String]) -> Result<String> {
    let canonical = canonical_json_bytes(&parent_receipt_ids)?;
    Ok(sha256_hex(&canonical))
}

impl ChildRequestReceipt {
    pub fn sign(body: ChildRequestReceiptBody, keypair: &Keypair) -> Result<Self> {
        ensure_keypair_matches_embedded_key(
            &body.kernel_key,
            keypair,
            "child request receipt",
            "kernel_key",
        )?;
        let signature = keypair.sign_wrapped(
            CHIO_CHILD_REQUEST_RECEIPT_SCHEMA,
            &CanonicalBytes::from_serializable(&body)?,
        )?;
        Ok(Self {
            id: body.id,
            timestamp: body.timestamp,
            session_id: body.session_id,
            parent_request_id: body.parent_request_id,
            request_id: body.request_id,
            operation_kind: body.operation_kind,
            terminal_state: body.terminal_state,
            outcome_hash: body.outcome_hash,
            policy_hash: body.policy_hash,
            metadata: body.metadata,
            kernel_key: body.kernel_key,
            signature,
        })
    }

    /// Sign a child-request receipt body with an arbitrary [`SigningBackend`].
    pub fn sign_with_backend(
        body: ChildRequestReceiptBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        ensure_backend_matches_embedded_key(
            &body.kernel_key,
            backend,
            "child request receipt",
            "kernel_key",
        )?;
        let outcome = sign_wrapped_for_embedded_key(
            &body.kernel_key,
            backend,
            CHIO_CHILD_REQUEST_RECEIPT_SCHEMA,
            &CanonicalBytes::from_serializable(&body)?,
        )?;
        Ok(Self {
            id: body.id,
            timestamp: body.timestamp,
            session_id: body.session_id,
            parent_request_id: body.parent_request_id,
            request_id: body.request_id,
            operation_kind: body.operation_kind,
            terminal_state: body.terminal_state,
            outcome_hash: body.outcome_hash,
            policy_hash: body.policy_hash,
            metadata: body.metadata,
            kernel_key: body.kernel_key,
            signature: outcome.signature,
        })
    }

    #[must_use]
    pub fn body(&self) -> ChildRequestReceiptBody {
        ChildRequestReceiptBody {
            id: self.id.clone(),
            timestamp: self.timestamp,
            session_id: self.session_id.clone(),
            parent_request_id: self.parent_request_id.clone(),
            request_id: self.request_id.clone(),
            operation_kind: self.operation_kind,
            terminal_state: self.terminal_state.clone(),
            outcome_hash: self.outcome_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            metadata: self.metadata.clone(),
            kernel_key: self.kernel_key.clone(),
        }
    }

    /// Verify the signature under `pinned`, a key the caller trusts. A carried
    /// signer key that differs from `pinned` is refused before the signature check.
    pub fn verify_signature(&self, pinned: &PublicKey) -> Result<bool> {
        crate::crypto::ensure_pinned_signer(&self.kernel_key, pinned)?;
        self.verify_signature_against(pinned)
    }

    /// Verifies integrity under the embedded key; the caller must bind that key
    /// to a trusted source before acting on the result.
    pub fn verify_integrity_embedded_key(&self) -> Result<bool> {
        self.verify_signature(&self.kernel_key)
    }

    fn verify_signature_against(&self, key: &PublicKey) -> Result<bool> {
        wrapped_verdict(verify_wrapped(
            key,
            CHIO_CHILD_REQUEST_RECEIPT_SCHEMA,
            &self.body(),
            &self.signature,
        ))
    }

    /// Verify the child-request receipt signature against `pinned` and
    /// enforce the configured crypto floor over the pinned key's algorithm.
    pub fn verify_signature_with_floor(
        &self,
        pinned: &PublicKey,
        floor: ReceiptCryptoFloor,
    ) -> core::result::Result<bool, ReceiptFloorVerifyError> {
        crate::crypto::ensure_pinned_signer(&self.kernel_key, pinned)
            .map_err(ReceiptFloorVerifyError::Crypto)?;
        ensure_receipt_signature_algorithm_allowed(
            pinned.algorithm(),
            self.signature.algorithm(),
            floor,
        )?;
        self.verify_signature_against(pinned)
            .map_err(ReceiptFloorVerifyError::Crypto)
    }
}

/// Versioned schema identifier for signed receipt-lineage statements.
pub const CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA: &str = "chio.receipt_lineage_statement.v1";

fn default_receipt_lineage_evidence_class() -> ProvenanceEvidenceClass {
    ProvenanceEvidenceClass::Verified
}

/// Relation type carried by a receipt-lineage statement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptLineageRelationKind {
    LocalChild,
    Continued,
    /// A governed memory-write receipt depends on a verified Finding
    /// delivery receipt. The direction is child write -> parent delivery.
    FindingMemoryWriteToDelivery,
}

/// Signable receipt-lineage statement body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptLineageStatementBody {
    pub schema: String,
    pub id: String,
    pub parent_receipt_id: String,
    pub child_receipt_id: String,
    pub parent_request_id: RequestId,
    pub child_request_id: RequestId,
    pub parent_session_anchor: SessionAnchorReference,
    pub child_session_anchor: SessionAnchorReference,
    pub relation_kind: ReceiptLineageRelationKind,
    #[serde(default = "default_receipt_lineage_evidence_class")]
    pub evidence_class: ProvenanceEvidenceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_token_id: Option<String>,
    pub issued_at: u64,
    pub kernel_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptLineageEndpoints {
    pub parent_receipt_id: String,
    pub child_receipt_id: String,
    pub parent_request_id: RequestId,
    pub child_request_id: RequestId,
    pub parent_session_anchor: SessionAnchorReference,
    pub child_session_anchor: SessionAnchorReference,
}

impl ReceiptLineageEndpoints {
    #[must_use]
    pub fn new(
        parent_receipt_id: impl Into<String>,
        child_receipt_id: impl Into<String>,
        parent_request_id: RequestId,
        child_request_id: RequestId,
        parent_session_anchor: SessionAnchorReference,
        child_session_anchor: SessionAnchorReference,
    ) -> Self {
        Self {
            parent_receipt_id: parent_receipt_id.into(),
            child_receipt_id: child_receipt_id.into(),
            parent_request_id,
            child_request_id,
            parent_session_anchor,
            child_session_anchor,
        }
    }
}

impl ReceiptLineageStatementBody {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        endpoints: ReceiptLineageEndpoints,
        relation_kind: ReceiptLineageRelationKind,
        issued_at: u64,
        kernel_key: PublicKey,
    ) -> Self {
        Self {
            schema: CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
            id: id.into(),
            parent_receipt_id: endpoints.parent_receipt_id,
            child_receipt_id: endpoints.child_receipt_id,
            parent_request_id: endpoints.parent_request_id,
            child_request_id: endpoints.child_request_id,
            parent_session_anchor: endpoints.parent_session_anchor,
            child_session_anchor: endpoints.child_session_anchor,
            relation_kind,
            evidence_class: default_receipt_lineage_evidence_class(),
            continuation_token_id: None,
            issued_at,
            kernel_key,
        }
    }

    #[must_use]
    pub fn with_evidence_class(mut self, evidence_class: ProvenanceEvidenceClass) -> Self {
        self.evidence_class = evidence_class;
        self
    }

    #[must_use]
    pub fn with_continuation_token_id(mut self, continuation_token_id: impl Into<String>) -> Self {
        self.continuation_token_id = Some(continuation_token_id.into());
        self
    }
}

/// Signed linkage statement connecting parent and child receipts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptLineageStatement {
    pub schema: String,
    pub id: String,
    pub parent_receipt_id: String,
    pub child_receipt_id: String,
    pub parent_request_id: RequestId,
    pub child_request_id: RequestId,
    pub parent_session_anchor: SessionAnchorReference,
    pub child_session_anchor: SessionAnchorReference,
    pub relation_kind: ReceiptLineageRelationKind,
    pub evidence_class: ProvenanceEvidenceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_token_id: Option<String>,
    pub issued_at: u64,
    pub kernel_key: PublicKey,
    pub signature: Signature,
}

impl ReceiptLineageStatement {
    pub fn sign(body: ReceiptLineageStatementBody, keypair: &Keypair) -> Result<Self> {
        ensure_schema_matches(
            &body.schema,
            CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
            "receipt lineage statement",
        )?;
        ensure_keypair_matches_embedded_key(
            &body.kernel_key,
            keypair,
            "receipt lineage statement",
            "kernel_key",
        )?;
        let signature = keypair.sign_wrapped(
            CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
            &CanonicalBytes::from_serializable(&body)?,
        )?;
        Ok(Self {
            schema: body.schema,
            id: body.id,
            parent_receipt_id: body.parent_receipt_id,
            child_receipt_id: body.child_receipt_id,
            parent_request_id: body.parent_request_id,
            child_request_id: body.child_request_id,
            parent_session_anchor: body.parent_session_anchor,
            child_session_anchor: body.child_session_anchor,
            relation_kind: body.relation_kind,
            evidence_class: body.evidence_class,
            continuation_token_id: body.continuation_token_id,
            issued_at: body.issued_at,
            kernel_key: body.kernel_key,
            signature,
        })
    }

    #[must_use]
    pub fn body(&self) -> ReceiptLineageStatementBody {
        ReceiptLineageStatementBody {
            schema: self.schema.clone(),
            id: self.id.clone(),
            parent_receipt_id: self.parent_receipt_id.clone(),
            child_receipt_id: self.child_receipt_id.clone(),
            parent_request_id: self.parent_request_id.clone(),
            child_request_id: self.child_request_id.clone(),
            parent_session_anchor: self.parent_session_anchor.clone(),
            child_session_anchor: self.child_session_anchor.clone(),
            relation_kind: self.relation_kind,
            evidence_class: self.evidence_class,
            continuation_token_id: self.continuation_token_id.clone(),
            issued_at: self.issued_at,
            kernel_key: self.kernel_key.clone(),
        }
    }

    /// Verify the signature under `pinned`, a key the caller trusts. A carried
    /// signer key that differs from `pinned` is refused before the signature check.
    pub fn verify_signature(&self, pinned: &PublicKey) -> Result<bool> {
        crate::crypto::ensure_pinned_signer(&self.kernel_key, pinned)?;
        ensure_schema_matches(
            &self.schema,
            CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
            "receipt lineage statement",
        )?;
        wrapped_verdict(verify_wrapped(
            pinned,
            CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
            &self.body(),
            &self.signature,
        ))
    }

    /// Verifies integrity under the embedded key; the caller must bind that key
    /// to a trusted source before acting on the result.
    pub fn verify_integrity_embedded_key(&self) -> Result<bool> {
        self.verify_signature(&self.kernel_key)
    }

    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.evidence_class == ProvenanceEvidenceClass::Verified
    }
}

/// A payload a [`SignedExportEnvelope`] signs, with its signing-wrapper
/// schema id.
pub trait SignedExportPayload: Serialize {
    /// Registered schema id the wrapper binds this payload to.
    const SCHEMA_ID: &'static str;
}

/// Signed envelope for stable export/report artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedExportEnvelope<T> {
    /// Unsigned export payload.
    pub body: T,
    /// Public key that signed the export.
    pub signer_key: PublicKey,
    /// Signature over the signing wrapper of the canonical `body` under
    /// `T::SCHEMA_ID`.
    pub signature: Signature,
}

impl<T> SignedExportEnvelope<T>
where
    T: SignedExportPayload + Clone,
{
    /// Sign an export payload with the provided keypair.
    pub fn sign(body: T, keypair: &Keypair) -> Result<Self> {
        let signature =
            keypair.sign_wrapped(T::SCHEMA_ID, &CanonicalBytes::from_serializable(&body)?)?;
        Ok(Self {
            body,
            signer_key: keypair.public_key(),
            signature,
        })
    }

    /// Sign an export payload through an external or platform signing backend.
    pub fn sign_with_backend(body: T, backend: &dyn SigningBackend) -> Result<Self> {
        let outcome =
            backend.sign_wrapped(T::SCHEMA_ID, &CanonicalBytes::from_serializable(&body)?)?;
        Ok(Self {
            body,
            signer_key: outcome.public_key,
            signature: outcome.signature,
        })
    }

    /// Verify the envelope signature against `pinned`, the key the caller
    /// trusts for this export.
    pub fn verify_signature(&self, pinned: &PublicKey) -> Result<bool> {
        wrapped_verdict(verify_wrapped(
            pinned,
            T::SCHEMA_ID,
            &self.body,
            &self.signature,
        ))
    }
}
