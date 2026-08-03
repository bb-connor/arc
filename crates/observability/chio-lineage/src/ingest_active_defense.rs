//! Verified active-defense receipt projection.
//!
//! Active-defense receipts use logical evidence IDs as their causal cursor.
//! This ingest path verifies the signed Chio envelope and its closed body before
//! projecting those logical IDs into the lineage DAG.

use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::receipt::body::{chio_receipt_id, ChioReceipt};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core_types::receipt::security::{
    ActiveDefensePolicyBinding, ActiveDefenseReceiptBody, ActiveDefenseResponseBinding,
};
use serde_json::json;

use crate::schema::{EdgeKind, EvidenceClass, LineageEdge, LineageGraph, LineageNode, NodeKind};

type ActiveDefenseEdgeKey = (String, String, EdgeKind, Option<String>);

/// Active-defense receipt projection failures. Every failure rejects the
/// complete batch so a partially verified causal chain is never returned.
#[derive(Debug, thiserror::Error)]
pub enum ActiveDefenseIngestError {
    #[error("active-defense ingest requires at least one trusted signer")]
    MissingTrustedSigner,
    #[error("active-defense trusted signer identifier is invalid")]
    InvalidTrustedSigner,
    #[error("active-defense receipt signature or signer trust failed")]
    UntrustedReceipt,
    #[error("active-defense receipt envelope binding is invalid")]
    InvalidReceiptBinding,
    #[error("active-defense receipt metadata is missing or malformed")]
    InvalidMetadata,
    #[error("active-defense logical evidence id is bound to conflicting signed receipts")]
    ConflictingEvidence,
    #[error("active-defense receipt time cannot be represented by the lineage schema")]
    InvalidTime,
}

/// Batch projector for native active-defense receipts.
pub struct ActiveDefenseReceiptIngest {
    trusted_signers: BTreeSet<String>,
}

impl ActiveDefenseReceiptIngest {
    pub fn new(trusted_signers: BTreeSet<String>) -> Result<Self, ActiveDefenseIngestError> {
        if trusted_signers.is_empty() {
            return Err(ActiveDefenseIngestError::MissingTrustedSigner);
        }
        if trusted_signers
            .iter()
            .any(|signer| signer.is_empty() || signer.trim() != signer)
        {
            return Err(ActiveDefenseIngestError::InvalidTrustedSigner);
        }
        Ok(Self { trusted_signers })
    }

    /// Verify and project a complete receipt batch.
    pub fn ingest_all(
        &self,
        receipts: &[ChioReceipt],
    ) -> Result<LineageGraph, ActiveDefenseIngestError> {
        let mut graph = LineageGraph::empty();
        let mut evidence_receipts = BTreeMap::<String, String>::new();
        let mut seen_nodes = BTreeSet::<String>::new();
        let mut seen_edges = BTreeSet::<ActiveDefenseEdgeKey>::new();
        let mut verified_receipts = Vec::with_capacity(receipts.len());

        for receipt in receipts {
            let verified = self.verify(receipt)?;
            if evidence_receipts
                .insert(verified.evidence_id.clone(), receipt.id.clone())
                .is_some_and(|existing| existing != receipt.id)
            {
                return Err(ActiveDefenseIngestError::ConflictingEvidence);
            }
            verified_receipts.push(verified);
        }

        for verified in &verified_receipts {
            let current_node_id = receipt_node_id(&verified.evidence_id);
            push_node(
                &mut graph,
                &mut seen_nodes,
                LineageNode {
                    id: current_node_id.clone(),
                    kind: NodeKind::Receipt,
                    evidence_class: EvidenceClass::Verified,
                    tenant_id: Some(verified.body.header().tenant_id.as_str().to_string()),
                    recorded_at: Some(verified.recorded_at),
                    label: Some(verified.body.kind().as_str().to_string()),
                    source_table: Some("active_defense.receipt".to_string()),
                    source_id: Some(verified.receipt.id.clone()),
                },
            );
        }

        let mut projection = ActiveDefenseProjection {
            graph: &mut graph,
            seen_nodes: &mut seen_nodes,
            seen_edges: &mut seen_edges,
        };
        for verified in verified_receipts {
            let current_node_id = receipt_node_id(&verified.evidence_id);
            for prior in verified.body.header().prior_receipt_ids.as_slice() {
                projection.project_parent(ParentReceiptProjection {
                    parent_evidence_id: prior.as_str(),
                    current_node_id: &current_node_id,
                    source_table: "active_defense.prior_receipt",
                    receipt: verified.receipt,
                    body: &verified.body,
                    recorded_at: verified.recorded_at,
                });
            }

            if let Some(response) = response_binding(&verified.body) {
                projection.project_parent(ParentReceiptProjection {
                    parent_evidence_id: response.trigger_finding_receipt_id.as_str(),
                    current_node_id: &current_node_id,
                    source_table: "active_defense.trigger_finding",
                    receipt: verified.receipt,
                    body: &verified.body,
                    recorded_at: verified.recorded_at,
                });
            }
        }

        Ok(graph)
    }

    fn verify<'receipt>(
        &self,
        receipt: &'receipt ChioReceipt,
    ) -> Result<VerifiedActiveDefenseReceipt<'receipt>, ActiveDefenseIngestError> {
        if !self.trusted_signers.contains(&receipt.kernel_key.to_hex())
            || !matches!(receipt.verify_signature(), Ok(true))
            || chio_receipt_id(&receipt.body()).ok().as_deref() != Some(receipt.id.as_str())
            || !matches!(receipt.action.verify_hash(), Ok(true))
        {
            return Err(ActiveDefenseIngestError::UntrustedReceipt);
        }
        let metadata = receipt
            .metadata
            .as_ref()
            .ok_or(ActiveDefenseIngestError::InvalidMetadata)?;
        let body = metadata
            .get("active_defense_body")
            .cloned()
            .ok_or(ActiveDefenseIngestError::InvalidMetadata)
            .and_then(|value| {
                serde_json::from_value::<ActiveDefenseReceiptBody>(value)
                    .map_err(|_| ActiveDefenseIngestError::InvalidMetadata)
            })?;
        let evidence_id = body
            .evidence_id()
            .map_err(|_| ActiveDefenseIngestError::InvalidMetadata)?;
        let body_digest = body
            .body_digest()
            .map_err(|_| ActiveDefenseIngestError::InvalidMetadata)?;
        let expected_action = ToolCallAction::from_parameters(json!({
            "evidence_id": evidence_id.as_str(),
            "kind": body.kind().as_str(),
            "transition_id": body.header().transition_id.as_str(),
        }))
        .map_err(|_| ActiveDefenseIngestError::InvalidMetadata)?;
        let metadata_evidence_id = metadata
            .get("active_defense_evidence_id")
            .and_then(serde_json::Value::as_str);
        let metadata_occurred_at = metadata
            .get("occurred_at_unix_ms")
            .and_then(serde_json::Value::as_u64);
        let expected_metadata = json!({
            "active_defense_body": &body,
            "active_defense_evidence_id": evidence_id.as_str(),
            "occurred_at_unix_ms": body.header().occurred_at_unix_ms,
        });
        let (receipt_kind, boundary_class, observation_outcome, decision, trust_level) =
            expected_semantics(&body);
        if metadata_evidence_id != Some(evidence_id.as_str())
            || metadata_occurred_at != Some(body.header().occurred_at_unix_ms)
            || receipt.capability_id != "chio.active-defense.system"
            || receipt.tool_server != "chio.kernel"
            || receipt.tool_name != body.kind().as_str()
            || receipt.timestamp != body.header().occurred_at_unix_ms / 1_000
            || receipt.tenant_id.as_deref() != Some(body.header().tenant_id.as_str())
            || receipt.content_hash != encode_hex(body_digest.as_bytes())
            || receipt.policy_hash != encode_hex(policy_binding(&body).policy_hash.as_bytes())
            || receipt.action.parameters != expected_action.parameters
            || receipt.action.parameter_hash != expected_action.parameter_hash
            || receipt.receipt_kind != receipt_kind
            || receipt.boundary_class != boundary_class
            || receipt.observation_outcome != observation_outcome
            || receipt.decision != decision
            || receipt.tool_origin != ToolOrigin::ChioInternal
            || receipt.redaction_mode != RedactionMode::Redacted
            || receipt.trust_level != trust_level
            || !receipt.actor_chain.is_empty()
            || !receipt.evidence.is_empty()
            || receipt.bbs_projection_version.is_some()
            || receipt.bbs_signature.is_some()
            || metadata != &expected_metadata
        {
            return Err(ActiveDefenseIngestError::InvalidReceiptBinding);
        }
        let recorded_at = i64::try_from(body.header().occurred_at_unix_ms)
            .map_err(|_| ActiveDefenseIngestError::InvalidTime)?;
        Ok(VerifiedActiveDefenseReceipt {
            body,
            evidence_id: evidence_id.as_str().to_string(),
            recorded_at,
            receipt,
        })
    }
}

fn expected_semantics(
    body: &ActiveDefenseReceiptBody,
) -> (
    ReceiptKind,
    BoundaryClass,
    Option<ObservationOutcome>,
    Option<Decision>,
    TrustLevel,
) {
    match body {
        ActiveDefenseReceiptBody::FlowDenial(_) => (
            ReceiptKind::MediatedDecision,
            BoundaryClass::Prevent,
            None,
            Some(Decision::Deny {
                reason: "active-defense flow policy denied the request".to_string(),
                guard: "chio.flow".to_string(),
            }),
            TrustLevel::Mediated,
        ),
        ActiveDefenseReceiptBody::ResponsePlan(_) => (
            ReceiptKind::AdvisoryEvaluation,
            BoundaryClass::AdvisoryOnly,
            Some(ObservationOutcome::Evaluated),
            None,
            TrustLevel::Advisory,
        ),
        _ => (
            ReceiptKind::TraceObservation,
            BoundaryClass::DetectOnly,
            Some(ObservationOutcome::Observed),
            None,
            TrustLevel::Verified,
        ),
    }
}

fn policy_binding(body: &ActiveDefenseReceiptBody) -> &ActiveDefensePolicyBinding {
    match body {
        ActiveDefenseReceiptBody::FlowDenial(body) => &body.policy,
        ActiveDefenseReceiptBody::DeclassificationConsumption(body) => &body.policy,
        ActiveDefenseReceiptBody::DeclassificationOutcome(body) => &body.policy,
        ActiveDefenseReceiptBody::TripwireObservation(body) => &body.policy,
        ActiveDefenseReceiptBody::CorrelatedFinding(body) => &body.policy,
        ActiveDefenseReceiptBody::ResponsePlan(body) => &body.response.policy,
        ActiveDefenseReceiptBody::ResponseStateTransition(body) => &body.response.policy,
        ActiveDefenseReceiptBody::EffectTransition(body) => &body.response.policy,
        ActiveDefenseReceiptBody::ResponseCompletion(body) => &body.response.policy,
        ActiveDefenseReceiptBody::LiftRollbackCompletion(body) => &body.response.policy,
        ActiveDefenseReceiptBody::DetectorHealth(body) => &body.policy,
        ActiveDefenseReceiptBody::SchedulerHealth(body) => &body.response.policy,
    }
}

struct VerifiedActiveDefenseReceipt<'receipt> {
    body: ActiveDefenseReceiptBody,
    evidence_id: String,
    recorded_at: i64,
    receipt: &'receipt ChioReceipt,
}

fn response_binding(body: &ActiveDefenseReceiptBody) -> Option<&ActiveDefenseResponseBinding> {
    match body {
        ActiveDefenseReceiptBody::ResponsePlan(body) => Some(&body.response),
        ActiveDefenseReceiptBody::ResponseStateTransition(body) => Some(&body.response),
        ActiveDefenseReceiptBody::EffectTransition(body) => Some(&body.response),
        ActiveDefenseReceiptBody::ResponseCompletion(body) => Some(&body.response),
        ActiveDefenseReceiptBody::LiftRollbackCompletion(body) => Some(&body.response),
        ActiveDefenseReceiptBody::SchedulerHealth(body) => Some(&body.response),
        ActiveDefenseReceiptBody::FlowDenial(_)
        | ActiveDefenseReceiptBody::DeclassificationConsumption(_)
        | ActiveDefenseReceiptBody::DeclassificationOutcome(_)
        | ActiveDefenseReceiptBody::TripwireObservation(_)
        | ActiveDefenseReceiptBody::CorrelatedFinding(_)
        | ActiveDefenseReceiptBody::DetectorHealth(_) => None,
    }
}

struct ActiveDefenseProjection<'projection> {
    graph: &'projection mut LineageGraph,
    seen_nodes: &'projection mut BTreeSet<String>,
    seen_edges: &'projection mut BTreeSet<ActiveDefenseEdgeKey>,
}

struct ParentReceiptProjection<'receipt> {
    parent_evidence_id: &'receipt str,
    current_node_id: &'receipt str,
    source_table: &'receipt str,
    receipt: &'receipt ChioReceipt,
    body: &'receipt ActiveDefenseReceiptBody,
    recorded_at: i64,
}

impl ActiveDefenseProjection<'_> {
    fn project_parent(&mut self, parent: ParentReceiptProjection<'_>) {
        let parent_node_id = receipt_node_id(parent.parent_evidence_id);
        push_node(
            self.graph,
            self.seen_nodes,
            LineageNode {
                id: parent_node_id.clone(),
                kind: NodeKind::Receipt,
                evidence_class: EvidenceClass::Observed,
                tenant_id: Some(parent.body.header().tenant_id.as_str().to_string()),
                recorded_at: None,
                label: Some(parent.parent_evidence_id.to_string()),
                source_table: Some(parent.source_table.to_string()),
                source_id: Some(parent.receipt.id.clone()),
            },
        );
        push_edge(
            self.graph,
            self.seen_edges,
            LineageEdge {
                from: parent_node_id,
                to: parent.current_node_id.to_string(),
                kind: EdgeKind::ReceiptLineageParent,
                evidence_class: EvidenceClass::Verified,
                source_table: Some(parent.source_table.to_string()),
                source_id: Some(parent.receipt.id.clone()),
                tenant_id: Some(parent.body.header().tenant_id.as_str().to_string()),
                recorded_at: Some(parent.recorded_at),
            },
        );
    }
}

fn push_node(graph: &mut LineageGraph, seen: &mut BTreeSet<String>, node: LineageNode) {
    if seen.insert(node.id.clone()) {
        graph.nodes.push(node);
    }
}

fn push_edge(
    graph: &mut LineageGraph,
    seen: &mut BTreeSet<ActiveDefenseEdgeKey>,
    edge: LineageEdge,
) {
    let key = (
        edge.from.clone(),
        edge.to.clone(),
        edge.kind,
        edge.source_table.clone(),
    );
    if seen.insert(key) {
        graph.edges.push(edge);
    }
}

fn receipt_node_id(evidence_id: &str) -> String {
    format!("rcpt:{evidence_id}")
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
