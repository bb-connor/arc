use super::*;

pub(crate) const COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_PROTOCOL_VERSION: &str =
    "chio.committed-composite-authorization-query.v1";
pub(crate) const COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_SERVICE: &str = "chio.trust-control";
pub(crate) const COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_NAMESPACE: &str =
    "chio.admission-consensus.composite-authorize";
pub(crate) const COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_ENVELOPE_SCHEMA: &str =
    "chio.committed-composite-authorization-query-envelope.v1";
pub(crate) const COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_MAX_TTL_SECS: u64 = 30;
const COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_SIGNATURE_DOMAIN: &[u8] =
    b"chio.committed-composite-authorization-query-envelope.v1\0";

/// Closed wire vocabulary for structured invocation quota ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum BudgetQuotaProfileView {
    #[serde(rename = "chio.grant-invocation.v1")]
    GrantInvocation,
    #[serde(rename = "chio.aggregate-capability-invocation.v1")]
    AggregateCapabilityInvocation,
    #[serde(rename = "chio.aggregate-family-invocation.v1")]
    AggregateFamilyInvocation,
    #[serde(rename = "chio.broker-capability-execution.v1")]
    SupplementalBrokerExecution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetQuotaKeyView {
    pub(crate) profile: BudgetQuotaProfileView,
    pub(crate) owner_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) grant_index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetInvocationQuotaView {
    pub(crate) key: BudgetQuotaKeyView,
    pub(crate) max_invocations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionCaptureInvocationQuotaTransitionView {
    pub(crate) key: BudgetQuotaKeyView,
    pub(crate) max_invocations: u32,
    pub(crate) reserved_invocations_before: u32,
    pub(crate) reserved_invocations_after: u32,
    pub(crate) captured_invocations_before: u32,
    pub(crate) captured_invocations_after: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum AdmissionCaptureInvocationQuotaView {
    Transition(AdmissionCaptureInvocationQuotaTransitionView),
    Definition(BudgetInvocationQuotaView),
}

impl AdmissionCaptureInvocationQuotaView {
    pub(crate) fn quota(&self) -> BudgetInvocationQuotaView {
        match self {
            Self::Transition(transition) => BudgetInvocationQuotaView {
                key: transition.key.clone(),
                max_invocations: transition.max_invocations,
            },
            Self::Definition(quota) => quota.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetInvocationQuotaUsageView {
    pub(crate) quota: BudgetInvocationQuotaView,
    pub(crate) reserved_invocations_after: u32,
    pub(crate) captured_invocations_after: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CanonicalRevocationSetView {
    pub(crate) ids: Vec<String>,
    pub(crate) digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetSupplementalQuotaBindingView {
    pub(crate) artifact_digest: String,
    pub(crate) verifier_id: String,
    pub(crate) request_binding_hash: String,
    pub(crate) negotiated_features_digest: String,
    pub(crate) issuer: chio_core::crypto::PublicKey,
    pub(crate) not_before: u64,
    pub(crate) expires_at: u64,
    pub(crate) request_constraint_digest: String,
    pub(crate) broker_capability_id: String,
    pub(crate) claim_binding_digest: String,
    pub(crate) verified_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetPartitionEscrowEvidenceView {
    pub(crate) canonical_json: String,
    pub(crate) digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetInvocationAdmissionEvidenceView {
    pub(crate) invocation_quotas: Vec<BudgetInvocationQuotaView>,
    pub(crate) revocation_set: CanonicalRevocationSetView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) aggregate_root_capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) aggregate_binding_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) supplemental_binding: Option<BudgetSupplementalQuotaBindingView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) partition_escrow_evidence: Option<BudgetPartitionEscrowEvidenceView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BudgetInvocationReservationStateView {
    Absent,
    Authorized,
    Captured,
    Reversed,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BudgetMonetaryHoldStateView {
    None,
    Exposed,
    Released,
    Reconciled,
    Captured,
    Reversed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CompositeBudgetAuthorizeRequest {
    #[serde(default)]
    pub(crate) existing_only: bool,
    pub(crate) operation_id: String,
    pub(crate) request_binding_hash: String,
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) requested_exposure_units: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_exposure_per_invocation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_total_exposure_units: Option<u64>,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) admission_evidence: BudgetInvocationAdmissionEvidenceView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CompositeBudgetAuthorizeResponse {
    pub(crate) operation_id: String,
    pub(crate) request_binding_hash: String,
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authorized_exposure_units: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) attempted_exposure_units: Option<u64>,
    pub(crate) committed_cost_units_after: u64,
    pub(crate) invocation_count_after: u32,
    pub(crate) invocation_counts_after: Vec<BudgetInvocationQuotaUsageView>,
    pub(crate) invocation_state: BudgetInvocationReservationStateView,
    pub(crate) monetary_state: BudgetMonetaryHoldStateView,
    pub(crate) admission_evidence: BudgetInvocationAdmissionEvidenceView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_commit: Option<BudgetWriteCommitView>,
}

/// One replica's authenticated, read-only view of a committed composite
/// authorization or of its absence at a current-term read barrier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CommittedCompositeAuthorizationQueryView {
    pub(crate) service_namespace: String,
    pub(crate) request_digest: String,
    pub(crate) operation_id: String,
    pub(crate) request_binding_hash: String,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) scoped_operation_id: String,
    pub(crate) current_term: u64,
    pub(crate) leader_id: String,
    pub(crate) last_log_index: u64,
    pub(crate) last_log_term: u64,
    pub(crate) commit_index: u64,
    pub(crate) last_applied: u64,
    pub(crate) applied_state_digest: String,
    pub(crate) read_barrier: AdmissionCommitProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) entry: Option<AdmissionLogEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) result_commit_proof: Option<AdmissionCommitProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) result_commit_target: Option<AdmissionLogEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) result: Option<AdmissionConsensusResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authorization: Option<CompositeBudgetAuthorizeResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rejection: Option<CommittedCompositeAuthorizationRejectionView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CommittedCompositeAuthorizationRejectionView {
    pub(crate) status_code: u16,
    pub(crate) code: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CommittedCompositeAuthorizationRejectionEnvelopeView {
    pub(crate) admission_consensus_rejection: CommittedCompositeAuthorizationRejectionView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CommittedCompositeAuthorizationReplicaQueryRequest {
    pub(crate) request_nonce: String,
    pub(crate) request: CompositeBudgetAuthorizeRequest,
}

/// Node-bound body returned only on the authenticated cluster endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CommittedCompositeAuthorizationReplicaQueryResponseBody {
    pub(crate) protocol_version: String,
    pub(crate) consensus_protocol_version: String,
    pub(crate) service: String,
    pub(crate) membership_digest: String,
    pub(crate) node_id: String,
    pub(crate) request_nonce: String,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) query: CommittedCompositeAuthorizationQueryView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CommittedCompositeAuthorizationReplicaQueryResponse {
    pub(crate) schema: String,
    pub(crate) body: CommittedCompositeAuthorizationReplicaQueryResponseBody,
    pub(crate) signer_public_key: PublicKey,
    pub(crate) algorithm: chio_core::SigningAlgorithm,
    pub(crate) signature: chio_core::Signature,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommittedCompositeAuthorizationReplicaQuerySigningPayload<'a> {
    schema: &'a str,
    body: &'a CommittedCompositeAuthorizationReplicaQueryResponseBody,
    signer_public_key: &'a PublicKey,
    algorithm: chio_core::SigningAlgorithm,
}

impl CommittedCompositeAuthorizationReplicaQueryResponse {
    pub(crate) fn sign(
        body: CommittedCompositeAuthorizationReplicaQueryResponseBody,
        keypair: &Keypair,
    ) -> Result<Self, String> {
        let signer_public_key = keypair.public_key();
        let algorithm = signer_public_key.algorithm();
        let signing_bytes = committed_composite_authorization_query_signing_bytes(
            &body,
            &signer_public_key,
            algorithm,
        )?;
        Ok(Self {
            schema: COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_ENVELOPE_SCHEMA.to_string(),
            body,
            signer_public_key,
            algorithm,
            signature: keypair.sign(&signing_bytes),
        })
    }

    pub(crate) fn verify_signature(&self, expected_signer: &PublicKey) -> Result<(), String> {
        if self.schema != COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_ENVELOPE_SCHEMA
            || &self.signer_public_key != expected_signer
            || self.algorithm != self.signer_public_key.algorithm()
            || self.algorithm != self.signature.algorithm()
        {
            return Err(
                "committed composite authorization query signer envelope mismatch".to_string(),
            );
        }
        let signing_bytes = committed_composite_authorization_query_signing_bytes(
            &self.body,
            &self.signer_public_key,
            self.algorithm,
        )?;
        if !self
            .signer_public_key
            .verify(&signing_bytes, &self.signature)
        {
            return Err(
                "committed composite authorization query response signature is invalid".to_string(),
            );
        }
        Ok(())
    }
}

fn committed_composite_authorization_query_signing_bytes(
    body: &CommittedCompositeAuthorizationReplicaQueryResponseBody,
    signer_public_key: &PublicKey,
    algorithm: chio_core::SigningAlgorithm,
) -> Result<Vec<u8>, String> {
    let payload = CommittedCompositeAuthorizationReplicaQuerySigningPayload {
        schema: COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_ENVELOPE_SCHEMA,
        body,
        signer_public_key,
        algorithm,
    };
    let canonical = canonical_json_bytes(&payload).map_err(|error| error.to_string())?;
    let mut bytes = Vec::with_capacity(
        COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_SIGNATURE_DOMAIN.len() + canonical.len(),
    );
    bytes.extend_from_slice(COMMITTED_COMPOSITE_AUTHORIZATION_QUERY_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureInvocationReservationsRequest {
    pub(crate) operation_id: String,
    pub(crate) request_binding_hash: String,
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_authority: Option<BudgetMutationAuthorityView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureInvocationReservationsResponse {
    pub(crate) operation_id: String,
    pub(crate) request_binding_hash: String,
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) exposure_units: u64,
    pub(crate) realized_spend_units: u64,
    pub(crate) committed_cost_units_after: u64,
    pub(crate) invocation_count_after: u32,
    pub(crate) invocation_counts_after: Vec<BudgetInvocationQuotaUsageView>,
    pub(crate) invocation_state: BudgetInvocationReservationStateView,
    pub(crate) monetary_state: BudgetMonetaryHoldStateView,
    pub(crate) revocation_set: CanonicalRevocationSetView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_commit: Option<BudgetWriteCommitView>,
}

/// Exact, non-mutating lookup for an ordinary invocation capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureInvocationPointQueryRequest {
    pub(crate) capture_request: CaptureInvocationReservationsRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureInvocationPointQueryResponse {
    pub(crate) operation_id: String,
    pub(crate) request_binding_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) capture: Option<CaptureInvocationReservationsResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureInvocationReplicaQueryResponse {
    pub(crate) protocol_version: String,
    pub(crate) membership_digest: String,
    pub(crate) node_id: String,
    pub(crate) query: CaptureInvocationPointQueryResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CombinedAdmissionCaptureRequest {
    pub(crate) operation_id: String,
    pub(crate) request_binding_hash: String,
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_authority: Option<BudgetMutationAuthorityView>,
    pub(crate) revocation_set: CanonicalRevocationSetView,
    pub(crate) bound_revocation_set_digest: String,
    pub(crate) authorization_artifact_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) aggregate_root_capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) aggregate_root_binding_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_observed_revocation_index: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdmissionCaptureOutcomeView {
    Captured,
    DeniedRevoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BudgetGuaranteeLevelView {
    SingleNodeAtomic,
    HaLinearizable,
    PartitionEscrowed,
    AdvisoryPosthoc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionCaptureMetadataView {
    pub(crate) operation_id: String,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) checked_revocation_set_digest: String,
    pub(crate) invocation_quotas: Vec<AdmissionCaptureInvocationQuotaView>,
    pub(crate) authorization_artifact_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) aggregate_root_capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) aggregate_root_binding_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_commit_index: Option<u64>,
    pub(crate) revocation_commit_index: u64,
    pub(crate) authority_commit_index: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) leader_epoch: Option<u64>,
    pub(crate) guarantee_level: BudgetGuaranteeLevelView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) partition_escrow_evidence: Option<BudgetPartitionEscrowEvidenceView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) authority: Option<BudgetMutationAuthorityView>,
    pub(crate) invocation_state: BudgetInvocationReservationStateView,
    pub(crate) monetary_state: BudgetMonetaryHoldStateView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CombinedAdmissionCaptureResponse {
    pub(crate) operation_id: String,
    pub(crate) request_binding_hash: String,
    pub(crate) capability_id: String,
    pub(crate) grant_index: usize,
    pub(crate) hold_id: String,
    pub(crate) event_id: String,
    pub(crate) outcome: AdmissionCaptureOutcomeView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget: Option<CaptureInvocationReservationsResponse>,
    pub(crate) revocation_set: CanonicalRevocationSetView,
    pub(crate) revoked_capability_ids: Vec<String>,
    pub(crate) metadata: AdmissionCaptureMetadataView,
}

/// Exact, non-mutating lookup for a previously committed combined admission
/// capture. The full capture request is retained so a reused operation ID can
/// never be queried under a different request binding or security projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionCapturePointQueryRequest {
    pub(crate) capture_request: CombinedAdmissionCaptureRequest,
}

/// A point-query miss is represented only by an absent capture body. The
/// operation and request-binding identities remain present on every response
/// so clients can reject cross-request response substitution even for misses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionCapturePointQueryResponse {
    pub(crate) operation_id: String,
    pub(crate) request_binding_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) capture: Option<CombinedAdmissionCaptureResponse>,
}

/// Authenticated replica response used to assemble one quorum point read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionCaptureReplicaQueryResponse {
    pub(crate) protocol_version: String,
    pub(crate) membership_digest: String,
    pub(crate) node_id: String,
    pub(crate) query: AdmissionCapturePointQueryResponse,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    fn quota(profile: BudgetQuotaProfileView, owner_id: &str) -> BudgetInvocationQuotaView {
        BudgetInvocationQuotaView {
            key: BudgetQuotaKeyView {
                profile,
                owner_id: owner_id.to_string(),
                grant_index: matches!(profile, BudgetQuotaProfileView::GrantInvocation)
                    .then_some(2),
            },
            max_invocations: 9,
        }
    }

    fn usage(profile: BudgetQuotaProfileView, owner_id: &str) -> BudgetInvocationQuotaUsageView {
        BudgetInvocationQuotaUsageView {
            quota: quota(profile, owner_id),
            reserved_invocations_after: 1,
            captured_invocations_after: 2,
        }
    }

    fn capture_transition(quota: BudgetInvocationQuotaView) -> AdmissionCaptureInvocationQuotaView {
        AdmissionCaptureInvocationQuotaView::Transition(
            AdmissionCaptureInvocationQuotaTransitionView {
                key: quota.key,
                max_invocations: quota.max_invocations,
                reserved_invocations_before: 1,
                reserved_invocations_after: 0,
                captured_invocations_before: 0,
                captured_invocations_after: 1,
            },
        )
    }

    fn revocation_set() -> CanonicalRevocationSetView {
        CanonicalRevocationSetView {
            ids: vec!["cap-leaf".to_string(), "cap-root".to_string()],
            digest: "11".repeat(32),
        }
    }

    fn admission_evidence() -> BudgetInvocationAdmissionEvidenceView {
        BudgetInvocationAdmissionEvidenceView {
            invocation_quotas: vec![
                quota(BudgetQuotaProfileView::GrantInvocation, "cap-leaf"),
                quota(
                    BudgetQuotaProfileView::AggregateFamilyInvocation,
                    &"22".repeat(32),
                ),
                quota(
                    BudgetQuotaProfileView::SupplementalBrokerExecution,
                    &"33".repeat(32),
                ),
            ],
            revocation_set: revocation_set(),
            aggregate_root_capability_id: Some("cap-root".to_string()),
            aggregate_binding_digest: Some("44".repeat(32)),
            supplemental_binding: Some(BudgetSupplementalQuotaBindingView {
                artifact_digest: "55".repeat(32),
                verifier_id: "broker-capability-verifier-v1".to_string(),
                request_binding_hash: "66".repeat(32),
                negotiated_features_digest: "77".repeat(32),
                issuer: chio_core::crypto::Keypair::from_seed(&[81; 32]).public_key(),
                not_before: 90,
                expires_at: 300,
                request_constraint_digest: "88".repeat(32),
                broker_capability_id: "broker-capability-1".to_string(),
                claim_binding_digest: "99".repeat(32),
                verified_at: 100,
            }),
            partition_escrow_evidence: None,
        }
    }

    fn mutation_authority() -> BudgetMutationAuthorityView {
        BudgetMutationAuthorityView {
            authority_id: "https://leader-a.example".to_string(),
            lease_id: "https://leader-a.example#term-7".to_string(),
            lease_epoch: 7,
        }
    }

    fn authority_metadata() -> BudgetAuthorityMetadataView {
        BudgetAuthorityMetadataView {
            authority_id: "https://leader-a.example".to_string(),
            leader_url: "https://leader-a.example".to_string(),
            budget_term: 7,
            lease_id: "https://leader-a.example#term-7".to_string(),
            lease_epoch: 7,
            lease_expires_at: 9_000,
            lease_ttl_ms: 750,
            guarantee_level: "ha_linearizable".to_string(),
            budget_commit_index: Some(42),
            partition_escrow_evidence: None,
        }
    }

    fn budget_commit() -> BudgetWriteCommitView {
        BudgetWriteCommitView {
            budget_seq: 42,
            commit_index: 42,
            quorum_committed: true,
            quorum_size: 2,
            committed_nodes: 2,
            witness_urls: vec![
                "https://leader-a.example".to_string(),
                "https://follower-b.example".to_string(),
            ],
            authority_id: "https://leader-a.example".to_string(),
            budget_term: 7,
            lease_id: "https://leader-a.example#term-7".to_string(),
            lease_epoch: 7,
        }
    }

    fn assert_round_trip<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let encoded = serde_json::to_value(value).test_unwrap();
        let decoded: T = serde_json::from_value(encoded.clone()).test_unwrap();
        let reencoded = serde_json::to_value(decoded).test_unwrap();
        assert_eq!(reencoded, encoded);
    }

    fn assert_unknown_field_rejected<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let mut encoded = serde_json::to_value(value).test_unwrap();
        encoded
            .as_object_mut()
            .test_unwrap()
            .insert("rogueField".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<T>(encoded).is_err());
    }

    #[test]
    fn structured_quota_and_admission_evidence_round_trip_exactly() {
        let evidence = admission_evidence();
        let encoded = serde_json::to_value(&evidence).test_unwrap();

        assert_eq!(
            encoded["invocationQuotas"][0]["key"]["profile"],
            "chio.grant-invocation.v1"
        );
        assert_eq!(encoded["invocationQuotas"][0]["key"]["grantIndex"], 2);
        assert!(encoded["invocationQuotas"][1]["key"]
            .get("grantIndex")
            .is_none());
        assert_eq!(
            encoded["supplementalBinding"]["requestBindingHash"],
            "66".repeat(32)
        );

        assert_round_trip(&evidence);
        assert_unknown_field_rejected(&evidence);
        assert_unknown_field_rejected(&evidence.invocation_quotas[0].key);
        assert_unknown_field_rejected(&evidence.invocation_quotas[0]);
        assert_unknown_field_rejected(&usage(BudgetQuotaProfileView::GrantInvocation, "cap-leaf"));
        assert_unknown_field_rejected(&evidence.revocation_set);
        assert_unknown_field_rejected(evidence.supplemental_binding.as_ref().test_unwrap());

        let mut key = encoded["invocationQuotas"][0]["key"].clone();
        key.as_object_mut()
            .test_unwrap()
            .insert("unknown".to_string(), serde_json::json!(1));
        assert!(serde_json::from_value::<BudgetQuotaKeyView>(key).is_err());
        assert!(
            serde_json::from_value::<BudgetQuotaProfileView>(serde_json::json!("chio.unknown.v1"))
                .is_err()
        );
    }

    #[test]
    fn composite_authorize_contract_round_trips_without_caller_authority() {
        let request = CompositeBudgetAuthorizeRequest {
            existing_only: false,
            operation_id: "operation-42".to_string(),
            request_binding_hash: "44".repeat(32),
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            requested_exposure_units: 120,
            max_exposure_per_invocation: Some(150),
            max_total_exposure_units: Some(900),
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:authorize".to_string(),
            admission_evidence: admission_evidence(),
        };
        let encoded = serde_json::to_value(&request).test_unwrap();
        assert_eq!(encoded["requestedExposureUnits"], 120);
        assert_eq!(encoded["maxExposurePerInvocation"], 150);
        assert_eq!(encoded["maxTotalExposureUnits"], 900);
        assert!(encoded.get("budgetAuthority").is_none());
        assert_round_trip(&request);
        assert_unknown_field_rejected(&request);

        let response = CompositeBudgetAuthorizeResponse {
            operation_id: "operation-42".to_string(),
            request_binding_hash: "44".repeat(32),
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:authorize".to_string(),
            allowed: true,
            authorized_exposure_units: Some(120),
            attempted_exposure_units: None,
            committed_cost_units_after: 120,
            invocation_count_after: 3,
            invocation_counts_after: vec![usage(
                BudgetQuotaProfileView::GrantInvocation,
                "cap-leaf",
            )],
            invocation_state: BudgetInvocationReservationStateView::Authorized,
            monetary_state: BudgetMonetaryHoldStateView::Exposed,
            admission_evidence: admission_evidence(),
            budget_authority: Some(authority_metadata()),
            budget_commit: Some(budget_commit()),
        };
        assert_round_trip(&response);
        assert_unknown_field_rejected(&response);
    }

    #[test]
    fn invocation_capture_contract_is_distinct_from_monetary_capture() {
        let request = CaptureInvocationReservationsRequest {
            operation_id: "operation-42".to_string(),
            request_binding_hash: "44".repeat(32),
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:capture-invocations".to_string(),
            budget_authority: Some(mutation_authority()),
        };
        let encoded = serde_json::to_value(&request).test_unwrap();
        assert_eq!(encoded["eventId"], "hold-42:capture-invocations");
        assert!(encoded.get("authorizedExposureUnits").is_none());
        assert!(encoded.get("realizedSpendUnits").is_none());
        assert_round_trip(&request);
        assert_unknown_field_rejected(&request);

        let response = CaptureInvocationReservationsResponse {
            operation_id: "operation-42".to_string(),
            request_binding_hash: "44".repeat(32),
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:capture-invocations".to_string(),
            exposure_units: 120,
            realized_spend_units: 0,
            committed_cost_units_after: 120,
            invocation_count_after: 3,
            invocation_counts_after: vec![usage(
                BudgetQuotaProfileView::GrantInvocation,
                "cap-leaf",
            )],
            invocation_state: BudgetInvocationReservationStateView::Captured,
            monetary_state: BudgetMonetaryHoldStateView::Exposed,
            revocation_set: revocation_set(),
            budget_authority: Some(authority_metadata()),
            budget_commit: Some(budget_commit()),
        };
        let encoded = serde_json::to_value(&response).test_unwrap();
        assert_eq!(encoded["exposureUnits"], 120);
        assert_eq!(encoded["realizedSpendUnits"], 0);
        assert_round_trip(&response);
        assert_unknown_field_rejected(&response);

        let point_request = CaptureInvocationPointQueryRequest {
            capture_request: request,
        };
        let point_response = CaptureInvocationPointQueryResponse {
            operation_id: "operation-42".to_string(),
            request_binding_hash: "44".repeat(32),
            capture: Some(response),
        };
        let replica_response = CaptureInvocationReplicaQueryResponse {
            protocol_version: "chio.admission-consensus.v1".to_string(),
            membership_digest: "55".repeat(32),
            node_id: "https://node-a.example".to_string(),
            query: point_response.clone(),
        };
        assert_round_trip(&point_request);
        assert_unknown_field_rejected(&point_request);
        assert_round_trip(&point_response);
        assert_unknown_field_rejected(&point_response);
        assert_round_trip(&replica_response);
        assert_unknown_field_rejected(&replica_response);
    }

    #[test]
    fn combined_admission_capture_contract_round_trips_all_commit_evidence() {
        let request = CombinedAdmissionCaptureRequest {
            operation_id: "operation-42".to_string(),
            request_binding_hash: "44".repeat(32),
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:combined-capture".to_string(),
            budget_authority: Some(mutation_authority()),
            revocation_set: revocation_set(),
            bound_revocation_set_digest: "11".repeat(32),
            authorization_artifact_digests: vec!["55".repeat(32)],
            aggregate_root_capability_id: Some("cap-root".to_string()),
            aggregate_root_binding_digest: Some("44".repeat(32)),
            last_observed_revocation_index: Some(40),
        };
        let encoded = serde_json::to_value(&request).test_unwrap();
        assert_eq!(encoded["lastObservedRevocationIndex"], 40);
        assert_eq!(encoded["authorizationArtifactDigests"][0], "55".repeat(32));
        assert_round_trip(&request);
        assert_unknown_field_rejected(&request);

        let metadata = AdmissionCaptureMetadataView {
            operation_id: "operation-42".to_string(),
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:combined-capture".to_string(),
            checked_revocation_set_digest: "11".repeat(32),
            invocation_quotas: admission_evidence()
                .invocation_quotas
                .into_iter()
                .map(capture_transition)
                .collect(),
            authorization_artifact_digests: vec!["55".repeat(32)],
            aggregate_root_capability_id: Some("cap-root".to_string()),
            aggregate_root_binding_digest: Some("44".repeat(32)),
            budget_commit_index: Some(42),
            revocation_commit_index: 42,
            authority_commit_index: 42,
            leader_epoch: Some(7),
            guarantee_level: BudgetGuaranteeLevelView::HaLinearizable,
            partition_escrow_evidence: None,
            authority: Some(mutation_authority()),
            invocation_state: BudgetInvocationReservationStateView::Captured,
            monetary_state: BudgetMonetaryHoldStateView::Exposed,
        };
        assert_round_trip(&metadata);
        assert_unknown_field_rejected(&metadata);
        let response = CombinedAdmissionCaptureResponse {
            operation_id: "operation-42".to_string(),
            request_binding_hash: "44".repeat(32),
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            hold_id: "hold-42".to_string(),
            event_id: "hold-42:combined-capture".to_string(),
            outcome: AdmissionCaptureOutcomeView::Captured,
            budget: Some(CaptureInvocationReservationsResponse {
                operation_id: "operation-42".to_string(),
                request_binding_hash: "44".repeat(32),
                capability_id: "cap-leaf".to_string(),
                grant_index: 2,
                hold_id: "hold-42".to_string(),
                event_id: "hold-42:combined-capture".to_string(),
                exposure_units: 120,
                realized_spend_units: 0,
                committed_cost_units_after: 120,
                invocation_count_after: 3,
                invocation_counts_after: vec![usage(
                    BudgetQuotaProfileView::GrantInvocation,
                    "cap-leaf",
                )],
                invocation_state: BudgetInvocationReservationStateView::Captured,
                monetary_state: BudgetMonetaryHoldStateView::Exposed,
                revocation_set: revocation_set(),
                budget_authority: Some(authority_metadata()),
                budget_commit: Some(budget_commit()),
            }),
            revocation_set: revocation_set(),
            revoked_capability_ids: Vec::new(),
            metadata,
        };
        let encoded = serde_json::to_value(&response).test_unwrap();
        assert_eq!(encoded["outcome"], "captured");
        assert_eq!(encoded["metadata"]["budgetCommitIndex"], 42);
        assert_eq!(encoded["metadata"]["revocationCommitIndex"], 42);
        assert_eq!(encoded["metadata"]["authorityCommitIndex"], 42);
        assert_eq!(encoded["metadata"]["leaderEpoch"], 7);
        assert_eq!(encoded["budget"]["invocationState"], "captured");
        assert_round_trip(&response);
        assert_unknown_field_rejected(&response);

        let point_request = AdmissionCapturePointQueryRequest {
            capture_request: request.clone(),
        };
        assert_round_trip(&point_request);
        assert_unknown_field_rejected(&point_request);
        let point_response = AdmissionCapturePointQueryResponse {
            operation_id: request.operation_id.clone(),
            request_binding_hash: request.request_binding_hash.clone(),
            capture: Some(response.clone()),
        };
        assert_round_trip(&point_response);
        assert_unknown_field_rejected(&point_response);
        let miss = AdmissionCapturePointQueryResponse {
            operation_id: request.operation_id.clone(),
            request_binding_hash: request.request_binding_hash.clone(),
            capture: None,
        };
        let encoded_miss = serde_json::to_value(&miss).test_unwrap();
        assert!(encoded_miss.get("capture").is_none());
        assert_round_trip(&miss);
        assert_unknown_field_rejected(&miss);

        let replica = AdmissionCaptureReplicaQueryResponse {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: "66".repeat(32),
            node_id: "https://node-a.example".to_string(),
            query: point_response,
        };
        assert_round_trip(&replica);
        assert_unknown_field_rejected(&replica);

        let denied = CombinedAdmissionCaptureResponse {
            operation_id: "operation-43".to_string(),
            request_binding_hash: "45".repeat(32),
            capability_id: "cap-leaf".to_string(),
            grant_index: 2,
            hold_id: "hold-43".to_string(),
            event_id: "hold-43:combined-capture".to_string(),
            outcome: AdmissionCaptureOutcomeView::DeniedRevoked,
            budget: None,
            revocation_set: revocation_set(),
            revoked_capability_ids: vec!["cap-root".to_string()],
            metadata: AdmissionCaptureMetadataView {
                operation_id: "operation-43".to_string(),
                hold_id: "hold-43".to_string(),
                event_id: "hold-43:combined-capture".to_string(),
                checked_revocation_set_digest: "11".repeat(32),
                invocation_quotas: admission_evidence()
                    .invocation_quotas
                    .into_iter()
                    .map(AdmissionCaptureInvocationQuotaView::Definition)
                    .collect(),
                authorization_artifact_digests: vec!["55".repeat(32)],
                aggregate_root_capability_id: Some("cap-root".to_string()),
                aggregate_root_binding_digest: Some("44".repeat(32)),
                budget_commit_index: None,
                revocation_commit_index: 43,
                authority_commit_index: 43,
                leader_epoch: Some(7),
                guarantee_level: BudgetGuaranteeLevelView::HaLinearizable,
                partition_escrow_evidence: None,
                authority: Some(mutation_authority()),
                invocation_state: BudgetInvocationReservationStateView::Authorized,
                monetary_state: BudgetMonetaryHoldStateView::Exposed,
            },
        };
        let encoded = serde_json::to_value(&denied).test_unwrap();
        assert_eq!(encoded["outcome"], "denied_revoked");
        assert!(encoded.get("budget").is_none());
        assert_eq!(encoded["revokedCapabilityIds"][0], "cap-root");
        assert_round_trip(&denied);
        assert_unknown_field_rejected(&denied);
    }

    #[test]
    fn dedicated_admission_paths_are_stable() {
        assert_eq!(BUDGET_AUTHORIZE_HOLD_PATH, "/v1/budgets/authorize-hold");
        assert_eq!(
            BUDGET_AUTHORIZE_HOLD_QUERY_PATH,
            "/v1/budgets/authorize-hold/query"
        );
        assert_eq!(
            BUDGET_CAPTURE_INVOCATIONS_PATH,
            "/v1/budgets/capture-invocations"
        );
        assert_eq!(
            BUDGET_CAPTURE_INVOCATIONS_QUERY_PATH,
            "/v1/budgets/capture-invocations/query"
        );
        assert_eq!(ADMISSION_CAPTURE_PATH, "/v1/admissions/capture");
        assert_eq!(ADMISSION_CAPTURE_QUERY_PATH, "/v1/admissions/capture/query");
        assert_eq!(
            INTERNAL_ADMISSION_CAPTURE_QUERY_PATH,
            "/v1/internal/admission-consensus/capture-query"
        );
        assert_eq!(
            INTERNAL_COMPOSITE_AUTHORIZE_QUERY_PATH,
            "/v1/internal/admission-consensus/composite-authorize-query"
        );
        assert_eq!(
            INTERNAL_INVOCATION_CAPTURE_QUERY_PATH,
            "/v1/internal/admission-consensus/invocation-capture-query"
        );
    }
}
