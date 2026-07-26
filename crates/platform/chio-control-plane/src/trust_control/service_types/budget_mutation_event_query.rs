use super::*;

pub(crate) const BUDGET_MUTATION_EVENT_QUERY_SCHEMA: &str =
    "chio.budget-mutation-event-query-envelope.v1";
pub(crate) const BUDGET_MUTATION_EVENT_QUERY_PROTOCOL_VERSION: &str =
    "chio.budget-mutation-event-query.v1";
pub(crate) const BUDGET_MUTATION_EVENT_QUERY_SERVICE: &str = "chio.trust-control.budget";
pub(crate) const BUDGET_MUTATION_EVENT_QUERY_NAMESPACE: &str = "budget-mutation-event";
pub(crate) const BUDGET_MUTATION_EVENT_QUERY_MAX_TTL_SECS: u64 = 30;
const BUDGET_MUTATION_EVENT_QUERY_SIGNATURE_DOMAIN: &[u8] =
    b"chio.budget-mutation-event-query-envelope.v1\0";
const BUDGET_MUTATION_EVENT_QUERY_REQUEST_DOMAIN: &[u8] =
    b"chio.budget-mutation-event-query.request.v1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetMutationEventQueryRequest {
    pub(crate) request_nonce: String,
    pub(crate) event_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetMutationEventQueryView {
    pub(crate) service_namespace: String,
    pub(crate) request_digest: String,
    pub(crate) event_id: String,
    pub(crate) current_term: u64,
    pub(crate) leader_id: String,
    pub(crate) last_log_index: u64,
    pub(crate) last_log_term: u64,
    pub(crate) commit_index: u64,
    pub(crate) last_applied: u64,
    pub(crate) applied_state_digest: String,
    pub(crate) read_barrier: AdmissionCommitProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) command_kind: Option<AdmissionCommandKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) entry: Option<AdmissionLogEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) result_commit_proof: Option<AdmissionCommitProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) result_commit_target: Option<AdmissionLogEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) result: Option<AdmissionConsensusResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rejection: Option<CommittedCompositeAuthorizationRejectionView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mutation_event: Option<BudgetMutationEventView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_authority: Option<BudgetAuthorityMetadataView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) budget_commit: Option<BudgetWriteCommitView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetMutationEventReplicaResponseBody {
    pub(crate) protocol_version: String,
    pub(crate) consensus_protocol_version: String,
    pub(crate) service: String,
    pub(crate) membership_digest: String,
    pub(crate) node_id: String,
    pub(crate) request_nonce: String,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) query: BudgetMutationEventQueryView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BudgetMutationEventReplicaResponse {
    pub(crate) schema: String,
    pub(crate) body: BudgetMutationEventReplicaResponseBody,
    pub(crate) signer_public_key: PublicKey,
    pub(crate) algorithm: chio_core::SigningAlgorithm,
    pub(crate) signature: chio_core::Signature,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BudgetMutationEventQuerySigningPayload<'a> {
    schema: &'a str,
    body: &'a BudgetMutationEventReplicaResponseBody,
    signer_public_key: &'a PublicKey,
    algorithm: chio_core::SigningAlgorithm,
}

impl BudgetMutationEventReplicaResponse {
    pub(crate) fn sign(
        body: BudgetMutationEventReplicaResponseBody,
        keypair: &Keypair,
    ) -> Result<Self, String> {
        let signer_public_key = keypair.public_key();
        let algorithm = signer_public_key.algorithm();
        let signing_bytes =
            budget_mutation_event_query_signing_bytes(&body, &signer_public_key, algorithm)?;
        Ok(Self {
            schema: BUDGET_MUTATION_EVENT_QUERY_SCHEMA.to_string(),
            body,
            signer_public_key,
            algorithm,
            signature: keypair.sign(&signing_bytes),
        })
    }

    pub(crate) fn verify_signature(&self, expected_signer: &PublicKey) -> Result<(), String> {
        if self.schema != BUDGET_MUTATION_EVENT_QUERY_SCHEMA
            || &self.signer_public_key != expected_signer
            || self.algorithm != self.signer_public_key.algorithm()
            || self.algorithm != self.signature.algorithm()
        {
            return Err("budget mutation event query signer envelope mismatch".to_string());
        }
        let signing_bytes = budget_mutation_event_query_signing_bytes(
            &self.body,
            &self.signer_public_key,
            self.algorithm,
        )?;
        if !self
            .signer_public_key
            .verify(&signing_bytes, &self.signature)
        {
            return Err("budget mutation event query response signature is invalid".to_string());
        }
        Ok(())
    }
}

pub(crate) fn budget_mutation_event_query_request_digest(
    request: &BudgetMutationEventQueryRequest,
) -> Result<String, String> {
    let canonical = canonical_json_bytes(request).map_err(|error| error.to_string())?;
    let mut preimage =
        Vec::with_capacity(BUDGET_MUTATION_EVENT_QUERY_REQUEST_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(BUDGET_MUTATION_EVENT_QUERY_REQUEST_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn budget_mutation_event_query_signing_bytes(
    body: &BudgetMutationEventReplicaResponseBody,
    signer_public_key: &PublicKey,
    algorithm: chio_core::SigningAlgorithm,
) -> Result<Vec<u8>, String> {
    let payload = BudgetMutationEventQuerySigningPayload {
        schema: BUDGET_MUTATION_EVENT_QUERY_SCHEMA,
        body,
        signer_public_key,
        algorithm,
    };
    let canonical = canonical_json_bytes(&payload).map_err(|error| error.to_string())?;
    let mut bytes =
        Vec::with_capacity(BUDGET_MUTATION_EVENT_QUERY_SIGNATURE_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(BUDGET_MUTATION_EVENT_QUERY_SIGNATURE_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}
