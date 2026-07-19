use super::*;

pub(crate) const ADMISSION_CONSENSUS_PROTOCOL_VERSION: &str = "chio.admission-consensus.v3";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdmissionCommandKind {
    LeadershipBarrier,
    IncrementInvocation,
    CompositeAuthorize,
    CaptureInvocations,
    ReverseExposure,
    ReleaseExposure,
    ReconcileSpend,
    CaptureExposure,
    Revoke,
    CombinedCapture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionLogEntry {
    pub(crate) index: u64,
    pub(crate) leader_epoch: u64,
    pub(crate) operation_id: String,
    pub(crate) command_kind: AdmissionCommandKind,
    pub(crate) canonical_command: String,
    pub(crate) command_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionCommitProof {
    pub(crate) protocol_version: String,
    pub(crate) membership_digest: String,
    pub(crate) index: u64,
    pub(crate) leader_epoch: u64,
    pub(crate) current_term_commit_index: u64,
    pub(crate) leader_id: String,
    pub(crate) quorum_size: usize,
    pub(crate) witness_urls: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionRequestVoteRequest {
    pub(crate) protocol_version: String,
    pub(crate) membership_digest: String,
    pub(crate) term: u64,
    pub(crate) candidate_id: String,
    pub(crate) last_log_index: u64,
    pub(crate) last_log_term: u64,
    pub(crate) commit_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionRequestVoteResponse {
    pub(crate) protocol_version: String,
    pub(crate) membership_digest: String,
    pub(crate) term: u64,
    pub(crate) vote_granted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionAppendEntriesRequest {
    pub(crate) protocol_version: String,
    pub(crate) membership_digest: String,
    pub(crate) term: u64,
    pub(crate) leader_id: String,
    pub(crate) previous_log_index: u64,
    pub(crate) previous_log_term: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) entry: Option<AdmissionLogEntry>,
    pub(crate) leader_commit: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) commit_proof: Option<AdmissionCommitProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionAppendEntriesResponse {
    pub(crate) protocol_version: String,
    pub(crate) membership_digest: String,
    pub(crate) term: u64,
    pub(crate) accepted: bool,
    pub(crate) match_index: u64,
    pub(crate) commit_index: u64,
    pub(crate) applied_index: u64,
    pub(crate) applied_state_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rejection: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionConsensusMetaView {
    pub(crate) current_term: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) baseline_state_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) membership_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) voted_for: Option<String>,
    pub(crate) last_log_index: u64,
    pub(crate) last_log_term: u64,
    pub(crate) commit_index: u64,
    pub(crate) last_applied: u64,
    pub(crate) applied_state_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionConsensusResult {
    pub(crate) operation_id: String,
    pub(crate) log_index: u64,
    pub(crate) response_json: String,
    pub(crate) response_digest: String,
    pub(crate) security_projection_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdmissionGenesisValueType {
    Integer,
    Real,
    Text,
    Blob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionGenesisColumn {
    pub(crate) name: String,
    pub(crate) value_type: AdmissionGenesisValueType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub(crate) enum AdmissionGenesisValue {
    Null,
    Integer(i64),
    RealBits(String),
    Text(String),
    BlobHex(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionGenesisTable {
    pub(crate) name: String,
    pub(crate) columns: Vec<AdmissionGenesisColumn>,
    pub(crate) rows: Vec<Vec<AdmissionGenesisValue>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionGenesisProjection {
    pub(crate) tables: Vec<AdmissionGenesisTable>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionProposalRequest {
    pub(crate) operation_id: String,
    pub(crate) command_kind: AdmissionCommandKind,
    pub(crate) command: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionConsensusSnapshot {
    pub(crate) protocol_version: String,
    pub(crate) meta: AdmissionConsensusMetaView,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) genesis_projection: Option<AdmissionGenesisProjection>,
    pub(crate) entries: Vec<AdmissionLogEntry>,
    pub(crate) commit_proofs: Vec<AdmissionCommitProof>,
    pub(crate) results: Vec<AdmissionConsensusResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConsensusCompositeAuthorizeCommand {
    pub(crate) request: CompositeBudgetAuthorizeRequest,
    pub(crate) authority: BudgetMutationAuthorityView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConsensusIncrementInvocationCommand {
    pub(crate) request: TryIncrementBudgetRequest,
    pub(crate) authority: BudgetMutationAuthorityView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConsensusRevocationProposal {
    pub(crate) capability_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConsensusRevocationCommand {
    pub(crate) capability_id: String,
    pub(crate) revoked_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConsensusCombinedCaptureCommand {
    pub(crate) request: CombinedAdmissionCaptureRequest,
    pub(crate) invocation_quotas: Vec<BudgetInvocationQuotaView>,
}
