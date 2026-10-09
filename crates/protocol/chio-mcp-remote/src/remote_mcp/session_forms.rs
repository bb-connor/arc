use super::*;

#[derive(Debug, Default, Deserialize)]
pub(super) struct AdminToolReceiptQuery {
    #[serde(default)]
    pub(super) capability_id: Option<String>,
    #[serde(default)]
    pub(super) tool_server: Option<String>,
    #[serde(default)]
    pub(super) tool_name: Option<String>,
    #[serde(default)]
    pub(super) decision: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
}
#[derive(Debug, Default, Deserialize)]
pub(super) struct AdminChildReceiptQuery {
    #[serde(default)]
    pub(super) session_id: Option<String>,
    #[serde(default)]
    pub(super) parent_request_id: Option<String>,
    #[serde(default)]
    pub(super) request_id: Option<String>,
    #[serde(default)]
    pub(super) operation_kind: Option<String>,
    #[serde(default)]
    pub(super) terminal_state: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct AdminRevocationQuery {
    #[serde(default)]
    pub(super) capability_id: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct AdminBudgetQuery {
    #[serde(default)]
    pub(super) capability_id: Option<String>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminRevokeCapabilityRequest {
    pub(super) capability_id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct AuthorizationRequest {
    pub(super) response_type: String,
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    #[serde(default)]
    pub(super) state: Option<String>,
    #[serde(default)]
    pub(super) scope: Option<String>,
    #[serde(default)]
    pub(super) resource: Option<String>,
    #[serde(default)]
    pub(super) authorization_details: Option<String>,
    #[serde(default)]
    pub(super) chio_transaction_context: Option<String>,
    #[serde(default)]
    pub(super) code_challenge: Option<String>,
    #[serde(default)]
    pub(super) code_challenge_method: Option<String>,
    #[serde(default)]
    pub(super) chio_sender_dpop_public_key: Option<String>,
    #[serde(default)]
    pub(super) chio_sender_mtls_thumbprint_sha256: Option<String>,
    #[serde(default)]
    pub(super) chio_sender_attestation_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AuthorizationApprovalForm {
    pub(super) response_type: String,
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    #[serde(default)]
    pub(super) state: Option<String>,
    #[serde(default)]
    pub(super) scope: Option<String>,
    #[serde(default)]
    pub(super) resource: Option<String>,
    #[serde(default)]
    pub(super) authorization_details: Option<String>,
    #[serde(default)]
    pub(super) chio_transaction_context: Option<String>,
    pub(super) code_challenge: String,
    pub(super) code_challenge_method: String,
    #[serde(default)]
    pub(super) chio_sender_dpop_public_key: Option<String>,
    #[serde(default)]
    pub(super) chio_sender_mtls_thumbprint_sha256: Option<String>,
    #[serde(default)]
    pub(super) chio_sender_attestation_sha256: Option<String>,
    pub(super) decision: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct TokenRequestForm {
    pub(super) grant_type: String,
    #[serde(default)]
    pub(super) code: Option<String>,
    #[serde(default)]
    pub(super) redirect_uri: Option<String>,
    #[serde(default)]
    pub(super) client_id: Option<String>,
    #[serde(default)]
    pub(super) code_verifier: Option<String>,
    #[serde(default)]
    pub(super) resource: Option<String>,
    #[serde(default)]
    pub(super) scope: Option<String>,
    #[serde(default)]
    pub(super) subject_token: Option<String>,
    #[serde(default)]
    pub(super) subject_token_type: Option<String>,
}
