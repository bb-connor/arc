#[derive(Debug, Default, Deserialize)]
struct AdminToolReceiptQuery {
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    tool_server: Option<String>,
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}
#[derive(Debug, Default, Deserialize)]
struct AdminChildReceiptQuery {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    parent_request_id: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    operation_kind: Option<String>,
    #[serde(default)]
    terminal_state: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// `GET /admin/revocations`: a page of entries after `after`, of `kind`
/// when named, or with `capability_id` the check of one capability. Members
/// are parsed by the handler, so every malformed value answers the fixed
/// refusal.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminRevocationQuery {
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    after: Option<String>,
    #[serde(default)]
    limit: Option<String>,
    #[serde(default)]
    kind: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminBudgetQuery {
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// `POST /admin/revocations`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminRevokeRequest {
    target: AdminRevocationTarget,
    reason: chio_core::root_authority::RevocationReason,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AdminRevocationTarget {
    CapabilityId { capability_id: String },
}

#[derive(Clone, Debug, Deserialize)]
struct AuthorizationRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    authorization_details: Option<String>,
    #[serde(default)]
    chio_transaction_context: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    chio_sender_dpop_public_key: Option<String>,
    #[serde(default)]
    chio_sender_mtls_thumbprint_sha256: Option<String>,
    #[serde(default)]
    chio_sender_attestation_sha256: Option<String>,
}

/// The consent form submission. The authorization request itself stays on
/// the server under `consent_nonce`, which the rendered page carries.
#[derive(Debug, Deserialize)]
struct AuthorizationApprovalForm {
    #[serde(default)]
    consent_nonce: Option<String>,
    decision: String,
}

#[derive(Debug, Deserialize)]
struct TokenRequestForm {
    grant_type: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    subject_token: Option<String>,
    #[serde(default)]
    subject_token_type: Option<String>,
}
