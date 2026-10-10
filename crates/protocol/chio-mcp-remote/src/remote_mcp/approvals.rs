//! Operator-owned approval records. This module never dispatches protected work.
//! Returned artifacts are admitted only by the ordinary kernel tools/call path.
use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedTransactionIntent,
    GovernedTransactionIntentBody,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

#[path = "approvals/records.rs"]
mod records;
#[path = "approvals/redemption.rs"]
mod redemption;
#[path = "approvals/validation.rs"]
mod validation;
use records::load_record;
pub(super) use redemption::{validate_redemption, ApprovalRedemption};

const RECORD_SCHEMA: &str = "chio.mcp.operator-approval.v2";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SubmitRequest {
    session_id: String,
    capability_id: String,
    request_id: String,
    tool_name: String,
    arguments: Value,
    purpose: String,
    #[serde(default = "default_ttl")]
    ttl_seconds: u64,
}

fn default_ttl() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecisionRequest {
    token: GovernedApprovalToken,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalRecord {
    schema: String,
    id: String,
    session_id: String,
    capability_id: String,
    subject: PublicKey,
    policy_fingerprint: String,
    runtime_contract_fingerprint: String,
    request_id: String,
    arguments: Value,
    intent: GovernedTransactionIntent,
    created_at: u64,
    expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision: Option<GovernedApprovalToken>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedRecord {
    record: ApprovalRecord,
    signature: Ed25519Signature,
}

fn failure(status: StatusCode, message: impl ToString) -> Response {
    plain_http_error(status, &message.to_string())
}

fn internal(error: impl ToString) -> Response {
    failure(StatusCode::INTERNAL_SERVER_ERROR, error)
}

fn storage(state: &RemoteAppState, headers: &HeaderMap) -> Result<(Connection, Keypair), Response> {
    super::remote_mcp_admin::validate_admin_request(headers, state.admin_token.as_deref())?;
    // The ordinary admin surface historically defaults to the agent credential.
    // Approval issuance must never inherit that compatibility behavior.
    if state.factory.config.auth_token.as_deref() == state.admin_token.as_deref() {
        return Err(failure(
            StatusCode::CONFLICT,
            "approvals require a distinct operator credential",
        ));
    }
    if state.factory.config.approval.is_none() {
        return Err(failure(
            StatusCode::CONFLICT,
            "explicit approval authority is required",
        ));
    }
    let runtime = state.factory.durable_admission.as_ref().ok_or_else(|| {
        failure(
            StatusCode::CONFLICT,
            "approvals require durable kernel admission",
        )
    })?;
    let path = state
        .factory
        .config
        .session_db_path
        .as_deref()
        .ok_or_else(|| {
            failure(
                StatusCode::CONFLICT,
                "approvals require durable session state",
            )
        })?;
    let connection = open_session_state_db(path).map_err(internal)?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(internal)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(internal)?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS remote_operator_approvals (
            id TEXT PRIMARY KEY NOT NULL,
            session_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            signed_record TEXT NOT NULL,
            UNIQUE(session_id, request_id)
        );",
        )
        .map_err(internal)?;
    Ok((connection, runtime.kernel_keypair()))
}

fn serialize_record(record: ApprovalRecord, signer: &Keypair) -> Result<String, Response> {
    let (signature, _) = signer.sign_canonical(&record).map_err(internal)?;
    serde_json::to_string(&SignedRecord { record, signature }).map_err(internal)
}

fn record_id(session_id: &str, request_id: &str) -> chio_core::error::Result<String> {
    let bytes = canonical_json_bytes(&json!([session_id, request_id]))?;
    Ok(format!("approval-{}", sha256_hex(&bytes)))
}

fn projection(record: &ApprovalRecord) -> Value {
    let status = match record.decision.as_ref().map(|token| token.decision) {
        Some(GovernedApprovalDecision::Approved) => "approved",
        Some(GovernedApprovalDecision::Denied) => "denied",
        None => "pending",
    };
    let mut result =
        json!({"record": record, "status": status, "dispatchPerformedByThisEndpoint": false});
    if let Some(token) = &record.decision {
        // A denied token is useful evidence and still fails kernel admission.
        result["toolCallParams"] = json!({
            "name": record.intent.tool_name,
            "arguments": record.arguments,
            "_meta": {
                "chioRequestId": record.request_id,
                "chioGovernedIntent": record.intent,
                "chioApprovalToken": token,
            },
        });
    }
    result
}

pub(super) async fn submit(
    State(state): State<RemoteAppState>,
    headers: HeaderMap,
    BoundedJson(request): BoundedJson<SubmitRequest>,
) -> Response {
    if let Err(response) =
        super::remote_mcp_admin::validate_admin_request(&headers, state.admin_token.as_deref())
    {
        return response;
    }
    if request.ttl_seconds == 0
        || request.ttl_seconds > 3600
        || !request.arguments.is_object()
        || request.request_id.is_empty()
        || request.request_id.len() > 256
        || request.tool_name.is_empty()
        || request.tool_name.len() > 256
        || request.purpose.is_empty()
        || request.purpose.len() > 4096
    {
        return failure(
            StatusCode::BAD_REQUEST,
            "invalid approval request, arguments, or lifetime",
        );
    }
    let Some(RemoteSessionEntry::Active(session)) =
        resolve_session_entry(&state, &request.session_id).await
    else {
        return failure(StatusCode::NOT_FOUND, "active MCP session required");
    };
    if let Err(response) = validate_session_lifecycle(&session) {
        return response;
    }
    let Some(capability) = session
        .issued_capabilities
        .iter()
        .find(|cap| cap.id == request.capability_id)
    else {
        return failure(
            StatusCode::BAD_REQUEST,
            "capability does not belong to session",
        );
    };
    let now = match state.factory.config.clock.seconds() {
        Ok(now) => now,
        Err(error) => return clock::rejection(error),
    };
    if capability.expires_at <= now {
        return failure(StatusCode::CONFLICT, "capability expired");
    }
    let (connection, signer) = match storage(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let id = match record_id(&request.session_id, &request.request_id) {
        Ok(id) => id,
        Err(error) => return internal(error),
    };
    let intent = GovernedTransactionIntent {
        id: id.clone(),
        server_id: state.factory.config.server_id.clone(),
        tool_name: request.tool_name,
        purpose: request.purpose,
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(json!({"mcpSessionId": request.session_id})),
        body: GovernedTransactionIntentBody::ToolInvocation,
    };
    let invocation = validation::invocation(
        &session,
        capability,
        &request.request_id,
        &request.arguments,
        intent,
    );
    let intent = match state.factory.bind_approval_intent(&session, &invocation) {
        Ok(intent) => intent,
        Err(error) => return failure(StatusCode::CONFLICT, error),
    };
    let Some(expires_at) = now.checked_add(request.ttl_seconds) else {
        return failure(StatusCode::BAD_REQUEST, "approval lifetime overflow");
    };
    let record = ApprovalRecord {
        schema: RECORD_SCHEMA.into(),
        id: id.clone(),
        session_id: request.session_id,
        capability_id: request.capability_id,
        subject: capability.subject.clone(),
        policy_fingerprint: session.policy_fingerprint.clone(),
        runtime_contract_fingerprint: session.runtime_contract_fingerprint.clone(),
        request_id: request.request_id,
        arguments: request.arguments,
        intent,
        created_at: now,
        expires_at: expires_at.min(capability.expires_at),
        decision: None,
    };
    let serialized = match serialize_record(record.clone(), &signer) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match connection.execute("INSERT OR IGNORE INTO remote_operator_approvals (id, session_id, request_id, signed_record) VALUES (?1, ?2, ?3, ?4)",
        params![id, record.session_id, record.request_id, serialized]) {
        Ok(1) => (StatusCode::CREATED, Json(projection(&record))).into_response(),
        Ok(_) => failure(StatusCode::CONFLICT, "session request already has an approval record; retrieve it instead"),
        Err(error) => internal(error),
    }
}

pub(super) async fn get_record(
    State(state): State<RemoteAppState>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let (connection, signer) = match storage(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match load_record(&connection, &id, &signer.public_key()) {
        Ok(record) => Json(projection(&record)).into_response(),
        Err(error) => error.response(),
    }
}

pub(super) async fn decide(
    State(state): State<RemoteAppState>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    BoundedJson(request): BoundedJson<DecisionRequest>,
) -> Response {
    let (mut connection, signer) = match storage(&state, &headers) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // Resolve the live session before taking the SQLite writer transaction.
    // Reload the signed record under that transaction before accepting a decision.
    let pending = match load_record(&connection, &id, &signer.public_key()) {
        Ok(record) => record,
        Err(error) => return error.response(),
    };
    let Some(RemoteSessionEntry::Active(session)) =
        resolve_session_entry(&state, &pending.session_id).await
    else {
        return failure(StatusCode::CONFLICT, "active MCP session required");
    };
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(value) => value,
        Err(error) => return internal(error),
    };
    let mut record = match load_record(&transaction, &id, &signer.public_key()) {
        Ok(value) => value,
        Err(error) => return error.response(),
    };
    let now = match state.factory.config.clock.seconds() {
        Ok(now) => now,
        Err(error) => return clock::rejection(error),
    };
    if let Err(response) = validation::decision(&state, &session, &record, &request.token, now) {
        return response;
    }
    if let Some(existing) = &record.decision {
        return if existing == &request.token {
            Json(projection(&record)).into_response()
        } else {
            failure(StatusCode::CONFLICT, "approval decision is terminal")
        };
    }
    record.decision = Some(request.token);
    let serialized = match serialize_record(record.clone(), &signer) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Err(error) = transaction.execute(
        "UPDATE remote_operator_approvals SET signed_record = ?1 WHERE id = ?2",
        params![serialized, id],
    ) {
        return internal(error);
    }
    if let Err(error) = transaction.commit() {
        return internal(error);
    }
    Json(projection(&record)).into_response()
}
