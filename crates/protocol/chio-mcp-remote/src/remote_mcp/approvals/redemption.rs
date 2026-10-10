//! Retained ordinary operator decisions are required before edge admission.
use super::*;

#[derive(Debug)]
pub(crate) struct ApprovalRedemption {
    database_path: PathBuf,
    policy_path: PathBuf,
    record_key: PublicKey,
    approvers: Vec<PublicKey>,
}

impl ApprovalRedemption {
    pub(crate) fn new(
        config: &RemoteServeHttpConfig,
        record_key: PublicKey,
    ) -> Result<Option<Self>, CliError> {
        let Some(approval) = config.approval.as_ref() else {
            return Ok(None);
        };
        let database_path = config
            .session_db_path
            .clone()
            .ok_or_else(|| denied("configured approvals require retained session storage"))?;
        Ok(Some(Self {
            database_path,
            policy_path: config.policy_path.clone(),
            record_key,
            approvers: approval.approvers.clone(),
        }))
    }

    fn redeem(
        &self,
        session: &RemoteSession,
        params: &Value,
        metadata: &serde_json::Map<String, Value>,
        token: &GovernedApprovalToken,
    ) -> Result<(), CliError> {
        session.ensure_session_store_owned().map_err(denied)?;
        if session.lifecycle_snapshot().state != RemoteSessionState::Ready
            || session.deadline_expired().map_err(denied)?
        {
            return Err(denied("session is not live"));
        }
        let request_id = metadata
            .get("chioRequestId")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 256
                    && value.trim() == *value
                    && !value.chars().any(char::is_control)
            })
            .ok_or_else(|| denied("ordinary approval requires a stable request identity"))?;
        let intent_value = unique_alias(metadata, "governedIntent", "chioGovernedIntent")?
            .ok_or_else(|| denied("ordinary approval requires its retained intent"))?;
        let intent: GovernedTransactionIntent = signed_value(intent_value)?;
        let id = record_id(&session.session_id, request_id).map_err(denied)?;
        let connection = open_session_state_db(&self.database_path).map_err(denied)?;
        let record = records::load_record(&connection, &id, &self.record_key).map_err(denied)?;
        let now = session.clock.seconds().map_err(denied)?;
        let capability = session
            .issued_capabilities
            .iter()
            .find(|capability| {
                capability.id == record.capability_id && capability.subject == record.subject
            })
            .ok_or_else(|| denied("retained capability is not in this session"))?;
        let intent_hash = record.intent.binding_hash().map_err(denied)?;
        if record.schema != RECORD_SCHEMA
            || record.session_id != session.session_id
            || record.request_id != request_id
            || record.policy_fingerprint != session.policy_fingerprint
            || record.runtime_contract_fingerprint != session.runtime_contract_fingerprint
            || record.decision.as_ref() != Some(token)
            || token.decision != GovernedApprovalDecision::Approved
            || token.id != format!("{}-decision", record.id)
            || token.request_id != request_id
            || token.subject != record.subject
            || token.governed_intent_hash != intent_hash
            || token.threshold_proposal_hash.is_some()
            || intent.binding_hash().map_err(denied)? != intent_hash
            || params.get("name").and_then(Value::as_str) != Some(record.intent.tool_name.as_str())
            || params.get("arguments") != Some(&record.arguments)
            || now < record.created_at
            || now >= record.expires_at
            || record.expires_at > capability.expires_at
            || token.issued_at < record.created_at
            || token.expires_at > record.expires_at
            || !token.is_valid_at(now)
            || !self.approvers.contains(&token.approver)
        {
            return Err(denied(
                "token is not the current retained Approved decision for this call",
            ));
        }
        if !token
            .approver
            .verify_canonical_strict(&token.body(), &token.signature)
            .map_err(denied)?
        {
            return Err(denied("approval signature is invalid"));
        }
        let policy = load_policy(&self.policy_path).map_err(denied)?;
        if fingerprint_remote_policy_contract(&policy).map_err(denied)? != record.policy_fingerprint
        {
            return Err(denied("approval policy changed"));
        }
        Ok(())
    }
}

/// Called by the shared session ingress, including native callers. Threshold
/// collections remain under their independent policy and kernel verifier.
pub(crate) fn validate_redemption(
    session: &RemoteSession,
    message: &Value,
) -> Result<(), CliError> {
    if message.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Ok(());
    }
    let params = message
        .get("params")
        .ok_or_else(|| denied("missing tool parameters"))?;
    let Some(metadata) = params.get("_meta") else {
        return Ok(());
    };
    let metadata = metadata
        .as_object()
        .ok_or_else(|| denied("approval metadata must be an object"))?;
    let Some(value) = unique_alias(metadata, "approvalToken", "chioApprovalToken")? else {
        return Ok(());
    };
    let token: GovernedApprovalToken = signed_value(value)?;
    let authority = session
        .approval_redemption
        .as_ref()
        .ok_or_else(|| denied("explicit ordinary approval authority is unavailable"))?;
    authority.redeem(session, params, metadata, &token)
}

fn unique_alias<'a>(
    metadata: &'a serde_json::Map<String, Value>,
    first: &str,
    second: &str,
) -> Result<Option<&'a Value>, CliError> {
    match (metadata.get(first), metadata.get(second)) {
        (Some(_), Some(_)) => Err(denied(
            "ordinary approval metadata contains conflicting aliases",
        )),
        (value, None) | (None, value) => Ok(value),
    }
}

fn signed_value<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, CliError> {
    let bytes = canonical_json_bytes(value).map_err(denied)?;
    decode_json(&bytes, MAX_SESSION_JSON_BYTES).map_err(denied)
}

fn denied(cause: impl std::fmt::Display) -> CliError {
    chio_kernel::KernelError::GovernedTransactionDenied(format!(
        "remote MCP approval redemption: {cause}"
    ))
    .into()
}
