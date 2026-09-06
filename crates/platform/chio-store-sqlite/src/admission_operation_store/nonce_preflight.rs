//! Permanent ownership of an internal, non-executable budget participant.

use super::*;
use chio_kernel::admission_operation::AdmissionNoncePreflightIdentityV1;

mod record;
pub(super) use record::{verify, verify_issued_cleanup, verify_ownership};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreflightOwnership {
    schema: String,
    operation_id: AdmissionOperationId,
    budget_operation_id: AdmissionIdentifier,
    hold_id: AdmissionIdentifier,
    grant_index: u32,
    authorization_event_id: AdmissionIdentifier,
    authorization_digest: AdmissionDigest,
    recorded_at_unix_ms: u64,
}

pub(super) fn load_identity(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<Option<AdmissionNoncePreflightIdentityV1>, AdmissionOperationStoreError> {
    verify(connection, operation)?
        .map(|(record, _)| {
            AdmissionNoncePreflightIdentityV1::for_operation(operation, record.grant_index)
                .map_err(Into::into)
        })
        .transpose()
}

impl SqliteAdmissionOperationStore {
    pub(super) fn authorize_nonce_preflight(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        request: BudgetAuthorizeHoldRequest,
        now: u64,
    ) -> Result<(BudgetAuthorizeHoldDecision, AdmissionOperationV1), AdmissionCaptureError> {
        if recovery_lease.store_fence() != &self.serving_owner.fence {
            return Err(AdmissionCaptureError::Fenced);
        }
        crate::budget_store::SqliteBudgetStore::open_alongside(
            self.connection.clone(),
            self.serving_owner.clone(),
        )
        .authorize_nonce_preflight(
            request,
            crate::budget_store::NoncePreflightAuthorizationBinding {
                operation,
                recovery_lease,
                trusted_now_unix_ms: now,
            },
        )
        .map_err(map_budget_capture_error)
    }
}

pub(crate) fn bind_nonce_preflight_tx(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    request: &BudgetAuthorizeHoldRequest,
    decision: &BudgetAuthorizeHoldDecision,
    binding: crate::budget_store::NoncePreflightAuthorizationBinding<'_>,
    new_authorization: bool,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let operation = binding.operation;
    let now = binding.trusted_now_unix_ms;
    verify_trusted_time(transaction, now)?;
    verify_participant_recovery_tx(transaction, owner, operation, binding.recovery_lease, now)?;
    ensure_no_reserved_terminal_stage(transaction, operation.binding().operation_id())?;
    if operation.state() != AdmissionOperationState::Prepared
        || operation.attachments().iter().any(|attachment| {
            !matches!(
                attachment,
                AdmissionAttachment::ExecutionNoncePreflightDigest(_)
            )
        })
    {
        return Err(invariant(
            "nonce preflight must precede issuance and executable participants",
        ));
    }
    let grant_index = u32::try_from(request.grant_index)
        .map_err(|_| invariant("nonce preflight grant index exceeds u32"))?;
    let identity = AdmissionNoncePreflightIdentityV1::for_operation(operation, grant_index)?;
    let original = retained_request::load_retained_request_tx(transaction, operation)?
        .ok_or_else(|| invariant("nonce preflight requires its retained original request"))?;
    let admission = request
        .admission_binding
        .as_ref()
        .ok_or_else(|| invariant("nonce preflight requires its budget binding"))?;
    if request.capability_id != operation.binding().capability_id().as_str()
        || original
            .retained_matching_grant(request.grant_index)
            .is_none()
        || request.hold_id.as_deref() != Some(identity.hold_id().as_str())
        || request.event_id.as_deref() != Some(identity.authorization_event_id().as_str())
        || admission.operation_id != identity.budget_operation_id().as_str()
        || !admission
            .revocation_set
            .ids()
            .iter()
            .any(|id| id == &request.capability_id)
    {
        return Err(invariant(
            "nonce preflight request does not match its derived parent ownership",
        ));
    }
    let retained = verify(transaction, operation)?;
    if let Some((record, _)) = retained {
        if record.grant_index != grant_index || new_authorization {
            return Err(invariant(
                "nonce preflight cannot replace its selected grant",
            ));
        }
        return Ok(operation.clone());
    }
    if matches!(decision, BudgetAuthorizeHoldDecision::Denied(_)) {
        return Ok(operation.clone());
    }
    if !new_authorization {
        return Err(invariant(
            "nonce preflight cannot backfill ownership for an existing authorization",
        ));
    }
    if !matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
            | BudgetAuthorizeHoldDecision::ApprovalRequired(_)
    ) {
        return Err(invariant("nonce preflight cannot adopt captured budget"));
    }
    let authorization_digest: String = transaction
        .query_row(
            "SELECT global.projection_reference_digest FROM authority_global_commits AS global
         JOIN budget_mutation_events AS event ON event.event_id = global.projection_key
         AND event.event_seq = global.projection_sequence
         WHERE global.projection_kind = 'budget' AND event.event_id = ?1",
            [identity.authorization_event_id().as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let ownership = PreflightOwnership {
        schema: "chio.admission-nonce-preflight-ownership.v1".into(),
        operation_id: operation.binding().operation_id().clone(),
        budget_operation_id: identity.budget_operation_id().clone(),
        hold_id: identity.hold_id().clone(),
        grant_index,
        authorization_event_id: identity.authorization_event_id().clone(),
        authorization_digest: AdmissionDigest::try_new(
            "preflight_authorization_digest",
            authorization_digest,
        )?,
        recorded_at_unix_ms: now,
    };
    let encoded = canonical_json_bytes(&ownership).map_err(|error| invariant(error.to_string()))?;
    let digest = AdmissionDigest::try_new("nonce_preflight_digest", sha256_hex(&encoded))?;
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        binding.recovery_lease.clone(),
        vec![AdmissionAttachment::ExecutionNoncePreflightDigest(digest)],
        Some(AdmissionOperationState::Prepared),
        None,
        None,
    )?;
    let updated = operation.apply_command(&command, now)?.into_operation();
    let snapshot = encode_operation(&updated)?;
    participant::advance_participant_bound_operation_tx(
        transaction,
        owner,
        operation,
        binding.recovery_lease,
        &updated,
        &record::commit_digest(&encoded, &snapshot, now)?,
        now,
    )?;
    transaction.execute(
        "INSERT INTO admission_nonce_preflight_holds
         (operation_id, budget_operation_id, hold_id, ownership_json, operation_json, recorded_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![operation.binding().operation_id().as_str(), identity.budget_operation_id().as_str(),
            identity.hold_id().as_str(), encoded, snapshot, sqlite_i64(now, "preflight_recorded_at")?],
    ).map_err(sqlite_error)?;
    verify(transaction, &updated)?;
    Ok(updated)
}
