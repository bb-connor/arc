//! Preflight uses the ordinary accounting engine but cannot acquire execution authority.

use super::*;
use chio_kernel::admission_operation::{
    AdmissionNoncePreflightIdentityV1, AdmissionOperationV1, AdmissionRecoveryLease,
    NONCE_PREFLIGHT_BUDGET_PREFIX,
};

#[derive(Clone, Copy)]
pub(crate) struct NoncePreflightAuthorizationBinding<'a> {
    pub(crate) operation: &'a AdmissionOperationV1,
    pub(crate) recovery_lease: &'a AdmissionRecoveryLease,
    pub(crate) trusted_now_unix_ms: u64,
}

pub(crate) enum NoncePreflightHoldState {
    Reserved,
    ReversedWithoutApproval,
    ReversedAuthorized { global_commit_sequence: u64 },
}

impl SqliteBudgetStore {
    pub(crate) fn authorize_nonce_preflight(
        &self,
        request: BudgetAuthorizeHoldRequest,
        binding: NoncePreflightAuthorizationBinding<'_>,
    ) -> Result<(BudgetAuthorizeHoldDecision, AdmissionOperationV1), BudgetStoreError> {
        let (decision, operation) = self.authorize_composite_hold_inner(
            request,
            Some(AuthorizationParticipant::NoncePreflight(binding)),
        )?;
        Ok((
            decision,
            operation.ok_or_else(|| {
                BudgetStoreError::Invariant("nonce preflight lost its parent operation".into())
            })?,
        ))
    }

    pub(super) fn bind_nonce_preflight(
        &self,
        transaction: &Transaction<'_>,
        request: &BudgetAuthorizeHoldRequest,
        decision: &BudgetAuthorizeHoldDecision,
        binding: NoncePreflightAuthorizationBinding<'_>,
        new_authorization: bool,
    ) -> Result<AdmissionOperationV1, BudgetStoreError> {
        let owner = self.serving_owner.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("nonce preflight requires its serving owner".into())
        })?;
        crate::admission_operation_store::bind_nonce_preflight_tx(
            transaction,
            owner,
            request,
            decision,
            binding,
            new_authorization,
        )
        .map_err(|error| map_credit_exposure_error(error, owner.fence.owner_epoch))
    }
}

/// The authorization and current physical projection remain checked on every read.
pub(crate) fn verify_preflight_hold(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    identity: &AdmissionNoncePreflightIdentityV1,
    authorization_digest: &str,
) -> Result<NoncePreflightHoldState, BudgetStoreError> {
    let hold = load_structured_hold(connection, identity.hold_id().as_str())?.ok_or_else(|| {
        BudgetStoreError::Invariant("nonce preflight lost its physical hold".into())
    })?;
    if hold.admission.operation_id != identity.budget_operation_id().as_str()
        || hold.capability_id != operation.binding().capability_id().as_str()
        || hold.grant_index != identity.grant_index() as usize
    {
        return Err(BudgetStoreError::Invariant(
            "nonce preflight physical ownership changed".into(),
        ));
    }
    let event = SqliteBudgetStore::load_mutation_event(
        connection,
        identity.authorization_event_id().as_str(),
    )?
    .ok_or_else(|| BudgetStoreError::Invariant("nonce preflight lost its authorization".into()))?;
    let request = load_authorization_request(connection, &event)?;
    if request.hold_id.as_deref() != Some(identity.hold_id().as_str())
        || request.capability_id != hold.capability_id
        || request.grant_index != hold.grant_index
        || request
            .admission_binding
            .as_ref()
            .map(|binding| binding.operation_id.as_str())
            != Some(identity.budget_operation_id().as_str())
    {
        return Err(BudgetStoreError::Invariant(
            "nonce preflight authorization identity changed".into(),
        ));
    }
    let (digest, _) = event_commit(connection, &event.event_id, event.event_seq)?;
    if digest != authorization_digest {
        return Err(BudgetStoreError::Invariant(
            "nonce preflight authorization commit changed".into(),
        ));
    }
    let authorization_completed = match event.authorization_outcome {
        Some(BudgetAuthorizationOutcome::Authorized) => true,
        Some(BudgetAuthorizationOutcome::ApprovalRequired) => hold
            .cumulative
            .as_ref()
            .is_some_and(|(_, _, digest)| digest.is_some()),
        _ => {
            return Err(BudgetStoreError::Invariant(
                "nonce preflight hold has no reserved authorization".into(),
            ))
        }
    };
    match hold.invocation_state {
        BudgetInvocationState::Authorized => Ok(NoncePreflightHoldState::Reserved),
        BudgetInvocationState::Reversed
            if hold.remaining_exposure == 0
                && matches!(
                    hold.monetary_state,
                    BudgetMonetaryState::None | BudgetMonetaryState::Reversed
                ) =>
        {
            let (event_id, event_seq): (String, i64) = connection.query_row(
                "SELECT event_id, event_seq FROM budget_mutation_events WHERE hold_id = ?1
                 ORDER BY event_seq DESC LIMIT 1",
                [identity.hold_id().as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let event = SqliteBudgetStore::load_mutation_event(connection, &event_id)?.ok_or_else(
                || BudgetStoreError::Invariant("nonce preflight lost its reversal".into()),
            )?;
            if !matches!(
                event.kind,
                BudgetMutationKind::ReverseInvocation | BudgetMutationKind::ReverseExposure
            ) {
                return Err(BudgetStoreError::Invariant(
                    "nonce preflight cleanup is not a reversal".into(),
                ));
            }
            let sequence = u64::try_from(event_seq).map_err(|_| {
                BudgetStoreError::Invariant("nonce preflight reversal sequence is invalid".into())
            })?;
            let global_commit_sequence = event_commit(connection, &event_id, sequence)?.1;
            Ok(if authorization_completed {
                NoncePreflightHoldState::ReversedAuthorized {
                    global_commit_sequence,
                }
            } else {
                NoncePreflightHoldState::ReversedWithoutApproval
            })
        }
        _ => Err(BudgetStoreError::Invariant(
            "nonce preflight hold acquired execution effects".into(),
        )),
    }
}

pub(super) fn reject_preflight_capture(
    connection: &Connection,
    hold_id: &str,
) -> Result<(), BudgetStoreError> {
    let preflight: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM budget_authorization_holds WHERE hold_id = ?1
         AND substr(operation_id, 1, length(?2)) = ?2)",
        params![hold_id, NONCE_PREFLIGHT_BUDGET_PREFIX],
        |row| row.get(0),
    )?;
    if preflight {
        return Err(BudgetStoreError::Invariant(
            "nonce preflight holds cannot be captured".into(),
        ));
    }
    Ok(())
}

fn event_commit(
    connection: &Connection,
    event_id: &str,
    event_seq: u64,
) -> Result<(String, u64), BudgetStoreError> {
    let (digest, sequence): (String, i64) = connection.query_row(
        "SELECT projection_reference_digest, commit_sequence FROM authority_global_commits
         WHERE projection_kind = 'budget' AND projection_key = ?1 AND projection_sequence = ?2",
        params![
            event_id,
            budget_u64_to_sqlite(event_seq, "preflight_event_sequence")?
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((
        digest,
        u64::try_from(sequence).map_err(|_| {
            BudgetStoreError::Invariant("nonce preflight global sequence is invalid".into())
        })?,
    ))
}
