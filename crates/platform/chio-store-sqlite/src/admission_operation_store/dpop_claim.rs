//! Operation-owned replay custody. These primitives do not activate a DPoP
//! profile or verify proof signatures; only the configured verifier may supply
//! a completely prepared intent. Agent metadata is never mutation authority.

use super::*;
use chio_kernel::admission_operation::dpop_claim::{
    DpopReplayClaimDisposition, DpopReplayClaimHistoryV1, DpopReplayClaimIntentV1,
    DpopReplayClaimPhase, DpopReplayClaimReferenceV1, MAX_DPOP_CLAIM_EPISODES,
};
use participant::{ParticipantCommit, ParticipantMutation};

mod capacity;
mod dispatch_snapshot;
mod records;
pub(super) use dispatch_snapshot::{dispatch_snapshot, verify_dispatch_snapshot};
pub(super) use records::{verify_all, verify_operation, verify_stored_operation};

const CLAIM_MUTATION: &str = "dpop_replay_claim";
const RELEASE_MUTATION: &str = "dpop_replay_release";

/// Validate the live verifier selection inside the same transaction as budget
/// authorization or capture. A matching grant elsewhere in the original scope
/// is not interchangeable with the grant whose dpop plan was prepared.
pub(crate) fn verify_dpop_budget_selection_tx(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    grant_index: usize,
    phase: DpopReplayClaimPhase,
) -> Result<(), AdmissionOperationStoreError> {
    verify_stored_operation(connection, operation)?;
    if operation.dpop_replay_ledger_digest().is_none() {
        return Ok(());
    }
    let episodes = records::load(connection, operation)?;
    let live = episodes
        .iter()
        .find(|episode| !episode.released())
        .ok_or_else(|| invariant("dpop budget selection has no live prepared claim"))?;
    if usize::try_from(live.intent().grant_index()).ok() != Some(grant_index)
        || live.intent().phase() != phase
    {
        return Err(invariant(
            "budget selection differs from the dpop prepared grant or phase",
        ));
    }
    Ok(())
}

/// Fresh authority is checked only when introducing an authorization or capture,
/// never when acknowledging an already committed historical result.
pub(crate) fn verify_fresh_dpop_tx(
    connection: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if operation.dpop_replay_ledger_digest().is_none() {
        return Ok(());
    }
    let episodes = records::load(connection, operation)?;
    let live = episodes
        .iter()
        .find(|episode| !episode.released())
        .ok_or_else(|| invariant("fresh dpop authority requires a live claim"))?;
    let source =
        dpop_replay::require_active_authority(connection, live.intent().credential().authority())?;
    let observed = dpop_replay::dpop_clock_tx(connection, &source, trusted_now_unix_ms)?;
    live.intent().credential().validate_at(observed)?;
    Ok(())
}

impl SqliteAdmissionOperationStore {
    /// Fenced, anchored readback for a lost claim or release acknowledgement.
    /// This does not rerun preparation, reacquire resources or require artifacts
    /// to remain unexpired. Returned history cannot authorize fresh execution.
    pub fn load_dpop_replay_claim_history(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(AdmissionOperationV1, Vec<DpopReplayClaimHistoryV1>)>,
        AdmissionOperationStoreError,
    > {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let Some(stored) = load_by_operation_id_tx(&transaction, operation_id)? else {
            return Ok(None);
        };
        stored.verify_decision_time(trusted_now_unix_ms)?;
        let history = records::load(&transaction, &stored.operation)?
            .into_iter()
            .map(|record| {
                Ok(DpopReplayClaimHistoryV1 {
                    reference: record.reference()?,
                    intent: record.intent().clone(),
                    disposition: if record.released() {
                        DpopReplayClaimDisposition::ReleasedBeforeDispatch
                    } else if stored.operation.dispatch_commit().is_some() {
                        DpopReplayClaimDisposition::RetainedAfterDispatchCommit
                    } else {
                        DpopReplayClaimDisposition::ReservedBeforeDispatch
                    },
                })
            })
            .collect::<Result<Vec<_>, AdmissionOperationStoreError>>()?;
        Ok(Some((stored.operation, history)))
    }

    /// Atomically reserve the prepared dpop resource set under the current
    /// operation lease. The returned reference names history, not fresh authority.
    /// A released episode is never reusable, even for an identical intent.
    /// The first claim advances the operation version; callers must renew the
    /// exact-version recovery lease before any subsequent mutation or retry.
    pub fn claim_dpop_replay(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        intent: &DpopReplayClaimIntentV1,
        trusted_now_unix_ms: u64,
    ) -> Result<(AdmissionOperationV1, DpopReplayClaimReferenceV1), AdmissionOperationStoreError>
    {
        intent.validate()?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(lease.store_fence()))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        verify_participant_recovery_tx(
            &transaction,
            &self.serving_owner,
            operation,
            lease,
            trusted_now_unix_ms,
        )?;
        ensure_no_reserved_terminal_stage(&transaction, operation.binding().operation_id())?;
        let source = require_intent(&transaction, operation, intent)?;
        let episodes = records::load(&transaction, operation)?;
        if let Some(existing) = episodes
            .iter()
            .find(|record| record.intent().episode_id() == intent.episode_id())
        {
            if existing.intent() != intent || existing.released() {
                return Err(invariant(
                    "dpop claim episode cannot be replaced or reacquired",
                ));
            }
            return Ok((operation.clone(), existing.reference()?));
        }
        if episodes.len() >= MAX_DPOP_CLAIM_EPISODES
            || episodes.iter().any(|record| !record.released())
        {
            return Err(invariant(
                "dpop operation has a live episode or exhausted its episode bound",
            ));
        }
        let observed = dpop_replay::dpop_clock_tx(&transaction, &source, trusted_now_unix_ms)?;
        intent.credential().validate_at(observed)?;
        capacity::require_available(&transaction, &source, operation, intent, observed)?;
        let ledger = ledger_digest(operation, intent)?;
        let command = AdmissionOperationCommand::new(
            operation.binding().operation_id().clone(),
            operation.version(),
            lease.clone(),
            vec![AdmissionAttachment::DpopReplayLedgerDigest(ledger.clone())],
            Some(operation.state()),
            None,
            None,
        )?;
        let updated = operation
            .apply_command(&command, trusted_now_unix_ms)?
            .into_operation();
        let record = records::Claim::new(&updated, intent.clone(), ledger, trusted_now_unix_ms)?;
        let digest = record.digest()?;
        let commit = ParticipantCommit {
            kind: ParticipantMutation::DpopReplayClaim,
            digest: digest.as_str(),
        };
        // Journal first, physical rows second, then verify the complete state.
        // No intermediate state escapes this IMMEDIATE transaction.
        if updated.version() == operation.version() {
            participant::append_named_participant_tx(
                &transaction,
                &self.serving_owner,
                operation,
                lease,
                commit,
                trusted_now_unix_ms,
            )?;
        } else {
            participant::advance_named_participant_tx(
                &transaction,
                &self.serving_owner,
                operation,
                lease,
                &updated,
                commit,
                trusted_now_unix_ms,
            )?;
        }
        record.insert(&transaction)?;
        verify_operation(&transaction, &updated)?;
        let reference = record.reference()?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok((updated, reference))
    }

    /// Append a release for one exact pre-dispatch episode. References to older
    /// episodes cannot release a successor. Dispatch commitment permanently
    /// prevents release, including after expiry, recovery or a lost response.
    pub fn release_dpop_replay(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        reference: &DpopReplayClaimReferenceV1,
        trusted_now_unix_ms: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if reference.operation_id() != operation.binding().operation_id() {
            return Err(invariant(
                "dpop claim reference belongs to a different operation",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(lease.store_fence()))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        verify_participant_recovery_tx(
            &transaction,
            &self.serving_owner,
            operation,
            lease,
            trusted_now_unix_ms,
        )?;
        ensure_no_reserved_terminal_stage(&transaction, operation.binding().operation_id())?;
        let episodes = records::load(&transaction, operation)?;
        let claim = episodes
            .iter()
            .find(|record| record.intent().episode_id() == reference.episode_id())
            .ok_or_else(|| invariant("dpop claim episode is absent"))?;
        if &claim.reference()? != reference {
            return Err(invariant(
                "dpop claim reference does not match retained ownership",
            ));
        }
        // Exact history acknowledgement does not mutate a successor episode.
        if claim.released() {
            return Ok(());
        }
        if operation.dispatch_commit().is_some() || operation.state().is_terminal() {
            return Err(invariant(
                "dpop participants cannot be released after dispatch commitment or termination",
            ));
        }
        let release = records::Release::new(operation, reference.clone(), trusted_now_unix_ms)?;
        let digest = release.digest()?;
        participant::append_named_participant_tx(
            &transaction,
            &self.serving_owner,
            operation,
            lease,
            ParticipantCommit {
                kind: ParticipantMutation::DpopReplayRelease,
                digest: digest.as_str(),
            },
            trusted_now_unix_ms,
        )?;
        release.insert(&transaction)?;
        verify_operation(&transaction, operation)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }
}

fn require_intent(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    intent: &DpopReplayClaimIntentV1,
) -> Result<dpop_replay::DpopReplayMigrationRecordV1, AdmissionOperationStoreError> {
    let phase_matches = match intent.phase() {
        DpopReplayClaimPhase::NoncePreflight => {
            operation.state() == AdmissionOperationState::Prepared
                && operation
                    .binding()
                    .participant_requirements()
                    .execution_nonce
                && operation.execution_nonce_issuance_digest().is_none()
                && operation.execution_nonce_preflight_digest().is_none()
        }
        DpopReplayClaimPhase::Dispatch => {
            operation.state() == AdmissionOperationState::BrokerAttemptRegistered
        }
    };
    if !phase_matches
        || operation.binding().kind() != AdmissionOperationKind::ToolDispatch
        || operation.dispatch_commit().is_some()
        || operation.binding().request_binding_hash() != intent.request_binding_hash()
    {
        return Err(invariant(
            "dpop claim phase or original request binding does not match its operation",
        ));
    }
    let retained = retained_request::load_retained_request_tx(connection, operation)?
        .ok_or_else(|| invariant("dpop claims require the retained original request"))?;
    retained.validate_binding(operation.binding())?;
    if retained
        .authority_profile()
        .and_then(|profile| profile.dpop())
        != Some(intent.credential().authority())
    {
        return Err(invariant(
            "DPoP claim changed or lacks its original authority profile",
        ));
    }
    if retained
        .retained_matching_grant(intent.grant_index() as usize)
        .is_none()
    {
        return Err(invariant(
            "dpop claim grant is absent from the original matching grants",
        ));
    }
    let request = retained.request_for_revalidation();
    let credential = intent.credential();
    let action_hash = sha256_hex(
        &canonical_json_bytes(&request.arguments).map_err(|error| invariant(error.to_string()))?,
    );
    let invocation = chio_kernel::dpop::authority::invocation_binding_digest(
        &request.capability,
        &request.server_id,
        &request.tool_name,
        &action_hash,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if credential.capability_id() != request.capability.id
        || credential.invocation_digest() != &invocation
    {
        return Err(invariant(
            "DPoP proof differs from retained original invocation",
        ));
    }
    dpop_replay::require_active_authority(connection, intent.credential().authority())
}

fn ledger_digest(
    operation: &AdmissionOperationV1,
    intent: &DpopReplayClaimIntentV1,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    hash(
        "chio.dpop-claim-ledger.v1",
        &(
            operation.binding().operation_id(),
            intent.credential().authority(),
        ),
    )
}

/// A fresh budget authorization or dispatch transition must still own the
/// unexpired dpop. Invoke only after recognizing exact committed retries.
pub(super) fn verify_transition_tx(
    tx: &Transaction<'_>,
    previous: &AdmissionOperationV1,
    updated: &AdmissionOperationV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    verify_operation(tx, updated)?;
    let fresh_authorization =
        previous.budget_hold_id().is_none() && updated.budget_hold_id().is_some();
    let fresh_dispatch =
        previous.dispatch_commit().is_none() && updated.dispatch_commit().is_some();
    if (fresh_authorization || fresh_dispatch) && previous.dpop_replay_ledger_digest().is_some() {
        verify_fresh_dpop_tx(tx, previous, now)?;
    }
    Ok(())
}

fn hash(
    domain: &str,
    value: &impl Serialize,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    let bytes =
        canonical_json_bytes(&(domain, value)).map_err(|error| invariant(error.to_string()))?;
    AdmissionDigest::try_new("dpop_replay_claim_digest", sha256_hex(&bytes)).map_err(Into::into)
}
