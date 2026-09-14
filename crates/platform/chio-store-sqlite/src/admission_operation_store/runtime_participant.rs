//! Operation-owned replay custody. These primitives do not activate a runtime
//! profile or verify runtime artifacts; only the configured verifier may supply
//! a completely prepared intent. Agent metadata is never mutation authority.

use super::*;
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantClaimHistoryV1, RuntimeParticipantClaimIntentV1,
    RuntimeParticipantClaimReferenceV1, RuntimeParticipantDisposition, RuntimeParticipantPhase,
    MAX_RUNTIME_PARTICIPANT_EPISODES,
};
use participant::{ParticipantCommit, ParticipantMutation};

mod dispatch_snapshot;
mod records;
pub(super) use dispatch_snapshot::{dispatch_snapshot, verify_dispatch_snapshot};
pub(super) use records::{verify_all, verify_operation};

const CLAIM_MUTATION: &str = "runtime_participant_claim";
const RELEASE_MUTATION: &str = "runtime_participant_release";

/// Validate the live verifier selection inside the same transaction as budget
/// authorization or capture. A matching grant elsewhere in the original scope
/// is not interchangeable with the grant whose runtime plan was prepared.
pub(crate) fn verify_runtime_budget_selection_tx(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    grant_index: usize,
    phase: RuntimeParticipantPhase,
) -> Result<(), AdmissionOperationStoreError> {
    verify_operation(connection, operation)?;
    if operation.runtime_participant_ledger_digest().is_none() {
        return Ok(());
    }
    let episodes = records::load(connection, operation)?;
    let live = episodes
        .iter()
        .find(|episode| !episode.released())
        .ok_or_else(|| invariant("runtime budget selection has no live prepared claim"))?;
    if usize::try_from(live.intent().grant_index()).ok() != Some(grant_index)
        || live.intent().phase() != phase
    {
        return Err(invariant(
            "budget selection differs from the runtime prepared grant or phase",
        ));
    }
    Ok(())
}

impl SqliteAdmissionOperationStore {
    /// Fenced, anchored readback for a lost claim or release acknowledgement.
    /// This does not rerun preparation, reacquire resources or require artifacts
    /// to remain unexpired. Returned history cannot authorize fresh execution.
    pub fn load_runtime_participant_history(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(AdmissionOperationV1, Vec<RuntimeParticipantClaimHistoryV1>)>,
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
                Ok(RuntimeParticipantClaimHistoryV1 {
                    reference: record.reference()?,
                    intent: record.intent().clone(),
                    disposition: if record.released() {
                        RuntimeParticipantDisposition::ReleasedBeforeDispatch
                    } else if stored.operation.dispatch_commit().is_some() {
                        RuntimeParticipantDisposition::RetainedAfterDispatchCommit
                    } else {
                        RuntimeParticipantDisposition::ReservedBeforeDispatch
                    },
                })
            })
            .collect::<Result<Vec<_>, AdmissionOperationStoreError>>()?;
        Ok(Some((stored.operation, history)))
    }

    /// Atomically reserve the prepared runtime resource set under the current
    /// operation lease. The returned reference names history, not fresh authority.
    /// A released episode is never reusable, even for an identical intent.
    /// The first claim advances the operation version; callers must renew the
    /// exact-version recovery lease before any subsequent mutation or retry.
    pub fn claim_runtime_participants(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        intent: &RuntimeParticipantClaimIntentV1,
        trusted_now_unix_ms: u64,
    ) -> Result<
        (AdmissionOperationV1, RuntimeParticipantClaimReferenceV1),
        AdmissionOperationStoreError,
    > {
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
        require_intent(&transaction, operation, intent)?;
        let episodes = records::load(&transaction, operation)?;
        if let Some(existing) = episodes
            .iter()
            .find(|record| record.intent().episode_id() == intent.episode_id())
        {
            if existing.intent() != intent || existing.released() {
                return Err(invariant(
                    "runtime claim episode cannot be replaced or reacquired",
                ));
            }
            return Ok((operation.clone(), existing.reference()?));
        }
        if episodes.len() >= MAX_RUNTIME_PARTICIPANT_EPISODES
            || episodes.iter().any(|record| !record.released())
        {
            return Err(invariant(
                "runtime operation has a live episode or exhausted its episode bound",
            ));
        }
        for resource in intent.resources() {
            let occupied: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM runtime_replay_legacy_tombstones
                     WHERE runtime_authority_id = ?1 AND participant_kind = ?2 AND resource_id = ?3)
                 OR EXISTS(SELECT 1 FROM runtime_replay_claim_resources AS resource
                     WHERE runtime_authority_id = ?1 AND participant_kind = ?2 AND resource_id = ?3
                     AND NOT EXISTS(SELECT 1 FROM runtime_replay_claim_releases AS released
                         WHERE released.operation_id = resource.operation_id AND released.episode_id = resource.episode_id))",
                params![intent.runtime_authority_id().as_str(), resource.kind().as_str(), resource.resource_id().as_str()],
                |row| row.get(0),
            ).map_err(sqlite_error)?;
            if occupied {
                return Err(invariant(
                    "runtime participant resource is already reserved or historically spent",
                ));
            }
        }
        let ledger = ledger_digest(operation, intent)?;
        let command = AdmissionOperationCommand::new(
            operation.binding().operation_id().clone(),
            operation.version(),
            lease.clone(),
            vec![AdmissionAttachment::RuntimeParticipantLedgerDigest(
                ledger.clone(),
            )],
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
            kind: ParticipantMutation::RuntimeClaim,
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
    pub fn release_runtime_participants(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        reference: &RuntimeParticipantClaimReferenceV1,
        trusted_now_unix_ms: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if reference.operation_id() != operation.binding().operation_id() {
            return Err(invariant(
                "runtime claim reference belongs to a different operation",
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
            .ok_or_else(|| invariant("runtime claim episode is absent"))?;
        if &claim.reference()? != reference {
            return Err(invariant(
                "runtime claim reference does not match retained ownership",
            ));
        }
        // Exact history acknowledgement does not mutate a successor episode.
        if claim.released() {
            return Ok(());
        }
        if operation.dispatch_commit().is_some() || operation.state().is_terminal() {
            return Err(invariant(
                "runtime participants cannot be released after dispatch commitment or termination",
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
                kind: ParticipantMutation::RuntimeRelease,
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
    intent: &RuntimeParticipantClaimIntentV1,
) -> Result<(), AdmissionOperationStoreError> {
    let phase_matches = match intent.phase() {
        RuntimeParticipantPhase::NoncePreflight => {
            operation.state() == AdmissionOperationState::Prepared
                && operation
                    .binding()
                    .participant_requirements()
                    .execution_nonce
                && operation.execution_nonce_issuance_digest().is_none()
                && operation.execution_nonce_preflight_digest().is_none()
        }
        RuntimeParticipantPhase::Dispatch => {
            operation.state() == AdmissionOperationState::BrokerAttemptRegistered
        }
    };
    if !phase_matches
        || operation.binding().kind() != AdmissionOperationKind::ToolDispatch
        || operation.dispatch_commit().is_some()
        || operation.binding().request_binding_hash() != intent.request_binding_hash()
    {
        return Err(invariant(
            "runtime claim phase or original request binding does not match its operation",
        ));
    }
    let retained = retained_request::load_retained_request_tx(connection, operation)?
        .ok_or_else(|| invariant("runtime claims require the retained original request"))?;
    retained.validate_binding(operation.binding())?;
    let selected = retained
        .authority_profile()
        .and_then(|profile| profile.runtime())
        .ok_or_else(|| invariant("runtime claim lacks an original authority profile"))?;
    if selected.runtime_authority_id() != intent.runtime_authority_id()
        || selected.expectation_id() != intent.expectation_id()
    {
        return Err(invariant(
            "runtime claim changed the original authority selection",
        ));
    }
    if retained
        .retained_matching_grant(intent.grant_index() as usize)
        .is_none()
    {
        return Err(invariant(
            "runtime claim grant is absent from the original matching grants",
        ));
    }
    runtime_replay::require_imported_source(
        connection,
        intent.runtime_authority_id(),
        intent.expectation_id(),
    )?;
    Ok(())
}

fn ledger_digest(
    operation: &AdmissionOperationV1,
    intent: &RuntimeParticipantClaimIntentV1,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    hash(
        "chio.runtime-participant-ledger.v1",
        &(
            operation.binding().operation_id(),
            intent.runtime_authority_id(),
            intent.expectation_id(),
        ),
    )
}

fn hash(
    domain: &str,
    value: &impl Serialize,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    let bytes =
        canonical_json_bytes(&(domain, value)).map_err(|error| invariant(error.to_string()))?;
    AdmissionDigest::try_new("runtime_participant_digest", sha256_hex(&bytes)).map_err(Into::into)
}
