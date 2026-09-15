//! Operation-owned replay custody. These primitives do not activate an approval
//! profile or verify approval artifacts; only the configured verifier may supply
//! a completely prepared intent. Agent metadata is never mutation authority.

use super::*;
use chio_kernel::admission_operation::governed_approval_claim::{
    GovernedApprovalAuthorityBindingV1, GovernedApprovalClaimDisposition,
    GovernedApprovalClaimHistoryV1, GovernedApprovalClaimIntentV1, GovernedApprovalClaimPhase,
    GovernedApprovalClaimReferenceV1, MAX_GOVERNED_APPROVAL_CLAIM_EPISODES,
};
use chio_kernel::admission_operation::governed_approval_replay::GovernedApprovalReplaySourceSnapshot;
use participant::{ParticipantCommit, ParticipantMutation};

mod dispatch_snapshot;
mod records;
pub(super) use dispatch_snapshot::{dispatch_snapshot, verify_dispatch_snapshot};
pub(super) use records::{verify_all, verify_operation, verify_stored_operation};

const CLAIM_MUTATION: &str = "governed_approval_claim";
const RELEASE_MUTATION: &str = "governed_approval_release";

/// Validate the live verifier selection inside the same transaction as budget
/// authorization or capture. A matching grant elsewhere in the original scope
/// is not interchangeable with the grant whose approval plan was prepared.
pub(crate) fn verify_approval_budget_selection_tx(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    grant_index: usize,
    phase: GovernedApprovalClaimPhase,
) -> Result<(), AdmissionOperationStoreError> {
    verify_stored_operation(connection, operation)?;
    if operation.governed_approval_ledger_digest().is_none() {
        return Ok(());
    }
    let episodes = records::load(connection, operation)?;
    let live = episodes
        .iter()
        .find(|episode| !episode.released())
        .ok_or_else(|| invariant("approval budget selection has no live prepared claim"))?;
    if usize::try_from(live.intent().grant_index()).ok() != Some(grant_index)
        || live.intent().phase() != phase
    {
        return Err(invariant(
            "budget selection differs from the approval prepared grant or phase",
        ));
    }
    Ok(())
}

/// Fresh authority is checked only when introducing an authorization or capture,
/// never when acknowledging an already committed historical result.
pub(crate) fn verify_fresh_approval_tx(
    connection: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if operation.governed_approval_ledger_digest().is_none() {
        return Ok(());
    }
    let episodes = records::load(connection, operation)?;
    let live = episodes
        .iter()
        .find(|episode| !episode.released())
        .ok_or_else(|| invariant("fresh approval authority requires a live claim"))?;
    let source = governed_approval_replay::require_active_source(
        connection,
        live.intent().approval_authority_id(),
        live.intent().expectation_id(),
    )?;
    let observed =
        governed_approval_replay::approval_clock_tx(connection, &source, trusted_now_unix_ms)?;
    live.intent().credential().validate_at(observed)?;
    Ok(())
}

impl SqliteAdmissionOperationStore {
    pub fn load_governed_approval_activation(
        &self,
        binding: &GovernedApprovalAuthorityBindingV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<GovernedApprovalReplaySourceSnapshot, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let source = governed_approval_replay::require_active_source(
            &tx,
            binding.approval_authority_id(),
            binding.expectation_id(),
        )?;
        governed_approval_replay::approval_clock_tx(&tx, &source, trusted_now_unix_ms)?;
        Ok(source)
    }
    /// Fenced, anchored readback for a lost claim or release acknowledgement.
    /// This does not rerun preparation, reacquire resources or require artifacts
    /// to remain unexpired. Returned history cannot authorize fresh execution.
    pub fn load_governed_approval_claim_history(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(AdmissionOperationV1, Vec<GovernedApprovalClaimHistoryV1>)>,
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
                Ok(GovernedApprovalClaimHistoryV1 {
                    reference: record.reference()?,
                    intent: record.intent().clone(),
                    disposition: if record.released() {
                        GovernedApprovalClaimDisposition::ReleasedBeforeDispatch
                    } else if stored.operation.dispatch_commit().is_some() {
                        GovernedApprovalClaimDisposition::RetainedAfterDispatchCommit
                    } else {
                        GovernedApprovalClaimDisposition::ReservedBeforeDispatch
                    },
                })
            })
            .collect::<Result<Vec<_>, AdmissionOperationStoreError>>()?;
        Ok(Some((stored.operation, history)))
    }

    /// Atomically reserve the prepared approval resource set under the current
    /// operation lease. The returned reference names history, not fresh authority.
    /// A released episode is never reusable, even for an identical intent.
    /// The first claim advances the operation version; callers must renew the
    /// exact-version recovery lease before any subsequent mutation or retry.
    pub fn claim_governed_approval(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        intent: &GovernedApprovalClaimIntentV1,
        trusted_now_unix_ms: u64,
    ) -> Result<
        (AdmissionOperationV1, GovernedApprovalClaimReferenceV1),
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
                    "approval claim episode cannot be replaced or reacquired",
                ));
            }
            return Ok((operation.clone(), existing.reference()?));
        }
        if episodes.len() >= MAX_GOVERNED_APPROVAL_CLAIM_EPISODES
            || episodes.iter().any(|record| !record.released())
        {
            return Err(invariant(
                "approval operation has a live episode or exhausted its episode bound",
            ));
        }
        let source = governed_approval_replay::require_active_source(
            &transaction,
            intent.approval_authority_id(),
            intent.expectation_id(),
        )?;
        let observed = governed_approval_replay::approval_clock_tx(
            &transaction,
            &source,
            trusted_now_unix_ms,
        )?;
        intent.credential().validate_at(observed)?;
        let credential = intent.credential();
        let occupied: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM governed_approval_replay_legacy_tombstones
                WHERE approval_authority_id = ?1 AND request_id = ?3 AND intent_hash = ?4
                  AND (subject_id = ?2 OR subject_id = ?5))
             OR EXISTS(SELECT 1 FROM governed_approval_replay_claim_resources AS resource
                WHERE approval_authority_id = ?1 AND subject_id = ?2 AND request_id = ?3 AND intent_hash = ?4
                  AND NOT EXISTS(SELECT 1 FROM governed_approval_replay_claim_releases AS released
                    WHERE released.operation_id = resource.operation_id AND released.episode_id = resource.episode_id))",
            params![intent.approval_authority_id().as_str(), credential.subject_id.as_str(),
                credential.request_id.as_str(), credential.intent_hash.as_str(),
                chio_kernel::admission_operation::governed_approval_replay::LEGACY_UNSCOPED_GOVERNED_APPROVAL_SUBJECT],
            |row| row.get(0)).map_err(sqlite_error)?;
        if occupied {
            return Err(invariant(
                "approval replay identity is already reserved or historically spent",
            ));
        }
        let live: i64 = transaction.query_row(
            "SELECT (SELECT COUNT(*) FROM governed_approval_replay_legacy_tombstones
                WHERE approval_authority_id = ?1 AND expires_at > ?2)
             + (SELECT COUNT(*) FROM governed_approval_replay_claim_resources AS resource
                WHERE approval_authority_id = ?1 AND expires_at > ?2
                  AND NOT EXISTS(SELECT 1 FROM governed_approval_replay_claim_releases AS released
                    WHERE released.operation_id = resource.operation_id AND released.episode_id = resource.episode_id))",
            params![intent.approval_authority_id().as_str(), sqlite_i64(observed / 1000, "approval_clock")?],
            |row| row.get(0)).map_err(sqlite_error)?;
        let capacity: i64 = source
            .inventory()
            .capacity
            .parse()
            .map_err(|_| invariant("invalid approval source capacity"))?;
        if live >= capacity {
            return Err(invariant("approval replay live capacity exhausted"));
        }
        let ledger = ledger_digest(operation, intent)?;
        let command = AdmissionOperationCommand::new(
            operation.binding().operation_id().clone(),
            operation.version(),
            lease.clone(),
            vec![AdmissionAttachment::GovernedApprovalLedgerDigest(
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
            kind: ParticipantMutation::GovernedApprovalClaim,
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
    pub fn release_governed_approval(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        reference: &GovernedApprovalClaimReferenceV1,
        trusted_now_unix_ms: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if reference.operation_id() != operation.binding().operation_id() {
            return Err(invariant(
                "approval claim reference belongs to a different operation",
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
            .ok_or_else(|| invariant("approval claim episode is absent"))?;
        if &claim.reference()? != reference {
            return Err(invariant(
                "approval claim reference does not match retained ownership",
            ));
        }
        // Exact history acknowledgement does not mutate a successor episode.
        if claim.released() {
            return Ok(());
        }
        if operation.dispatch_commit().is_some() || operation.state().is_terminal() {
            return Err(invariant(
                "approval participants cannot be released after dispatch commitment or termination",
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
                kind: ParticipantMutation::GovernedApprovalRelease,
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
    intent: &GovernedApprovalClaimIntentV1,
) -> Result<(), AdmissionOperationStoreError> {
    let phase_matches = match intent.phase() {
        GovernedApprovalClaimPhase::NoncePreflight => {
            operation.state() == AdmissionOperationState::Prepared
                && operation
                    .binding()
                    .participant_requirements()
                    .execution_nonce
                && operation.execution_nonce_issuance_digest().is_none()
                && operation.execution_nonce_preflight_digest().is_none()
        }
        GovernedApprovalClaimPhase::Dispatch => {
            operation.state() == AdmissionOperationState::BrokerAttemptRegistered
        }
    };
    if !phase_matches
        || operation.binding().kind() != AdmissionOperationKind::ToolDispatch
        || operation.dispatch_commit().is_some()
        || operation.binding().request_binding_hash() != intent.request_binding_hash()
    {
        return Err(invariant(
            "approval claim phase or original request binding does not match its operation",
        ));
    }
    let retained = retained_request::load_retained_request_tx(connection, operation)?
        .ok_or_else(|| invariant("approval claims require the retained original request"))?;
    retained.validate_binding(operation.binding())?;
    let selected = retained
        .authority_profile()
        .and_then(|profile| profile.approval())
        .ok_or_else(|| invariant("approval claim lacks an original authority profile"))?;
    if selected.approval_authority_id() != intent.approval_authority_id()
        || selected.expectation_id() != intent.expectation_id()
    {
        return Err(invariant(
            "approval claim changed the original authority selection",
        ));
    }
    if retained
        .retained_matching_grant(intent.grant_index() as usize)
        .is_none()
    {
        return Err(invariant(
            "approval claim grant is absent from the original matching grants",
        ));
    }
    let request = retained.request_for_revalidation();
    let credential = intent.credential();
    let intent_hash = request
        .governed_intent
        .as_ref()
        .ok_or_else(|| invariant("approval claim requires a retained governed intent"))?
        .binding_hash()
        .map_err(|error| invariant(error.to_string()))?;
    if credential.subject_id.as_str() != request.capability.subject.to_hex()
        || credential.request_id.as_str() != request.request_id
        || credential.intent_hash.as_str() != intent_hash
    {
        return Err(invariant(
            "approval credential differs from original request provenance",
        ));
    }
    governed_approval_replay::require_active_source(
        connection,
        intent.approval_authority_id(),
        intent.expectation_id(),
    )?;
    Ok(())
}

fn ledger_digest(
    operation: &AdmissionOperationV1,
    intent: &GovernedApprovalClaimIntentV1,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    hash(
        "chio.governed-approval-claim-ledger.v1",
        &(
            operation.binding().operation_id(),
            intent.approval_authority_id(),
            intent.expectation_id(),
        ),
    )
}

/// A fresh budget authorization or dispatch transition must still own the
/// unexpired approval. Invoke only after recognizing exact committed retries.
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
    if (fresh_authorization || fresh_dispatch)
        && previous.governed_approval_ledger_digest().is_some()
    {
        verify_fresh_approval_tx(tx, previous, now)?;
    }
    Ok(())
}

fn hash(
    domain: &str,
    value: &impl Serialize,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    let bytes =
        canonical_json_bytes(&(domain, value)).map_err(|error| invariant(error.to_string()))?;
    AdmissionDigest::try_new("governed_approval_claim_digest", sha256_hex(&bytes))
        .map_err(Into::into)
}
