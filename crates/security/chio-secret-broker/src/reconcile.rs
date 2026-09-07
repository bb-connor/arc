#[cfg(test)]
use crate::budget::AuthorizeExecutionHoldRequest;
use chio_core_types::PublicKey;

use crate::budget::{BrokerExecutionBudget, ExecutionHoldState, QueryExecutionHoldRequest};
use crate::protocol::BrokerExecuteResponse;
use crate::receipt::{
    validate_durable_completed_response, verify_failure_receipt, BrokerDispatchKnowledge,
    BrokerExecutionOutcome, BrokerFailureOutcome, BrokerFailureStage, BrokerReceiptSink,
    SignedBrokerFailureReceipt,
};
use crate::service::failure_receipt_id_for_canonical_request_digest;
use crate::store::{AttemptRecord, AttemptState, AttemptStore, AttemptTransitionEvidence};
use crate::{BrokerError, Result};

pub fn reconcile_attempt(
    store: &dyn AttemptStore,
    authority: &dyn BrokerExecutionBudget,
    attempt: &AttemptRecord,
    now_unix_seconds: u64,
) -> Result<AttemptRecord> {
    authority.capabilities().require_production()?;
    let query = QueryExecutionHoldRequest {
        operation_id: attempt.registration.ids.operation_id.clone(),
        invocation_id: attempt.registration.invocation_id.clone(),
        parent_capability_id: attempt.registration.parent_capability_id.clone(),
        broker_capability_id: attempt.registration.broker_capability_id.clone(),
        hold_id: attempt.registration.ids.hold_id.clone(),
        authorize_event_id: attempt.registration.ids.authorize_event_id.clone(),
        reverse_event_id: attempt.registration.ids.reverse_event_id.clone(),
        capture_event_id: attempt.registration.ids.capture_event_id.clone(),
    };
    query.validate()?;
    let state = authority.query_execution_hold(&query)?;
    match state {
        ExecutionHoldState::Unknown => Ok(attempt.clone()),
        ExecutionHoldState::Denied => transition_any_nonterminal(
            store,
            attempt,
            AttemptState::Failed,
            &AttemptTransitionEvidence::default(),
            now_unix_seconds,
        ),
        ExecutionHoldState::Held => Ok(attempt.clone()),
        ExecutionHoldState::Reversed => transition_any_nonterminal(
            store,
            attempt,
            AttemptState::Reversed,
            &AttemptTransitionEvidence::default(),
            now_unix_seconds,
        ),
        ExecutionHoldState::Captured(commit) => {
            reconcile_authoritative_capture(store, attempt, commit, now_unix_seconds)
        }
    }
}

fn reconcile_authoritative_capture(
    store: &dyn AttemptStore,
    attempt: &AttemptRecord,
    commit: crate::budget::CombinedCaptureCommit,
    now_unix_seconds: u64,
) -> Result<AttemptRecord> {
    let evidence = AttemptTransitionEvidence {
        revocation_set_digest: Some(commit.checked_revocation_set_digest),
        budget_commit_index: Some(commit.budget_commit_index),
        revocation_commit_index: Some(commit.revocation_commit_index),
        authority_commit_index: Some(commit.authority_commit_index),
        leader_epoch: Some(commit.leader_epoch),
        response_digest: None,
    };
    match attempt.state {
        AttemptState::Prepared | AttemptState::Held | AttemptState::Captured => store.transition(
            &attempt.registration.ids.attempt_id,
            attempt.state,
            AttemptState::Captured,
            &evidence,
            now_unix_seconds,
        ),
        AttemptState::DispatchCommitted => store.transition(
            &attempt.registration.ids.attempt_id,
            AttemptState::DispatchCommitted,
            AttemptState::UnknownOutcome,
            &evidence,
            now_unix_seconds,
        ),
        _ => Ok(attempt.clone()),
    }
}

pub fn reconcile_pending(
    store: &dyn AttemptStore,
    authority: &dyn BrokerExecutionBudget,
    limit: usize,
    now_unix_seconds: u64,
) -> Result<Vec<AttemptRecord>> {
    let mut reconciled = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let pending = store.recoverable_attempts(cursor.as_deref(), limit)?;
        if pending.is_empty() {
            break;
        }
        let next_cursor = pending
            .last()
            .map(|attempt| attempt.registration.ids.attempt_id.clone())
            .ok_or_else(|| {
                BrokerError::Invariant("recovery page lost its final attempt".to_string())
            })?;
        if cursor
            .as_ref()
            .is_some_and(|previous| next_cursor.as_str() <= previous.as_str())
        {
            return Err(BrokerError::Invariant(
                "attempt recovery cursor did not advance".to_string(),
            ));
        }
        for attempt in &pending {
            let attempt =
                if attempt.dispatch_claim_id.is_some() && attempt.state == AttemptState::Captured {
                    store.clear_stale_captured_attempt_claim(
                        &attempt.registration.ids.attempt_id,
                        now_unix_seconds,
                    )?
                } else {
                    attempt.clone()
                };
            reconciled.push(reconcile_attempt(
                store,
                authority,
                &attempt,
                now_unix_seconds,
            )?);
        }
        cursor = Some(next_cursor);
        if pending.len() < limit {
            break;
        }
    }
    Ok(reconciled)
}

/// Converge broker-signed durable failures before any live authority query.
/// Receipt persistence is the terminal commit; this scan closes the crash
/// window before the compatible pre-dispatch attempt journal reaches `Failed`.
pub fn reconcile_durable_failures(
    store: &dyn AttemptStore,
    receipt_sink: &dyn BrokerReceiptSink,
    trusted_receipt_signer: &PublicKey,
    limit: usize,
    now_unix_seconds: u64,
) -> Result<Vec<AttemptRecord>> {
    let mut failed = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let pending = store.recoverable_attempts(cursor.as_deref(), limit)?;
        if pending.is_empty() {
            break;
        }
        let next_cursor = pending
            .last()
            .map(|attempt| attempt.registration.ids.attempt_id.clone())
            .ok_or_else(|| {
                BrokerError::Invariant(
                    "durable failure recovery page lost its final attempt".to_string(),
                )
            })?;
        if cursor
            .as_ref()
            .is_some_and(|previous| next_cursor.as_str() <= previous.as_str())
        {
            return Err(BrokerError::Invariant(
                "durable failure recovery cursor did not advance".to_string(),
            ));
        }
        for attempt in &pending {
            let receipt_id = failure_receipt_id_for_canonical_request_digest(
                &attempt.registration.request_canonical_digest,
            )?;
            let Some(receipt) = receipt_sink.load_failure(&receipt_id)? else {
                continue;
            };
            let (target, evidence) =
                validate_failure_for_attempt(attempt, &receipt, trusted_receipt_signer)?;
            if attempt.state != target {
                failed.push(store.transition(
                    &attempt.registration.ids.attempt_id,
                    attempt.state,
                    target,
                    &evidence,
                    now_unix_seconds.max(attempt.updated_at_unix_seconds),
                )?);
            }
        }
        cursor = Some(next_cursor);
        if pending.len() < limit {
            break;
        }
    }
    Ok(failed)
}

fn validate_failure_for_attempt(
    attempt: &AttemptRecord,
    receipt: &SignedBrokerFailureReceipt,
    trusted_receipt_signer: &PublicKey,
) -> Result<(AttemptState, AttemptTransitionEvidence)> {
    verify_failure_receipt(receipt, trusted_receipt_signer)?;
    let registration = &attempt.registration;
    let expected_receipt_id =
        failure_receipt_id_for_canonical_request_digest(&registration.request_canonical_digest)?;
    let binding_is_absent = receipt.body.attempt_id.is_none();
    let binding_is_exact = receipt.body.attempt_id.as_deref()
        == Some(registration.ids.attempt_id.as_str())
        && receipt.body.invocation_id.as_deref() == Some(registration.invocation_id.as_str())
        && receipt.body.hold_id.as_deref() == Some(registration.ids.hold_id.as_str())
        && receipt.body.parent_capability_id.as_deref()
            == Some(registration.parent_capability_id.as_str())
        && receipt.body.broker_capability_id.as_deref()
            == Some(registration.broker_capability_id.as_str());
    let target = if receipt.body.outcome == BrokerFailureOutcome::Reversed {
        AttemptState::Reversed
    } else {
        AttemptState::Failed
    };
    let projection_is_compatible = match attempt.state {
        AttemptState::Registered => {
            receipt.body.stage == BrokerFailureStage::Admission
                && receipt.body.dispatch_knowledge == BrokerDispatchKnowledge::NotStarted
                && matches!(
                    receipt.body.outcome,
                    BrokerFailureOutcome::Denied | BrokerFailureOutcome::Failed
                )
        }
        AttemptState::Prepared => {
            receipt.body.stage == BrokerFailureStage::Hold
                && receipt.body.dispatch_knowledge == BrokerDispatchKnowledge::NotCommitted
                && matches!(
                    receipt.body.outcome,
                    BrokerFailureOutcome::Denied
                        | BrokerFailureOutcome::Reversed
                        | BrokerFailureOutcome::Failed
                )
        }
        AttemptState::Held => {
            receipt.body.stage == BrokerFailureStage::Capture
                && receipt.body.dispatch_knowledge == BrokerDispatchKnowledge::NotCommitted
                && matches!(
                    receipt.body.outcome,
                    BrokerFailureOutcome::Denied
                        | BrokerFailureOutcome::Reversed
                        | BrokerFailureOutcome::Failed
                )
        }
        AttemptState::Captured => {
            attempt.dispatch_claim_id.is_none()
                && receipt.body.stage == BrokerFailureStage::Capture
                && receipt.body.dispatch_knowledge == BrokerDispatchKnowledge::NotCommitted
                && matches!(
                    receipt.body.outcome,
                    BrokerFailureOutcome::Denied | BrokerFailureOutcome::Failed
                )
        }
        AttemptState::DispatchCommitted | AttemptState::UnknownOutcome => {
            attempt.revocation_set_digest.is_some()
                && attempt.budget_commit_index.is_some()
                && attempt.revocation_commit_index.is_some()
                && attempt.authority_commit_index.is_some()
                && attempt.leader_epoch.is_some()
                && matches!(
                    (
                        receipt.body.stage,
                        receipt.body.outcome,
                        receipt.body.dispatch_knowledge,
                    ),
                    (
                        BrokerFailureStage::Dispatch,
                        BrokerFailureOutcome::Unknown,
                        BrokerDispatchKnowledge::Unknown,
                    ) | (
                        BrokerFailureStage::Response | BrokerFailureStage::ReceiptPersistence,
                        BrokerFailureOutcome::Failed,
                        BrokerDispatchKnowledge::Committed,
                    )
                )
        }
        AttemptState::Reversed => target == AttemptState::Reversed,
        AttemptState::Failed => target == AttemptState::Failed,
        AttemptState::Completed => false,
    };
    let post_capture = matches!(
        attempt.state,
        AttemptState::Captured
            | AttemptState::DispatchCommitted
            | AttemptState::UnknownOutcome
            | AttemptState::Completed
    );
    if receipt.body.receipt_id != expected_receipt_id
        || receipt.body.request_digest != registration.request_digest
        || (!binding_is_absent && !binding_is_exact)
        || (post_capture && !binding_is_exact)
        || !projection_is_compatible
    {
        return Err(BrokerError::Storage(
            "durable failure receipt is misbound to its attempt journal".to_string(),
        ));
    }
    let evidence = if post_capture {
        AttemptTransitionEvidence {
            revocation_set_digest: attempt.revocation_set_digest.clone(),
            budget_commit_index: attempt.budget_commit_index,
            revocation_commit_index: attempt.revocation_commit_index,
            authority_commit_index: attempt.authority_commit_index,
            leader_epoch: attempt.leader_epoch,
            response_digest: attempt.response_digest.clone(),
        }
    } else {
        AttemptTransitionEvidence::default()
    };
    Ok((target, evidence))
}

/// Converge broker-signed durable completions before consulting a live
/// execution authority. This closes the crash window after atomic response
/// persistence but before the attempt journal reaches `Completed`.
pub fn reconcile_durable_completions(
    store: &dyn AttemptStore,
    receipt_sink: &dyn BrokerReceiptSink,
    trusted_receipt_signer: &PublicKey,
    limit: usize,
    now_unix_seconds: u64,
) -> Result<Vec<AttemptRecord>> {
    let mut completed = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let pending = store.recoverable_attempts(cursor.as_deref(), limit)?;
        if pending.is_empty() {
            break;
        }
        let next_cursor = pending
            .last()
            .map(|attempt| attempt.registration.ids.attempt_id.clone())
            .ok_or_else(|| {
                BrokerError::Invariant(
                    "durable completion recovery page lost its final attempt".to_string(),
                )
            })?;
        if cursor
            .as_ref()
            .is_some_and(|previous| next_cursor.as_str() <= previous.as_str())
        {
            return Err(BrokerError::Invariant(
                "durable completion recovery cursor did not advance".to_string(),
            ));
        }
        for attempt in &pending {
            let Some(response) =
                receipt_sink.load_completed(&attempt.registration.ids.attempt_id)?
            else {
                continue;
            };
            let evidence =
                validate_completion_for_attempt(attempt, &response, trusted_receipt_signer)?;
            completed.push(store.transition(
                &attempt.registration.ids.attempt_id,
                attempt.state,
                AttemptState::Completed,
                &evidence,
                now_unix_seconds,
            )?);
        }
        cursor = Some(next_cursor);
        if pending.len() < limit {
            break;
        }
    }
    Ok(completed)
}

fn validate_completion_for_attempt(
    attempt: &AttemptRecord,
    response: &BrokerExecuteResponse,
    trusted_receipt_signer: &PublicKey,
) -> Result<AttemptTransitionEvidence> {
    validate_durable_completed_response(response, trusted_receipt_signer)?;
    let registration = &attempt.registration;
    let ids = &registration.ids;
    let evidence = &response.evidence;
    let receipt = &response.receipt.body;
    if !matches!(
        attempt.state,
        AttemptState::DispatchCommitted | AttemptState::UnknownOutcome
    ) || evidence.attempt_id != ids.attempt_id
        || evidence.invocation_id != registration.invocation_id
        || evidence.hold_id != ids.hold_id
        || evidence.request_digest != registration.request_digest
        || attempt.revocation_set_digest.as_ref() != Some(&evidence.revocation_set_digest)
        || attempt.budget_commit_index != Some(evidence.budget_commit_index)
        || attempt.revocation_commit_index != Some(evidence.revocation_commit_index)
        || attempt.authority_commit_index != Some(evidence.authority_commit_index)
        || attempt.leader_epoch != Some(evidence.leader_epoch)
        || attempt
            .response_digest
            .as_ref()
            .is_some_and(|digest| digest != &evidence.response_body_sha256)
        || receipt.receipt_id != format!("broker-receipt-{}", ids.attempt_id)
        || receipt.operation_id != ids.operation_id
        || receipt.authorize_event_id != ids.authorize_event_id
        || receipt.capture_event_id != ids.capture_event_id
        || receipt.parent_capability_id != registration.parent_capability_id
        || receipt.broker_capability_id != registration.broker_capability_id
        || receipt.quotas != registration.quotas
        || receipt.outcome != BrokerExecutionOutcome::Completed
    {
        return Err(BrokerError::Storage(
            "durable completed response is misbound to its attempt journal".to_string(),
        ));
    }
    Ok(AttemptTransitionEvidence {
        revocation_set_digest: Some(evidence.revocation_set_digest.clone()),
        budget_commit_index: Some(evidence.budget_commit_index),
        revocation_commit_index: Some(evidence.revocation_commit_index),
        authority_commit_index: Some(evidence.authority_commit_index),
        leader_epoch: Some(evidence.leader_epoch),
        response_digest: Some(evidence.response_body_sha256.clone()),
    })
}

fn transition_any_nonterminal(
    store: &dyn AttemptStore,
    attempt: &AttemptRecord,
    next: AttemptState,
    evidence: &AttemptTransitionEvidence,
    now_unix_seconds: u64,
) -> Result<AttemptRecord> {
    if attempt.state.permits(next) {
        store.transition(
            &attempt.registration.ids.attempt_id,
            attempt.state,
            next,
            evidence,
            now_unix_seconds,
        )
    } else if attempt.state == next {
        Ok(attempt.clone())
    } else {
        Err(BrokerError::Conflict(
            "authoritative result conflicts with terminal local attempt".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use chio_test_support::prelude::*;
    use std::sync::Mutex;

    use chio_core_types::{Ed25519Backend, Keypair};
    use sha2::{Digest, Sha256};

    use crate::budget::{
        CaptureExecutionHoldRequest, CombinedCaptureCommit, ExecutionAuthorityCapabilities,
        ExecutionAuthorityProfile, ExecutionQuota, ReverseExecutionHoldRequest,
    };
    use crate::protocol::{
        BrokerDestination, BrokerExecuteResponse, BrokerExecutionEvidence, BROKER_EVIDENCE_SCHEMA,
    };
    use crate::receipt::{
        receipt_digest, sign_execution_receipt, sign_failure_receipt, BrokerDispatchKnowledge,
        BrokerExecutionOutcome, BrokerFailureOutcome, BrokerFailureReceiptBody, BrokerFailureStage,
        BrokerReceiptBody, BrokerReceiptSink, SignedBrokerFailureReceipt, SqliteBrokerReceiptSink,
        BROKER_FAILURE_RECEIPT_SCHEMA, BROKER_RECEIPT_SCHEMA,
    };
    use crate::sqlite::SqliteAttemptStore;
    use crate::store::{derive_attempt_ids, AttemptRegistration, RegisterAttemptOutcome};

    use super::*;

    struct RecoveryAuthority {
        state: Mutex<ExecutionHoldState>,
        unavailable: bool,
    }

    impl BrokerExecutionBudget for RecoveryAuthority {
        fn capabilities(&self) -> ExecutionAuthorityCapabilities {
            ExecutionAuthorityCapabilities {
                profile: ExecutionAuthorityProfile::AuthoritativeHoldEvent,
                atomic_multi_key_holds: true,
                combined_capture_and_revocation: true,
                query_by_id: true,
                shared_revocation_write_domain: true,
            }
        }

        fn query_execution_hold(
            &self,
            _request: &QueryExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            if self.unavailable {
                return Err(BrokerError::AuthorityUnavailable(
                    "injected query timeout".to_string(),
                ));
            }
            Ok(self.state.lock().test_expect("state lock").clone())
        }

        fn authorize_execution_hold(
            &self,
            _request: &AuthorizeExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            let mut state = self.state.lock().test_expect("state lock");
            if *state == ExecutionHoldState::Unknown {
                *state = ExecutionHoldState::Held;
            }
            Ok(state.clone())
        }

        fn reverse_execution_hold(
            &self,
            _request: &ReverseExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            Ok(ExecutionHoldState::Reversed)
        }

        fn capture_execution_hold(
            &self,
            _request: &CaptureExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            Ok(self.state.lock().test_expect("state lock").clone())
        }
    }

    fn registration() -> AttemptRegistration {
        let request_digest = "a".repeat(64);
        AttemptRegistration {
            ids: derive_attempt_ids(
                "broker-capability",
                "invocation",
                "nonce-abcdefghijkl",
                &request_digest,
            )
            .test_expect("ids"),
            invocation_id: "invocation".to_string(),
            parent_capability_id: "parent-capability".to_string(),
            broker_capability_id: "broker-capability".to_string(),
            request_digest,
            request_canonical_digest: "d".repeat(64),
            proof_digest: "b".repeat(64),
            proof_key_id: "proof-key".to_string(),
            proof_nonce: "nonce-abcdefghijkl".to_string(),
            nonce_expires_at_unix_seconds: 100,
            quotas: vec![ExecutionQuota {
                key_id: "broker-quota".to_string(),
                maximum_executions: 1,
            }],
            authority_metadata_digest: "c".repeat(64),
            revocation_authority_domain: "combined-authority".to_string(),
        }
    }

    fn inserted(store: &SqliteAttemptStore) -> AttemptRecord {
        match store
            .register_attempt(&registration(), 10)
            .test_expect("register")
        {
            RegisterAttemptOutcome::Inserted(record)
            | RegisterAttemptOutcome::ExactRetry(record) => record,
        }
    }

    fn completed_response(attempt: &AttemptRecord, signer: &Keypair) -> BrokerExecuteResponse {
        let body = b"durable-completed-response".to_vec();
        let evidence = BrokerExecutionEvidence {
            schema: BROKER_EVIDENCE_SCHEMA.to_string(),
            attempt_id: attempt.registration.ids.attempt_id.clone(),
            invocation_id: attempt.registration.invocation_id.clone(),
            hold_id: attempt.registration.ids.hold_id.clone(),
            request_digest: attempt.registration.request_digest.clone(),
            capability_digest: "e".repeat(64),
            revocation_set_digest: attempt
                .revocation_set_digest
                .clone()
                .test_expect("captured revocation digest"),
            budget_commit_index: attempt
                .budget_commit_index
                .test_expect("budget commit index"),
            revocation_commit_index: attempt
                .revocation_commit_index
                .test_expect("revocation commit index"),
            authority_commit_index: attempt
                .authority_commit_index
                .test_expect("authority commit index"),
            leader_epoch: attempt.leader_epoch.test_expect("leader epoch"),
            upstream_status: 200,
            response_body_sha256: hex::encode(Sha256::digest(&body)),
        };
        let receipt = sign_execution_receipt(
            BrokerReceiptBody {
                schema: BROKER_RECEIPT_SCHEMA.to_string(),
                receipt_id: format!("broker-receipt-{}", attempt.registration.ids.attempt_id),
                issued_at_unix_seconds: 13,
                evidence: evidence.clone(),
                operation_id: attempt.registration.ids.operation_id.clone(),
                authorize_event_id: attempt.registration.ids.authorize_event_id.clone(),
                capture_event_id: attempt.registration.ids.capture_event_id.clone(),
                parent_capability_id: attempt.registration.parent_capability_id.clone(),
                broker_capability_id: attempt.registration.broker_capability_id.clone(),
                subject: Keypair::from_seed(&[72; 32]).public_key(),
                credential_reference_hash: "f".repeat(64),
                credential_version: 1,
                normalized_destination: BrokerDestination::parse(
                    "https://example.com/recovery",
                    "POST",
                    false,
                )
                .test_expect("destination"),
                request_body_sha256: "1".repeat(64),
                caller_headers_sha256: "2".repeat(64),
                caller_options_sha256: "3".repeat(64),
                quotas: attempt.registration.quotas.clone(),
                broker_quota_key_id: "broker-quota".to_string(),
                provider_adapter_id: "generic-bearer".to_string(),
                provider_adapter_version: 1,
                request_body_bytes: 8,
                response_body_bytes: u64::try_from(body.len()).test_expect("response length"),
                source_receipt_ids: Vec::new(),
                outcome: BrokerExecutionOutcome::Completed,
            },
            &Ed25519Backend::new(signer.clone()),
        )
        .test_expect("signed execution receipt");
        BrokerExecuteResponse {
            status: evidence.upstream_status,
            headers: Vec::new(),
            body,
            evidence,
            receipt_reference: format!(
                "broker-receipt-sha256-{}",
                receipt_digest(&receipt).test_expect("receipt digest")
            ),
            receipt,
        }
    }

    fn terminal_failure_receipt(
        attempt: &AttemptRecord,
        signer: &Keypair,
    ) -> SignedBrokerFailureReceipt {
        sign_failure_receipt(
            BrokerFailureReceiptBody {
                schema: BROKER_FAILURE_RECEIPT_SCHEMA.to_string(),
                receipt_id: failure_receipt_id_for_canonical_request_digest(
                    &attempt.registration.request_canonical_digest,
                )
                .test_expect("failure receipt id"),
                issued_at_unix_seconds: 12,
                stage: BrokerFailureStage::Hold,
                outcome: BrokerFailureOutcome::Failed,
                diagnostic_code: "chio.broker.authority_unavailable".to_string(),
                request_digest: attempt.registration.request_digest.clone(),
                capability_digest: Some("e".repeat(64)),
                attempt_id: Some(attempt.registration.ids.attempt_id.clone()),
                invocation_id: Some(attempt.registration.invocation_id.clone()),
                hold_id: Some(attempt.registration.ids.hold_id.clone()),
                parent_capability_id: Some(attempt.registration.parent_capability_id.clone()),
                broker_capability_id: Some(attempt.registration.broker_capability_id.clone()),
                dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
            },
            &Ed25519Backend::new(signer.clone()),
        )
        .test_expect("signed terminal failure")
    }

    fn terminal_dispatch_failure_receipt(
        attempt: &AttemptRecord,
        signer: &Keypair,
    ) -> SignedBrokerFailureReceipt {
        sign_failure_receipt(
            BrokerFailureReceiptBody {
                schema: BROKER_FAILURE_RECEIPT_SCHEMA.to_string(),
                receipt_id: failure_receipt_id_for_canonical_request_digest(
                    &attempt.registration.request_canonical_digest,
                )
                .test_expect("failure receipt id"),
                issued_at_unix_seconds: 13,
                stage: BrokerFailureStage::Dispatch,
                outcome: BrokerFailureOutcome::Unknown,
                diagnostic_code: "chio.broker.upstream_failure".to_string(),
                request_digest: attempt.registration.request_digest.clone(),
                capability_digest: Some("e".repeat(64)),
                attempt_id: Some(attempt.registration.ids.attempt_id.clone()),
                invocation_id: Some(attempt.registration.invocation_id.clone()),
                hold_id: Some(attempt.registration.ids.hold_id.clone()),
                parent_capability_id: Some(attempt.registration.parent_capability_id.clone()),
                broker_capability_id: Some(attempt.registration.broker_capability_id.clone()),
                dispatch_knowledge: BrokerDispatchKnowledge::Unknown,
            },
            &Ed25519Backend::new(signer.clone()),
        )
        .test_expect("signed dispatch failure")
    }

    fn unknown_outcome(store: &SqliteAttemptStore) -> AttemptRecord {
        let prepared = inserted(store);
        store
            .transition(
                &prepared.registration.ids.attempt_id,
                AttemptState::Prepared,
                AttemptState::UnknownOutcome,
                &AttemptTransitionEvidence::default(),
                11,
            )
            .test_expect("persist unknown outcome")
    }

    #[test]
    fn unknown_authority_state_leaves_kernel_owned_prepared_attempt_pending() {
        let store = SqliteAttemptStore::open_in_memory().test_expect("store");
        let prepared = inserted(&store);
        let authority = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Unknown),
            unavailable: false,
        };
        let reconciled =
            reconcile_attempt(&store, &authority, &prepared, 11).test_expect("reconcile");
        assert_eq!(reconciled.state, AttemptState::Prepared);
        assert_eq!(
            reconciled.registration.ids.hold_id,
            prepared.registration.ids.hold_id
        );
    }

    #[test]
    fn lost_capture_response_reconciles_to_resumable_capture_after_restart() {
        let directory = crate::private_tempdir().test_expect("directory");
        let trusted_directory =
            std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
        let path = trusted_directory.join("attempts.sqlite");
        let prepared = {
            let store = SqliteAttemptStore::open(&path).test_expect("store");
            inserted(&store)
        };
        let authority = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Captured(CombinedCaptureCommit {
                checked_revocation_set_digest: "d".repeat(64),
                budget_commit_index: 1,
                revocation_commit_index: 2,
                authority_commit_index: 3,
                leader_epoch: 4,
            })),
            unavailable: false,
        };
        let reopened = SqliteAttemptStore::open(&path).test_expect("reopen after lost response");
        let reconciled = reconcile_attempt(&reopened, &authority, &prepared, 11)
            .test_expect("reconcile restart");
        assert_eq!(reconciled.state, AttemptState::Captured);
        assert_eq!(reconciled.budget_commit_index, Some(1));
    }

    #[test]
    fn startup_clears_dead_dispatch_claim_and_keeps_capture_resumable() {
        let store = SqliteAttemptStore::open_in_memory().test_expect("store");
        let prepared = inserted(&store);
        let commit = CombinedCaptureCommit {
            checked_revocation_set_digest: "d".repeat(64),
            budget_commit_index: 1,
            revocation_commit_index: 2,
            authority_commit_index: 3,
            leader_epoch: 4,
        };
        let evidence = AttemptTransitionEvidence {
            revocation_set_digest: Some(commit.checked_revocation_set_digest.clone()),
            budget_commit_index: Some(commit.budget_commit_index),
            revocation_commit_index: Some(commit.revocation_commit_index),
            authority_commit_index: Some(commit.authority_commit_index),
            leader_epoch: Some(commit.leader_epoch),
            response_digest: None,
        };
        store
            .transition(
                &prepared.registration.ids.attempt_id,
                AttemptState::Prepared,
                AttemptState::Captured,
                &evidence,
                11,
            )
            .test_expect("persist captured attempt");
        assert!(store
            .claim_captured_attempt(
                &prepared.registration.ids.attempt_id,
                "dead-dispatch-claim",
                12,
            )
            .test_expect("claim captured attempt"));
        let authority = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Captured(commit)),
            unavailable: false,
        };

        let reconciled =
            reconcile_pending(&store, &authority, 10, 13).test_expect("startup recovery");

        assert_eq!(reconciled.len(), 1);
        assert_eq!(reconciled[0].state, AttemptState::Captured);
        assert_eq!(reconciled[0].dispatch_claim_id, None);
    }

    #[test]
    fn reverse_commit_before_local_ack_reconciles_reversed_after_restart() {
        let directory = crate::private_tempdir().test_expect("directory");
        let trusted_directory =
            std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
        let path = trusted_directory.join("attempts.sqlite");
        let prepared = {
            let store = SqliteAttemptStore::open(&path).test_expect("store");
            inserted(&store)
        };
        let reopened = SqliteAttemptStore::open(&path).test_expect("reopen");
        let authority = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Reversed),
            unavailable: false,
        };
        let reconciled =
            reconcile_attempt(&reopened, &authority, &prepared, 12).test_expect("reconcile");
        assert_eq!(reconciled.state, AttemptState::Reversed);
    }

    #[test]
    fn unknown_outcome_with_authoritative_held_does_not_reverse_kernel_hold() {
        let store = SqliteAttemptStore::open_in_memory().test_expect("store");
        let unknown = unknown_outcome(&store);
        let authority = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Held),
            unavailable: false,
        };

        let reconciled = reconcile_attempt(&store, &authority, &unknown, 12)
            .test_expect("reconcile held outcome");

        assert_eq!(reconciled.state, AttemptState::UnknownOutcome);
        assert_eq!(
            store
                .load_attempt(&unknown.registration.ids.attempt_id)
                .test_expect("load")
                .test_expect("record")
                .state,
            AttemptState::UnknownOutcome
        );
    }

    #[test]
    fn unknown_outcome_with_authoritative_reversed_converges_reversed() {
        let store = SqliteAttemptStore::open_in_memory().test_expect("store");
        let unknown = unknown_outcome(&store);
        let authority = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Reversed),
            unavailable: false,
        };

        let reconciled = reconcile_attempt(&store, &authority, &unknown, 12)
            .test_expect("reconcile reversed outcome");

        assert_eq!(reconciled.state, AttemptState::Reversed);
    }

    #[test]
    fn unknown_outcome_with_authoritative_denied_converges_failed() {
        let store = SqliteAttemptStore::open_in_memory().test_expect("store");
        let unknown = unknown_outcome(&store);
        let authority = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Denied),
            unavailable: false,
        };

        let reconciled = reconcile_attempt(&store, &authority, &unknown, 12)
            .test_expect("reconcile denied outcome");

        assert_eq!(reconciled.state, AttemptState::Failed);
    }

    #[test]
    fn unknown_outcome_with_authoritative_capture_remains_non_resending_terminal() {
        let store = SqliteAttemptStore::open_in_memory().test_expect("store");
        let unknown = unknown_outcome(&store);
        let authority = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Captured(CombinedCaptureCommit {
                checked_revocation_set_digest: "d".repeat(64),
                budget_commit_index: 21,
                revocation_commit_index: 22,
                authority_commit_index: 23,
                leader_epoch: 24,
            })),
            unavailable: false,
        };

        let reconciled = reconcile_attempt(&store, &authority, &unknown, 12)
            .test_expect("reconcile captured outcome");

        assert_eq!(reconciled.state, AttemptState::UnknownOutcome);
        assert_eq!(reconciled.revocation_set_digest, None);
        assert_eq!(reconciled.budget_commit_index, None);
        assert_eq!(reconciled.revocation_commit_index, None);
        assert_eq!(reconciled.authority_commit_index, None);
        assert_eq!(reconciled.leader_epoch, None);
    }

    #[test]
    fn unreachable_authority_leaves_prepared_intent_without_new_side_effect() {
        let store = SqliteAttemptStore::open_in_memory().test_expect("store");
        let prepared = inserted(&store);
        let authority = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Unknown),
            unavailable: true,
        };
        assert!(reconcile_attempt(&store, &authority, &prepared, 11).is_err());
        assert_eq!(
            store
                .load_attempt(&prepared.registration.ids.attempt_id)
                .test_expect("load")
                .test_expect("record")
                .state,
            AttemptState::Prepared
        );
    }

    #[test]
    fn durable_failure_wins_before_unavailable_authority_on_restart() {
        let directory = crate::private_tempdir().test_expect("directory");
        let trusted_directory =
            std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
        let attempt_path = trusted_directory.join("failure-attempts.sqlite3");
        let receipt_path = trusted_directory.join("failure-receipts.sqlite3");
        let signer = Keypair::from_seed(&[73; 32]);
        let attempt_id = {
            let store = SqliteAttemptStore::open(&attempt_path).test_expect("attempt store");
            let prepared = inserted(&store);
            let sink = SqliteBrokerReceiptSink::open(&receipt_path, signer.public_key())
                .test_expect("receipt sink");
            sink.persist_failure(&terminal_failure_receipt(&prepared, &signer))
                .test_expect("persist failure before simulated crash");
            prepared.registration.ids.attempt_id
        };

        let reopened_store =
            SqliteAttemptStore::open(&attempt_path).test_expect("reopen attempt store");
        let reopened_sink = SqliteBrokerReceiptSink::open(&receipt_path, signer.public_key())
            .test_expect("reopen receipt sink");
        let failed = reconcile_durable_failures(
            &reopened_store,
            &reopened_sink,
            &signer.public_key(),
            10,
            13,
        )
        .test_expect("reconcile local durable failure");
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].state, AttemptState::Failed);

        let unavailable = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Unknown),
            unavailable: true,
        };
        assert!(reconcile_pending(&reopened_store, &unavailable, 10, 14)
            .test_expect("no authority call after local failure")
            .is_empty());
        assert_eq!(
            reopened_store
                .load_attempt(&attempt_id)
                .test_expect("load failed attempt")
                .test_expect("failed attempt")
                .state,
            AttemptState::Failed
        );
    }

    #[test]
    fn durable_dispatch_failure_terminalizes_restart_without_resend_recovery() {
        let directory = crate::private_tempdir().test_expect("directory");
        let trusted_directory =
            std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
        let attempt_path = trusted_directory.join("dispatch-attempts.sqlite3");
        let receipt_path = trusted_directory.join("dispatch-receipts.sqlite3");
        let signer = Keypair::from_seed(&[74; 32]);
        let attempt_id = {
            let store = SqliteAttemptStore::open(&attempt_path).test_expect("attempt store");
            let prepared = inserted(&store);
            let capture = AttemptTransitionEvidence {
                revocation_set_digest: Some("4".repeat(64)),
                budget_commit_index: Some(31),
                revocation_commit_index: Some(32),
                authority_commit_index: Some(33),
                leader_epoch: Some(34),
                response_digest: None,
            };
            let captured = store
                .transition(
                    &prepared.registration.ids.attempt_id,
                    AttemptState::Prepared,
                    AttemptState::Captured,
                    &capture,
                    11,
                )
                .test_expect("capture attempt");
            assert!(store
                .claim_captured_attempt(
                    &captured.registration.ids.attempt_id,
                    "dispatch-failure-crash-window-claim",
                    12,
                )
                .test_expect("claim captured attempt"));
            let dispatch_committed = store
                .commit_captured_attempt_dispatch(
                    &captured.registration.ids.attempt_id,
                    "dispatch-failure-crash-window-claim",
                    &capture,
                    12,
                )
                .test_expect("commit dispatch boundary");
            let sink = SqliteBrokerReceiptSink::open(&receipt_path, signer.public_key())
                .test_expect("receipt sink");
            sink.persist_failure(&terminal_dispatch_failure_receipt(
                &dispatch_committed,
                &signer,
            ))
            .test_expect("persist dispatch failure before simulated crash");
            dispatch_committed.registration.ids.attempt_id
        };

        let reopened_store =
            SqliteAttemptStore::open(&attempt_path).test_expect("reopen attempt store");
        let reopened_sink = SqliteBrokerReceiptSink::open(&receipt_path, signer.public_key())
            .test_expect("reopen receipt sink");
        let failed = reconcile_durable_failures(
            &reopened_store,
            &reopened_sink,
            &signer.public_key(),
            10,
            14,
        )
        .test_expect("reconcile durable dispatch failure");
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].state, AttemptState::Failed);

        let unavailable = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Unknown),
            unavailable: true,
        };
        assert!(reconcile_pending(&reopened_store, &unavailable, 10, 15)
            .test_expect("terminal dispatch failure is excluded from live recovery")
            .is_empty());
        assert_eq!(
            reopened_store
                .load_attempt(&attempt_id)
                .test_expect("load failed attempt")
                .test_expect("failed attempt")
                .state,
            AttemptState::Failed
        );
    }

    #[test]
    fn durable_completion_wins_before_unavailable_authority_on_restart() {
        let directory = crate::private_tempdir().test_expect("directory");
        let trusted_directory =
            std::fs::canonicalize(directory.path()).test_expect("canonicalize database directory");
        let attempt_path = trusted_directory.join("attempts.sqlite3");
        let receipt_path = trusted_directory.join("receipts.sqlite3");
        let signer = Keypair::from_seed(&[71; 32]);
        let attempt_id = {
            let store = SqliteAttemptStore::open(&attempt_path).test_expect("attempt store");
            let prepared = inserted(&store);
            let capture = AttemptTransitionEvidence {
                revocation_set_digest: Some("4".repeat(64)),
                budget_commit_index: Some(21),
                revocation_commit_index: Some(22),
                authority_commit_index: Some(23),
                leader_epoch: Some(24),
                response_digest: None,
            };
            let captured = store
                .transition(
                    &prepared.registration.ids.attempt_id,
                    AttemptState::Prepared,
                    AttemptState::Captured,
                    &capture,
                    11,
                )
                .test_expect("capture attempt");
            assert!(store
                .claim_captured_attempt(
                    &captured.registration.ids.attempt_id,
                    "restart-crash-window-claim",
                    12,
                )
                .test_expect("claim captured attempt"));
            let dispatch_committed = store
                .commit_captured_attempt_dispatch(
                    &captured.registration.ids.attempt_id,
                    "restart-crash-window-claim",
                    &capture,
                    12,
                )
                .test_expect("commit dispatch");
            let sink = SqliteBrokerReceiptSink::open(&receipt_path, signer.public_key())
                .test_expect("receipt sink");
            sink.persist_completed(&completed_response(&dispatch_committed, &signer))
                .test_expect("persist response before simulated crash");
            dispatch_committed.registration.ids.attempt_id
        };

        let reopened_store =
            SqliteAttemptStore::open(&attempt_path).test_expect("reopen attempt store");
        let reopened_sink = SqliteBrokerReceiptSink::open(&receipt_path, signer.public_key())
            .test_expect("reopen receipt sink");
        let completed = reconcile_durable_completions(
            &reopened_store,
            &reopened_sink,
            &signer.public_key(),
            10,
            14,
        )
        .test_expect("reconcile local durable response");
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].state, AttemptState::Completed);

        let unavailable = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Unknown),
            unavailable: true,
        };
        assert!(reconcile_pending(&reopened_store, &unavailable, 10, 14)
            .test_expect("no authority call after local completion")
            .is_empty());
        assert_eq!(
            reopened_store
                .load_attempt(&attempt_id)
                .test_expect("load completed attempt")
                .test_expect("completed attempt")
                .state,
            AttemptState::Completed
        );
    }
}
