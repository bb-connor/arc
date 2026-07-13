use crate::budget::{
    AuthorizeExecutionHoldRequest, BrokerExecutionBudget, ExecutionHoldState,
    QueryExecutionHoldRequest, ReverseExecutionHoldRequest,
};
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
    let mut state = authority.query_execution_hold(&query)?;
    if state == ExecutionHoldState::Unknown && attempt.state == AttemptState::Prepared {
        state = authority.authorize_execution_hold(&AuthorizeExecutionHoldRequest {
            operation_id: attempt.registration.ids.operation_id.clone(),
            invocation_id: attempt.registration.invocation_id.clone(),
            parent_capability_id: attempt.registration.parent_capability_id.clone(),
            broker_capability_id: attempt.registration.broker_capability_id.clone(),
            hold_id: attempt.registration.ids.hold_id.clone(),
            authorize_event_id: attempt.registration.ids.authorize_event_id.clone(),
            quotas: attempt.registration.quotas.clone(),
            authority_metadata_digest: attempt.registration.authority_metadata_digest.clone(),
        })?;
    }
    match state {
        ExecutionHoldState::Unknown => Ok(attempt.clone()),
        ExecutionHoldState::Denied => transition_any_nonterminal(
            store,
            attempt,
            AttemptState::Failed,
            &AttemptTransitionEvidence::default(),
            now_unix_seconds,
        ),
        ExecutionHoldState::Held => {
            if matches!(attempt.state, AttemptState::Prepared | AttemptState::Held) {
                let reverse = ReverseExecutionHoldRequest {
                    operation_id: attempt.registration.ids.operation_id.clone(),
                    invocation_id: attempt.registration.invocation_id.clone(),
                    parent_capability_id: attempt.registration.parent_capability_id.clone(),
                    broker_capability_id: attempt.registration.broker_capability_id.clone(),
                    hold_id: attempt.registration.ids.hold_id.clone(),
                    reverse_event_id: attempt.registration.ids.reverse_event_id.clone(),
                    proof_dispatch_did_not_begin: true,
                };
                reverse.validate()?;
                match authority.reverse_execution_hold(&reverse)? {
                    ExecutionHoldState::Reversed => store.transition(
                        &attempt.registration.ids.attempt_id,
                        attempt.state,
                        AttemptState::Reversed,
                        &AttemptTransitionEvidence::default(),
                        now_unix_seconds,
                    ),
                    ExecutionHoldState::Captured(commit) => {
                        transition_captured_unknown(store, attempt, commit, now_unix_seconds)
                    }
                    _ => Err(BrokerError::AuthorityUnavailable(
                        "held execution could not be authoritatively reversed".to_string(),
                    )),
                }
            } else {
                transition_unknown(store, attempt, now_unix_seconds)
            }
        }
        ExecutionHoldState::Reversed => transition_any_nonterminal(
            store,
            attempt,
            AttemptState::Reversed,
            &AttemptTransitionEvidence::default(),
            now_unix_seconds,
        ),
        ExecutionHoldState::Captured(commit) => {
            transition_captured_unknown(store, attempt, commit, now_unix_seconds)
        }
    }
}

fn transition_captured_unknown(
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
    if matches!(
        attempt.state,
        AttemptState::Prepared
            | AttemptState::Held
            | AttemptState::Captured
            | AttemptState::DispatchCommitted
    ) {
        store.transition(
            &attempt.registration.ids.attempt_id,
            attempt.state,
            AttemptState::UnknownOutcome,
            &evidence,
            now_unix_seconds,
        )
    } else {
        Ok(attempt.clone())
    }
}

pub fn reconcile_pending(
    store: &dyn AttemptStore,
    authority: &dyn BrokerExecutionBudget,
    limit: usize,
    now_unix_seconds: u64,
) -> Result<Vec<AttemptRecord>> {
    let pending = store.recoverable_attempts(limit)?;
    pending
        .iter()
        .map(|attempt| reconcile_attempt(store, authority, attempt, now_unix_seconds))
        .collect()
}

fn transition_unknown(
    store: &dyn AttemptStore,
    attempt: &AttemptRecord,
    now_unix_seconds: u64,
) -> Result<AttemptRecord> {
    if matches!(
        attempt.state,
        AttemptState::Prepared
            | AttemptState::Held
            | AttemptState::Captured
            | AttemptState::DispatchCommitted
    ) {
        store.transition(
            &attempt.registration.ids.attempt_id,
            attempt.state,
            AttemptState::UnknownOutcome,
            &AttemptTransitionEvidence::default(),
            now_unix_seconds,
        )
    } else {
        Ok(attempt.clone())
    }
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
    use std::sync::Mutex;

    use crate::budget::{
        CaptureExecutionHoldRequest, CombinedCaptureCommit, ExecutionAuthorityCapabilities,
        ExecutionAuthorityProfile, ExecutionQuota, ReverseExecutionHoldRequest,
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
            Ok(self.state.lock().expect("state lock").clone())
        }

        fn authorize_execution_hold(
            &self,
            _request: &AuthorizeExecutionHoldRequest,
        ) -> Result<ExecutionHoldState> {
            let mut state = self.state.lock().expect("state lock");
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
            Ok(self.state.lock().expect("state lock").clone())
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
            .expect("ids"),
            invocation_id: "invocation".to_string(),
            parent_capability_id: "parent-capability".to_string(),
            broker_capability_id: "broker-capability".to_string(),
            request_digest,
            proof_digest: "b".repeat(64),
            proof_key_id: "proof-key".to_string(),
            proof_nonce: "nonce-abcdefghijkl".to_string(),
            nonce_expires_at_unix_seconds: 100,
            quotas: vec![ExecutionQuota {
                key_id: "broker-quota".to_string(),
                maximum_executions: 1,
            }],
            authority_metadata_digest: "c".repeat(64),
        }
    }

    fn inserted(store: &SqliteAttemptStore) -> AttemptRecord {
        match store
            .register_attempt(&registration(), 10)
            .expect("register")
        {
            RegisterAttemptOutcome::Inserted(record)
            | RegisterAttemptOutcome::ExactRetry(record) => record,
        }
    }

    #[test]
    fn crash_before_remote_call_retries_same_ids_then_reverses_the_orphan_hold() {
        let store = SqliteAttemptStore::open_in_memory().expect("store");
        let prepared = inserted(&store);
        let authority = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Unknown),
            unavailable: false,
        };
        let reconciled = reconcile_attempt(&store, &authority, &prepared, 11).expect("reconcile");
        assert_eq!(reconciled.state, AttemptState::Reversed);
        assert_eq!(
            reconciled.registration.ids.hold_id,
            prepared.registration.ids.hold_id
        );
    }

    #[test]
    fn capture_commit_before_local_ack_becomes_unknown_and_never_dispatches() {
        let store = SqliteAttemptStore::open_in_memory().expect("store");
        let prepared = inserted(&store);
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
        let reconciled = reconcile_attempt(&store, &authority, &prepared, 11).expect("reconcile");
        assert_eq!(reconciled.state, AttemptState::UnknownOutcome);
        assert_eq!(reconciled.budget_commit_index, Some(1));
    }

    #[test]
    fn reverse_commit_before_local_ack_reconciles_reversed_after_restart() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("attempts.sqlite");
        let prepared = {
            let store = SqliteAttemptStore::open(&path).expect("store");
            inserted(&store)
        };
        let reopened = SqliteAttemptStore::open(&path).expect("reopen");
        let authority = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Reversed),
            unavailable: false,
        };
        let reconciled =
            reconcile_attempt(&reopened, &authority, &prepared, 12).expect("reconcile");
        assert_eq!(reconciled.state, AttemptState::Reversed);
    }

    #[test]
    fn unreachable_authority_leaves_prepared_intent_without_new_side_effect() {
        let store = SqliteAttemptStore::open_in_memory().expect("store");
        let prepared = inserted(&store);
        let authority = RecoveryAuthority {
            state: Mutex::new(ExecutionHoldState::Unknown),
            unavailable: true,
        };
        assert!(reconcile_attempt(&store, &authority, &prepared, 11).is_err());
        assert_eq!(
            store
                .load_attempt(&prepared.registration.ids.attempt_id)
                .expect("load")
                .expect("record")
                .state,
            AttemptState::Prepared
        );
    }
}
