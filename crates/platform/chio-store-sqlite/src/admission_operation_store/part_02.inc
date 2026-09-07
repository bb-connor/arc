#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_kernel::{
        AdmissionOperationCompareAndSwap, AdmissionOperationKind, PreparedAdmissionOperation,
    };

    fn cas_request<'a>(
        operation_id: &'a str,
        expected_version: u64,
        coordinator_lease_epoch: u64,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        next_coordinator_lease_epoch: u64,
        last_error: Option<String>,
    ) -> AdmissionOperationCompareAndSwap<'a> {
        AdmissionOperationCompareAndSwap {
            operation_id,
            expected_version,
            coordinator_lease_epoch,
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        }
    }

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_admission_operation_store_creates_private_database_file() {
        use std::os::unix::fs::PermissionsExt;

        let path = unique_db_path("chio-admission-operation-private");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;

        assert_eq!(mode, 0o600);

        drop(store);
        let _ = fs::remove_file(path);
    }

    fn operation_with_binding(request_id: &str, budget_hold_id: &str) -> AdmissionOperation {
        AdmissionOperation::prepared(PreparedAdmissionOperation {
            kind: AdmissionOperationKind::ToolDispatch,
            coordinator_authority_id: "coordinator-1".to_string(),
            request_id: request_id.to_string(),
            capability_id: "capability-1".to_string(),
            authorization_capability_hash: "11".repeat(32),
            request_binding_hash: "22".repeat(32),
            policy_hash: "33".repeat(32),
            broker_attempt_id: Some("attempt-1".to_string()),
            budget_hold_id: Some(budget_hold_id.to_string()),
            approval_set_hash: Some("44".repeat(32)),
            execution_nonce_id: Some("nonce-1".to_string()),
            coordinator_lease_epoch: 7,
        })
        .unwrap()
    }

    fn operation() -> AdmissionOperation {
        operation_with_binding("request-1", "hold-1")
    }

    fn governed_response_operation() -> AdmissionOperation {
        AdmissionOperation::prepared(PreparedAdmissionOperation {
            kind: AdmissionOperationKind::GovernedActiveResponse,
            coordinator_authority_id: "coordinator-1".to_string(),
            request_id: "response-request-1".to_string(),
            capability_id: "response-capability-1".to_string(),
            authorization_capability_hash: "55".repeat(32),
            request_binding_hash: "66".repeat(32),
            policy_hash: "77".repeat(32),
            broker_attempt_id: None,
            budget_hold_id: None,
            approval_set_hash: Some("88".repeat(32)),
            execution_nonce_id: None,
            coordinator_lease_epoch: 7,
        })
        .unwrap()
    }

    #[test]
    fn admission_operation_survives_restart_and_exact_create_retry() {
        let path = unique_db_path("chio-admission-operation-restart");
        let operation = operation();
        {
            let store = SqliteAdmissionOperationStore::open(&path).unwrap();
            assert_eq!(
                store.authority_profile(),
                AdmissionOperationStoreProfile::SingleNodeDurable
            );
            assert!(matches!(
                store.create_prepared(operation.clone()).unwrap(),
                AdmissionOperationCreateOutcome::Created(_)
            ));
        }
        let reopened = SqliteAdmissionOperationStore::open(&path).unwrap();
        assert_eq!(
            reopened.load(operation.operation_id()).unwrap(),
            Some(operation.clone())
        );
        assert!(matches!(
            reopened.create_prepared(operation).unwrap(),
            AdmissionOperationCreateOutcome::Existing(_)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn admission_operation_kind_request_owner_is_unique_and_exact_retryable() {
        let path = unique_db_path("chio-admission-operation-request-owner");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let first = operation_with_binding("request-owner", "hold-owner-a");
        assert!(matches!(
            store.create_prepared(first.clone()).unwrap(),
            AdmissionOperationCreateOutcome::Created(_)
        ));
        assert!(matches!(
            store.create_prepared(first).unwrap(),
            AdmissionOperationCreateOutcome::Existing(_)
        ));
        let conflicting = operation_with_binding("request-owner", "hold-owner-b");
        assert!(matches!(
            store.create_prepared(conflicting),
            Err(AdmissionOperationError::Conflict(_))
        ));
        assert_eq!(
            store
                .load_by_request_id(AdmissionOperationKind::ToolDispatch, "request-owner", 2,)
                .unwrap()
                .len(),
            1
        );
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn budget_hold_lookup_survives_restart_and_rejects_duplicate_owners() {
        let path = unique_db_path("chio-admission-operation-hold-index");
        let operation = operation();
        {
            let store = SqliteAdmissionOperationStore::open(&path).unwrap();
            store.create_prepared(operation.clone()).unwrap();
            assert_eq!(
                store.load_by_budget_hold_id("hold-1").unwrap(),
                Some(operation.clone())
            );
            assert!(store
                .create_prepared(operation_with_binding("request-2", "hold-1"))
                .is_err());
        }
        {
            let store = SqliteAdmissionOperationStore::open(&path).unwrap();
            assert_eq!(
                store.load_by_budget_hold_id("hold-1").unwrap(),
                Some(operation)
            );
            assert_eq!(store.load_by_budget_hold_id("unknown-hold").unwrap(), None);
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn admission_operation_profile_reflects_instance_durability() {
        let memory = SqliteAdmissionOperationStore::open_in_memory().unwrap();
        assert_eq!(
            memory.authority_profile(),
            AdmissionOperationStoreProfile::EphemeralLocal
        );
        assert!(SqliteAdmissionOperationStore::open(":memory:").is_err());
        assert!(SqliteAdmissionOperationStore::open("file::memory:?cache=shared").is_err());
        assert!(
            SqliteAdmissionOperationStore::open("file:admission?mode=memory&cache=shared").is_err()
        );
    }

    #[test]
    fn admission_operation_compare_and_swap_is_durable_and_fenced() {
        let path = unique_db_path("chio-admission-operation-cas");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let operation = operation();
        let operation_id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        let applied = store
            .compare_and_swap(cas_request(
                &operation_id,
                0,
                7,
                AdmissionOperationState::BrokerAttemptRegistered,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            ))
            .unwrap();
        assert!(matches!(applied, AdmissionOperationCasOutcome::Applied(_)));
        assert!(matches!(
            store
                .compare_and_swap(cas_request(
                    &operation_id,
                    0,
                    7,
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(_)
        ));
        drop(store);
        assert_eq!(
            SqliteAdmissionOperationStore::open(&path)
                .unwrap()
                .load(&operation_id)
                .unwrap()
                .unwrap()
                .version(),
            1
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn caller_reservation_handoff_actions_enforce_atomic_edge_and_intent_state() {
        let path = unique_db_path("chio-admission-caller-handoff-edge");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let prepared = operation();
        store.create_prepared(prepared.clone()).unwrap();

        let early_intent = AdmissionCleanupAction::pending(
            &prepared,
            AdmissionCleanupActionKind::CallerReservationHandoffIntent,
            &serde_json::json!({"intent": "early"}),
        )
        .unwrap();
        assert!(matches!(
            store.create_cleanup_action(early_intent),
            Err(AdmissionOperationError::Invalid(_))
        ));
        let direct_final = AdmissionCleanupAction::pending(
            &prepared,
            AdmissionCleanupActionKind::CallerReservationHandoff,
            &serde_json::json!({"response": "direct"}),
        )
        .unwrap();
        assert!(matches!(
            store.create_cleanup_action(direct_final),
            Err(AdmissionOperationError::Invalid(_))
        ));

        let AdmissionOperationCasOutcome::Applied(budget_authorized) = store
            .compare_and_swap(cas_request(
                prepared.operation_id(),
                prepared.version(),
                prepared.coordinator_lease_epoch(),
                AdmissionOperationState::BudgetAuthorized,
                AdmissionDispatchState::NotStarted,
                prepared.coordinator_lease_epoch(),
                None,
            ))
            .unwrap()
        else {
            panic!("budget authorization should apply");
        };
        let intent = AdmissionCleanupAction::pending(
            &budget_authorized,
            AdmissionCleanupActionKind::CallerReservationHandoffIntent,
            &serde_json::json!({"intent": "signed"}),
        )
        .unwrap();
        assert!(matches!(
            store.create_cleanup_action(intent).unwrap(),
            AdmissionCleanupActionCreateOutcome::Created(_)
        ));
        let AdmissionOperationCasOutcome::Applied(ready) = store
            .compare_and_swap(cas_request(
                budget_authorized.operation_id(),
                budget_authorized.version(),
                budget_authorized.coordinator_lease_epoch(),
                AdmissionOperationState::ReadyToDispatch,
                AdmissionDispatchState::NotStarted,
                budget_authorized.coordinator_lease_epoch(),
                None,
            ))
            .unwrap()
        else {
            panic!("ready transition should apply");
        };
        let wrong_edge = AdmissionCleanupAction::pending(
            &ready,
            AdmissionCleanupActionKind::CallerReservationHandoff,
            &serde_json::json!({"response": "wrong-edge"}),
        )
        .unwrap();
        assert!(matches!(
            store.compare_and_swap_with_cleanup_action(
                cas_request(
                    ready.operation_id(),
                    ready.version(),
                    ready.coordinator_lease_epoch(),
                    AdmissionOperationState::CallerReserved,
                    AdmissionDispatchState::Committed,
                    ready.coordinator_lease_epoch(),
                    None,
                ),
                wrong_edge,
            ),
            Err(AdmissionOperationError::Invalid(_))
        ));

        let AdmissionOperationCasOutcome::Applied(capture_pending) = store
            .compare_and_swap(cas_request(
                ready.operation_id(),
                ready.version(),
                ready.coordinator_lease_epoch(),
                AdmissionOperationState::CallerReservationCapturePending,
                AdmissionDispatchState::NotStarted,
                ready.coordinator_lease_epoch(),
                None,
            ))
            .unwrap()
        else {
            panic!("capture-pending transition should apply");
        };
        let final_handoff = AdmissionCleanupAction::pending(
            &capture_pending,
            AdmissionCleanupActionKind::CallerReservationHandoff,
            &serde_json::json!({"response": "exact"}),
        )
        .unwrap();
        assert!(matches!(
            store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        capture_pending.operation_id(),
                        capture_pending.version(),
                        capture_pending.coordinator_lease_epoch(),
                        AdmissionOperationState::CallerReserved,
                        AdmissionDispatchState::Committed,
                        capture_pending.coordinator_lease_epoch(),
                        None,
                    ),
                    final_handoff,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(operation)
                if operation.state() == AdmissionOperationState::CallerReserved
        ));
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn recovery_inventory_and_epoch_claim_survive_restart() {
        let path = unique_db_path("chio-admission-operation-recovery-claim");
        let operation = operation();
        let operation_id = operation.operation_id().to_string();
        {
            let store = SqliteAdmissionOperationStore::open(&path).unwrap();
            store.create_prepared(operation).unwrap();
            let inventory = store
                .list_unresolved(Some(AdmissionOperationKind::ToolDispatch), 1)
                .unwrap();
            assert_eq!(inventory.len(), 1);
            let AdmissionOperationCasOutcome::Applied(claimed) =
                store.claim_recovery(&operation_id, 0, 7).unwrap()
            else {
                panic!("recovery claim should apply");
            };
            assert_eq!(claimed.state(), AdmissionOperationState::Prepared);
            assert_eq!(claimed.coordinator_lease_epoch(), 8);
            assert_eq!(claimed.version(), 1);
            assert!(matches!(
                store.claim_recovery(&operation_id, 0, 7).unwrap(),
                AdmissionOperationCasOutcome::Conflict(_)
            ));
        }
        let reopened = SqliteAdmissionOperationStore::open(&path).unwrap();
        let claimed = reopened.load(&operation_id).unwrap().unwrap();
        assert_eq!(claimed.coordinator_lease_epoch(), 8);
        assert_eq!(claimed.version(), 1);
        assert_eq!(reopened.list_unresolved(None, 1).unwrap(), vec![claimed]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unresolved_authority_count_includes_unknown_post_dispatch_outcome() {
        let path = unique_db_path("chio-admission-operation-unresolved-authority");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let operation = governed_response_operation();
        let operation_id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();

        for (expected_version, state, dispatch_state) in [
            (
                0,
                AdmissionOperationState::ApprovalReserved,
                AdmissionDispatchState::NotStarted,
            ),
            (
                1,
                AdmissionOperationState::DispatchCommitted,
                AdmissionDispatchState::Committed,
            ),
            (
                2,
                AdmissionOperationState::OutcomeUnknownAfterDispatch,
                AdmissionDispatchState::OutcomeUnknown,
            ),
        ] {
            let outcome = if state.is_terminal() {
                let current = store.load(&operation_id).unwrap().unwrap();
                let action = AdmissionCleanupAction::pending(
                    &current,
                    AdmissionCleanupActionKind::TerminalReceipt,
                    &serde_json::json!({"terminal": state.as_str()}),
                )
                .unwrap();
                store.compare_and_swap_with_cleanup_action(
                    cas_request(
                        &operation_id,
                        expected_version,
                        7,
                        state,
                        dispatch_state,
                        7,
                        None,
                    ),
                    action,
                )
            } else {
                store.compare_and_swap(cas_request(
                    &operation_id,
                    expected_version,
                    7,
                    state,
                    dispatch_state,
                    7,
                    None,
                ))
            };
            assert!(matches!(
                outcome.unwrap(),
                AdmissionOperationCasOutcome::Applied(_)
            ));
        }

        assert_eq!(
            store
                .count_unresolved_by_authority(
                    AdmissionOperationKind::GovernedActiveResponse,
                    "coordinator-1",
                )
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .count_unresolved_by_authority(
                    AdmissionOperationKind::ToolDispatch,
                    "coordinator-1",
                )
                .unwrap(),
            0
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn advanced_admission_operation_accepts_deterministic_create_retry() {
        let path = unique_db_path("chio-admission-operation-advanced-retry");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let prepared = operation();
        let operation_id = prepared.operation_id().to_string();
        store.create_prepared(prepared.clone()).unwrap();
        assert!(matches!(
            store
                .compare_and_swap(cas_request(
                    &operation_id,
                    0,
                    7,
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));

        let retry = store.create_prepared(prepared).unwrap();
        let AdmissionOperationCreateOutcome::Existing(existing) = retry else {
            panic!("deterministic retry must return the advanced operation");
        };
        assert_eq!(existing.state(), AdmissionOperationState::BudgetAuthorized);
        assert_eq!(existing.version(), 1);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn participant_stages_survive_restart_and_resume_linearly() {
        let path = unique_db_path("chio-admission-operation-participant-restart");
        let operation = operation();
        let operation_id = operation.operation_id().to_string();
        {
            let store = SqliteAdmissionOperationStore::open(&path).unwrap();
            store.create_prepared(operation).unwrap();
            for (expected_version, state) in [
                (0, AdmissionOperationState::BudgetAuthorized),
                (1, AdmissionOperationState::DelegatedBudgetReserved),
                (2, AdmissionOperationState::PaymentAuthorized),
            ] {
                assert!(matches!(
                    store
                        .compare_and_swap(cas_request(
                            &operation_id,
                            expected_version,
                            7,
                            state,
                            AdmissionDispatchState::NotStarted,
                            7,
                            None,
                        ))
                        .unwrap(),
                    AdmissionOperationCasOutcome::Applied(_)
                ));
            }
        }

        let reopened = SqliteAdmissionOperationStore::open(&path).unwrap();
        let recovered = reopened.load(&operation_id).unwrap().unwrap();
        assert_eq!(
            recovered.state(),
            AdmissionOperationState::PaymentAuthorized
        );
        assert_eq!(recovered.version(), 3);
        assert!(matches!(
            reopened
                .compare_and_swap(cas_request(
                    &operation_id,
                    recovered.version(),
                    recovered.coordinator_lease_epoch(),
                    AdmissionOperationState::ApprovalReserved,
                    AdmissionDispatchState::NotStarted,
                    recovered.coordinator_lease_epoch(),
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn admission_operation_rejects_corrupted_state() {
        let path = unique_db_path("chio-admission-operation-corrupt");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let operation = operation();
        let operation_id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE admission_operations SET state = 'future_state' WHERE operation_id = ?1",
                params![operation_id],
            )
            .unwrap();
        assert!(matches!(
            store.load(&operation_id),
            Err(AdmissionOperationError::Invalid(_))
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn cleanup_action_retries_require_the_exact_payload_and_state() {
        let path = unique_db_path("chio-admission-cleanup-exact-retry");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let operation = operation();
        store.create_prepared(operation.clone()).unwrap();
        let action = AdmissionCleanupAction::pending(
            &operation,
            AdmissionCleanupActionKind::Budget,
            &serde_json::json!({"participant": "budget", "value": 1}),
        )
        .unwrap();
        assert!(matches!(
            store.create_cleanup_action(action.clone()).unwrap(),
            AdmissionCleanupActionCreateOutcome::Created(_)
        ));
        let AdmissionCleanupActionClaimOutcome::Claimed(claimed) = store
            .claim_cleanup_action(action.action_id(), "worker", 100, 200)
            .unwrap()
        else {
            panic!("cleanup action should be claimable");
        };
        assert!(matches!(
            store
                .acknowledge_cleanup_action(claimed.action_id(), claimed.version(), "worker")
                .unwrap(),
            AdmissionCleanupActionCasOutcome::Applied(_)
        ));

        assert!(matches!(
            store.create_cleanup_action(action.clone()),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert!(matches!(
            store.compare_and_swap_with_cleanup_action(
                cas_request(
                    operation.operation_id(),
                    operation.version(),
                    operation.coordinator_lease_epoch(),
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    operation.coordinator_lease_epoch(),
                    None,
                ),
                action.clone(),
            ),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert_eq!(
            store.load(operation.operation_id()).unwrap(),
            Some(operation.clone())
        );

        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE admission_cleanup_actions SET payload_json = ?2 WHERE action_id = ?1",
                params![action.action_id(), r#"{"participant":"budget","value":2}"#],
            )
            .unwrap();
        assert!(matches!(
            store.create_cleanup_action(action.clone()),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert!(matches!(
            store.compare_and_swap_with_cleanup_action(
                cas_request(
                    operation.operation_id(),
                    operation.version(),
                    operation.coordinator_lease_epoch(),
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    operation.coordinator_lease_epoch(),
                    None,
                ),
                action,
            ),
            Err(AdmissionOperationError::Invalid(_))
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn completed_terminal_action_cannot_finalize_compensation_pending_operation() {
        let path = unique_db_path("chio-admission-terminal-action-state");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let operation = operation();
        store.create_prepared(operation.clone()).unwrap();
        let terminal_action = AdmissionCleanupAction::pending(
            &operation,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "compensated_before_dispatch"}),
        )
        .unwrap();
        let AdmissionOperationCasOutcome::Applied(compensation_pending) = store
            .compare_and_swap_with_cleanup_action(
                cas_request(
                    operation.operation_id(),
                    operation.version(),
                    operation.coordinator_lease_epoch(),
                    AdmissionOperationState::CompensationPending,
                    AdmissionDispatchState::NotStarted,
                    operation.coordinator_lease_epoch(),
                    Some("deny".to_string()),
                ),
                terminal_action.clone(),
            )
            .unwrap()
        else {
            panic!("compensation staging should apply");
        };
        let AdmissionCleanupActionClaimOutcome::Claimed(claimed) = store
            .claim_cleanup_action(terminal_action.action_id(), "worker", 100, 200)
            .unwrap()
        else {
            panic!("terminal action should be claimable");
        };
        store
            .acknowledge_cleanup_action(claimed.action_id(), claimed.version(), "worker")
            .unwrap();
        assert!(matches!(
            store.compare_and_swap_with_cleanup_action(
                cas_request(
                    compensation_pending.operation_id(),
                    compensation_pending.version(),
                    compensation_pending.coordinator_lease_epoch(),
                    AdmissionOperationState::CompensatedBeforeDispatch,
                    AdmissionDispatchState::NotStarted,
                    compensation_pending.coordinator_lease_epoch(),
                    Some("deny".to_string()),
                ),
                terminal_action,
            ),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert_eq!(
            store.load(operation.operation_id()).unwrap(),
            Some(compensation_pending)
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn cleanup_journal_survives_each_participant_crash_window() {
        let path = unique_db_path("chio-admission-cleanup-restart");
        let operation = operation();
        let kinds = [
            AdmissionCleanupActionKind::Budget,
            AdmissionCleanupActionKind::Payment,
            AdmissionCleanupActionKind::DelegatedBudget,
            AdmissionCleanupActionKind::Approval,
            AdmissionCleanupActionKind::ExecutionNonce,
            AdmissionCleanupActionKind::Broker,
        ];
        {
            let store = SqliteAdmissionOperationStore::open(&path).unwrap();
            store.create_prepared(operation.clone()).unwrap();
            for kind in kinds {
                let action = AdmissionCleanupAction::pending(
                    &operation,
                    kind,
                    &serde_json::json!({
                        "operationId": operation.operation_id(),
                        "participant": kind.as_str(),
                    }),
                )
                .unwrap();
                store.create_cleanup_action(action).unwrap();
            }
            let terminal_action = AdmissionCleanupAction::pending(
                &operation,
                AdmissionCleanupActionKind::TerminalReceipt,
                &serde_json::json!({"terminal": "compensated_before_dispatch"}),
            )
            .unwrap();
            store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        operation.operation_id(),
                        operation.version(),
                        operation.coordinator_lease_epoch(),
                        AdmissionOperationState::CompensationPending,
                        AdmissionDispatchState::NotStarted,
                        operation.coordinator_lease_epoch(),
                        Some("deny".to_string()),
                    ),
                    terminal_action,
                )
                .unwrap();
            let first = store
                .load_cleanup_actions(operation.operation_id())
                .unwrap()
                .remove(0);
            assert!(matches!(
                store
                    .claim_cleanup_action(first.action_id(), "crashed-worker", 100, 200)
                    .unwrap(),
                AdmissionCleanupActionClaimOutcome::Claimed(_)
            ));
        }

        let reopened = SqliteAdmissionOperationStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .list_compensated_with_pending_cleanup(None, 4)
                .unwrap(),
            vec![operation.operation_id().to_string()]
        );
        for action in reopened
            .load_cleanup_actions(operation.operation_id())
            .unwrap()
        {
            let AdmissionCleanupActionClaimOutcome::Claimed(claimed) = reopened
                .claim_cleanup_action(action.action_id(), "recovery-worker", 200, 300)
                .unwrap()
            else {
                panic!("recovery worker should own the action");
            };
            assert!(matches!(
                reopened
                    .claim_cleanup_action(action.action_id(), "concurrent-worker", 250, 350)
                    .unwrap(),
                AdmissionCleanupActionClaimOutcome::Busy(_)
            ));
            reopened
                .acknowledge_cleanup_action(
                    claimed.action_id(),
                    claimed.version(),
                    "recovery-worker",
                )
                .unwrap();
            assert!(matches!(
                reopened
                    .acknowledge_cleanup_action(
                        claimed.action_id(),
                        claimed.version(),
                        "recovery-worker",
                    )
                    .unwrap(),
                AdmissionCleanupActionCasOutcome::Conflict(current)
                    if current.state() == AdmissionCleanupActionState::Completed
            ));
        }
        drop(reopened);

        let reopened_after_ack_loss = SqliteAdmissionOperationStore::open(&path).unwrap();
        assert!(reopened_after_ack_loss
            .list_compensated_with_pending_cleanup(None, 8)
            .unwrap()
            .is_empty());
        assert!(reopened_after_ack_loss
            .load_cleanup_actions(operation.operation_id())
            .unwrap()
            .iter()
            .all(|action| action.state() == AdmissionCleanupActionState::Completed));
        let _ = fs::remove_file(path);
    }
}
