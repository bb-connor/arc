#[cfg(test)]
mod tests {
    use super::*;

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

    fn prepared_with_binding(
        kind: AdmissionOperationKind,
        request_id: &str,
        budget_hold_id: Option<&str>,
    ) -> AdmissionOperation {
        AdmissionOperation::prepared(PreparedAdmissionOperation {
            kind,
            coordinator_authority_id: "coordinator-1".to_string(),
            request_id: request_id.to_string(),
            capability_id: "capability-1".to_string(),
            authorization_capability_hash: "11".repeat(32),
            request_binding_hash: "22".repeat(32),
            policy_hash: "33".repeat(32),
            broker_attempt_id: (kind == AdmissionOperationKind::ToolDispatch)
                .then(|| "attempt-1".to_string()),
            budget_hold_id: (kind == AdmissionOperationKind::ToolDispatch)
                .then(|| budget_hold_id.map(ToOwned::to_owned))
                .flatten(),
            approval_set_hash: Some("44".repeat(32)),
            execution_nonce_id: (kind == AdmissionOperationKind::ToolDispatch)
                .then(|| "nonce-1".to_string()),
            coordinator_lease_epoch: 7,
        })
        .unwrap()
    }

    fn prepared(kind: AdmissionOperationKind) -> AdmissionOperation {
        prepared_with_binding(kind, "request-1", Some("hold-1"))
    }

    fn request_binding_parts() -> AdmissionRequestBindingParts {
        AdmissionRequestBindingParts {
            action_hash: "11".repeat(32),
            policy_hash: "77".repeat(32),
            governed_intent_hash: None,
            threshold_proposal_hash: Some("22".repeat(32)),
            verified_approval_set_hash: Some("33".repeat(32)),
            approval_token_digests: vec!["44".repeat(32), "55".repeat(32)],
            budget_hold_reference: Some("budget-hold-1".to_string()),
            supplemental_authorization_reference: Some("supplemental-1".to_string()),
            supplemental_authorization_digest: Some("66".repeat(32)),
            execution_nonce_reference: Some("nonce-1".to_string()),
        }
    }

    #[test]
    fn operation_id_is_fixed_and_identity_bound() {
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        assert_eq!(
            operation.operation_id(),
            "c9cd50e1d749c5d8c7dd1616c4f5ef3269ca4be0dd8587339751c88f94aadbee"
        );
        assert_eq!(operation, prepared(AdmissionOperationKind::ToolDispatch));

        let mut changed = prepared(AdmissionOperationKind::ToolDispatch);
        changed.request_id = "request-2".to_string();
        assert_ne!(
            operation.operation_id(),
            derive_operation_id(
                changed.kind,
                &changed.coordinator_authority_id,
                &changed.request_id,
                &changed.capability_id,
                &changed.authorization_capability_hash,
                &changed.request_binding_hash,
            )
            .unwrap()
        );
    }

    #[test]
    fn approval_membership_order_cannot_change_request_binding() {
        let mut unordered = request_binding_parts();
        unordered.approval_token_digests.reverse();
        let left =
            AdmissionRequestBindingInput::from_unordered_approval_token_digests(unordered.clone())
                .unwrap();
        let right = AdmissionRequestBindingInput::new(request_binding_parts()).unwrap();
        assert_eq!(
            left.approval_token_digests(),
            right.approval_token_digests()
        );
        assert_eq!(left.derive_hash().unwrap(), right.derive_hash().unwrap());
        assert!(AdmissionRequestBindingInput::new(unordered).is_err());

        let mut changed_reference_parts = request_binding_parts();
        changed_reference_parts.supplemental_authorization_reference =
            Some("supplemental-2".to_string());
        let changed_reference = AdmissionRequestBindingInput::new(changed_reference_parts).unwrap();
        let mut changed_digest_parts = request_binding_parts();
        changed_digest_parts.supplemental_authorization_digest = Some("77".repeat(32));
        let changed_digest = AdmissionRequestBindingInput::new(changed_digest_parts).unwrap();
        assert_ne!(
            left.derive_hash().unwrap(),
            changed_reference.derive_hash().unwrap()
        );
        assert_ne!(
            left.derive_hash().unwrap(),
            changed_digest.derive_hash().unwrap()
        );
        let mut changed_budget = left.clone();
        changed_budget.budget_hold_reference = Some("budget-hold-2".to_string());
        let mut changed_policy = left.clone();
        changed_policy.policy_hash = "88".repeat(32);
        assert_ne!(
            left.derive_hash().unwrap(),
            changed_budget.derive_hash().unwrap()
        );
        assert_ne!(
            left.derive_hash().unwrap(),
            changed_policy.derive_hash().unwrap()
        );
        let mut duplicate_parts = request_binding_parts();
        duplicate_parts.threshold_proposal_hash = None;
        duplicate_parts.verified_approval_set_hash = None;
        duplicate_parts.approval_token_digests = vec!["44".repeat(32), "44".repeat(32)];
        duplicate_parts.supplemental_authorization_reference = None;
        duplicate_parts.supplemental_authorization_digest = None;
        duplicate_parts.execution_nonce_reference = None;
        assert!(AdmissionRequestBindingInput::new(duplicate_parts).is_err());
    }

    #[test]
    fn compare_and_swap_is_versioned_and_lease_fenced() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        let id = operation.operation_id().to_string();
        assert!(matches!(
            store.create_prepared(operation).unwrap(),
            AdmissionOperationCreateOutcome::Created(_)
        ));

        let applied = store
            .compare_and_swap(cas_request(
                &id,
                0,
                7,
                AdmissionOperationState::BrokerAttemptRegistered,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            ))
            .unwrap();
        let AdmissionOperationCasOutcome::Applied(applied) = applied else {
            panic!("first transition should apply");
        };
        assert_eq!(applied.version(), 1);

        assert!(matches!(
            store
                .compare_and_swap(cas_request(
                    &id,
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
        assert!(matches!(
            store
                .compare_and_swap(cas_request(
                    &id,
                    1,
                    6,
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(_)
        ));
    }

    #[test]
    fn create_prepared_atomically_fences_kind_and_request_id() {
        let store = InMemoryAdmissionOperationStore::new();
        let first = prepared_with_binding(
            AdmissionOperationKind::ToolDispatch,
            "request-owner",
            Some("hold-owner-a"),
        );
        assert!(matches!(
            store.create_prepared(first.clone()).unwrap(),
            AdmissionOperationCreateOutcome::Created(_)
        ));
        assert!(matches!(
            store.create_prepared(first).unwrap(),
            AdmissionOperationCreateOutcome::Existing(_)
        ));
        let conflicting = prepared_with_binding(
            AdmissionOperationKind::ToolDispatch,
            "request-owner",
            Some("hold-owner-b"),
        );
        assert!(matches!(
            store.create_prepared(conflicting),
            Err(AdmissionOperationError::Conflict(_))
        ));
        assert_eq!(
            store
                .load_by_request_id(
                    AdmissionOperationKind::ToolDispatch,
                    "request-owner",
                    2,
                )
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn unresolved_count_includes_unknown_post_dispatch_outcomes() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::GovernedActiveResponse);
        let id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        for (expected_version, state, dispatch) in [
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
                let current = store.load(&id).unwrap().unwrap();
                let action = AdmissionCleanupAction::pending(
                    &current,
                    AdmissionCleanupActionKind::TerminalReceipt,
                    &serde_json::json!({"terminal": state.as_str()}),
                )
                .unwrap();
                store.compare_and_swap_with_cleanup_action(
                    cas_request(
                        &id,
                        expected_version,
                        7,
                        state,
                        dispatch,
                        7,
                        None,
                    ),
                    action,
                )
            } else {
                store.compare_and_swap(cas_request(
                    &id,
                    expected_version,
                    7,
                    state,
                    dispatch,
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
            1,
            "an unknown committed outcome still requires its original authority"
        );
    }

    #[test]
    fn recovery_inventory_is_bounded_and_claim_fences_stale_coordinators() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        let operation_id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();

        assert!(store.list_unresolved(None, 0).unwrap().is_empty());
        assert_eq!(
            store
                .list_unresolved(Some(AdmissionOperationKind::ToolDispatch), 1)
                .unwrap()
                .len(),
            1
        );
        assert!(store
            .list_unresolved(Some(AdmissionOperationKind::GovernedActiveResponse), 1,)
            .unwrap()
            .is_empty());

        let AdmissionOperationCasOutcome::Applied(claimed) =
            store.claim_recovery(&operation_id, 0, 7).unwrap()
        else {
            panic!("recovery claim should apply");
        };
        assert_eq!(claimed.state(), AdmissionOperationState::Prepared);
        assert_eq!(claimed.coordinator_lease_epoch(), 8);
        assert_eq!(claimed.version(), 1);
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

        let terminal_action = AdmissionCleanupAction::pending(
            &claimed,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "compensated_before_dispatch"}),
        )
        .unwrap();
        let AdmissionOperationCasOutcome::Applied(compensation_pending) = store
            .compare_and_swap_with_cleanup_action(
                cas_request(
                    &operation_id,
                    claimed.version(),
                    claimed.coordinator_lease_epoch(),
                    AdmissionOperationState::CompensationPending,
                    AdmissionDispatchState::NotStarted,
                    claimed.coordinator_lease_epoch(),
                    None,
                ),
                terminal_action.clone(),
            )
            .unwrap()
        else {
            panic!("compensation staging should apply");
        };
        assert!(matches!(
            store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        &operation_id,
                        compensation_pending.version(),
                        compensation_pending.coordinator_lease_epoch(),
                        AdmissionOperationState::CompensatedBeforeDispatch,
                        AdmissionDispatchState::NotStarted,
                        compensation_pending.coordinator_lease_epoch(),
                        None,
                    ),
                    terminal_action,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
        assert!(store.list_unresolved(None, 1).unwrap().is_empty());
    }

    #[test]
    fn deterministic_create_recovers_an_advanced_operation() {
        let store = InMemoryAdmissionOperationStore::new();
        let prepared = prepared(AdmissionOperationKind::ToolDispatch);
        let operation_id = prepared.operation_id().to_string();
        store.create_prepared(prepared.clone()).unwrap();
        let advanced = match store
            .compare_and_swap(cas_request(
                &operation_id,
                0,
                7,
                AdmissionOperationState::BudgetAuthorized,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            ))
            .unwrap()
        {
            AdmissionOperationCasOutcome::Applied(operation) => operation,
            other => panic!("unexpected CAS outcome: {other:?}"),
        };
        assert!(matches!(
            store.create_prepared(prepared).unwrap(),
            AdmissionOperationCreateOutcome::Existing(existing) if existing == advanced
        ));
    }

    #[test]
    fn budget_hold_lookup_is_exact_and_unique() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        store.create_prepared(operation.clone()).unwrap();

        assert_eq!(
            store.load_by_budget_hold_id("hold-1").unwrap(),
            Some(operation.clone())
        );
        assert_eq!(store.load_by_budget_hold_id("unknown-hold").unwrap(), None);
        assert!(store
            .create_prepared(prepared_with_binding(
                AdmissionOperationKind::ToolDispatch,
                "request-2",
                Some("hold-1"),
            ))
            .is_err());
        assert_eq!(
            store.load_by_budget_hold_id("hold-1").unwrap(),
            Some(operation)
        );
    }

    #[test]
    fn tool_dispatch_participant_stages_are_linear_and_parseable() {
        assert_eq!(
            AdmissionOperationState::parse("delegated_budget_reserved"),
            Some(AdmissionOperationState::DelegatedBudgetReserved)
        );
        assert_eq!(
            AdmissionOperationState::parse("payment_authorized"),
            Some(AdmissionOperationState::PaymentAuthorized)
        );
        assert_eq!(
            AdmissionOperationState::DelegatedBudgetReserved.as_str(),
            "delegated_budget_reserved"
        );
        assert_eq!(
            AdmissionOperationState::PaymentAuthorized.as_str(),
            "payment_authorized"
        );
        assert_eq!(
            AdmissionOperationState::parse("caller_reservation_capture_pending"),
            Some(AdmissionOperationState::CallerReservationCapturePending)
        );
        assert_eq!(
            AdmissionOperationState::CallerReserved.as_str(),
            "caller_reserved"
        );

        let budget_authorized = prepared(AdmissionOperationKind::ToolDispatch)
            .transition_checked(
                AdmissionOperationState::BudgetAuthorized,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .unwrap();
        assert!(budget_authorized
            .transition_checked(
                AdmissionOperationState::ApprovalReserved,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .is_err());

        let delegated_budget_reserved = budget_authorized
            .transition_checked(
                AdmissionOperationState::DelegatedBudgetReserved,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .unwrap();
        assert!(delegated_budget_reserved
            .transition_checked(
                AdmissionOperationState::ApprovalReserved,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .is_err());

        let payment_authorized = delegated_budget_reserved
            .transition_checked(
                AdmissionOperationState::PaymentAuthorized,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .unwrap();
        assert!(payment_authorized
            .transition_checked(
                AdmissionOperationState::ApprovalReserved,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .is_ok());
    }

    #[test]
    fn caller_reservation_capture_has_a_distinct_committed_lifecycle() {
        let budget_authorized = prepared(AdmissionOperationKind::ToolDispatch)
            .transition_checked(
                AdmissionOperationState::BudgetAuthorized,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .unwrap();
        let ready = budget_authorized
            .transition_checked(
                AdmissionOperationState::ReadyToDispatch,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .unwrap();
        let capture_pending = ready
            .transition_checked(
                AdmissionOperationState::CallerReservationCapturePending,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .unwrap();
        assert!(capture_pending
            .transition_checked(
                AdmissionOperationState::CallerReserved,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .is_err());

        let caller_reserved = capture_pending
            .transition_checked(
                AdmissionOperationState::CallerReserved,
                AdmissionDispatchState::Committed,
                7,
                None,
            )
            .unwrap();
        assert!(!caller_reserved.state().is_terminal());
        assert!(caller_reserved
            .transition_checked(
                AdmissionOperationState::CompensationPending,
                AdmissionDispatchState::NotStarted,
                7,
                Some("must not reverse an issued reservation".to_string()),
            )
            .is_err());
        assert!(caller_reserved
            .transition_checked(
                AdmissionOperationState::Completed,
                AdmissionDispatchState::EffectCompleted,
                7,
                None,
            )
            .is_ok());
        assert!(caller_reserved
            .transition_checked(
                AdmissionOperationState::OutcomeUnknownAfterDispatch,
                AdmissionDispatchState::OutcomeUnknown,
                7,
                Some("reservation expired before reconcile".to_string()),
            )
            .is_ok());
    }

    #[test]
    fn caller_reservation_handoff_actions_enforce_atomic_edge_and_intent_state() {
        let store = InMemoryAdmissionOperationStore::new();
        let prepared = prepared(AdmissionOperationKind::ToolDispatch);
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
    }

    #[test]
    fn dispatch_commit_precedes_effect_terminal_states() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        let id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        let mut version = 0;
        for state in [
            AdmissionOperationState::BrokerAttemptRegistered,
            AdmissionOperationState::BudgetAuthorized,
            AdmissionOperationState::DelegatedBudgetReserved,
            AdmissionOperationState::PaymentAuthorized,
            AdmissionOperationState::ApprovalReserved,
            AdmissionOperationState::ReadyToDispatch,
            AdmissionOperationState::CapturePending,
        ] {
            let AdmissionOperationCasOutcome::Applied(applied) = store
                .compare_and_swap(cas_request(
                    &id,
                    version,
                    7,
                    state,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                ))
                .unwrap()
            else {
                panic!("transition should apply");
            };
            version = applied.version();
        }
        assert!(store
            .compare_and_swap(cas_request(
                &id,
                version,
                7,
                AdmissionOperationState::Completed,
                AdmissionDispatchState::EffectCompleted,
                7,
                None,
            ))
            .is_err());
        let AdmissionOperationCasOutcome::Applied(committed) = store
            .compare_and_swap(cas_request(
                &id,
                version,
                7,
                AdmissionOperationState::DispatchCommitted,
                AdmissionDispatchState::Committed,
                7,
                None,
            ))
            .unwrap()
        else {
            panic!("dispatch commit should apply");
        };
        assert!(matches!(
            store.compare_and_swap(cas_request(
                &id,
                committed.version(),
                7,
                AdmissionOperationState::Completed,
                AdmissionDispatchState::EffectCompleted,
                7,
                None,
            )),
            Err(AdmissionOperationError::Invalid(_))
        ));
        let terminal_action = AdmissionCleanupAction::pending(
            &committed,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "completed"}),
        )
        .unwrap();
        assert!(matches!(
            store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        &id,
                        committed.version(),
                        7,
                        AdmissionOperationState::Completed,
                        AdmissionDispatchState::EffectCompleted,
                        7,
                        None,
                    ),
                    terminal_action,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
    }

    #[test]
    fn dispatch_and_compensation_share_one_versioned_winner_fence() {
        fn capture_pending_store() -> (InMemoryAdmissionOperationStore, AdmissionOperation) {
            let store = InMemoryAdmissionOperationStore::new();
            let operation = prepared(AdmissionOperationKind::ToolDispatch);
            let id = operation.operation_id().to_string();
            store.create_prepared(operation).unwrap();
            let mut current = store.load(&id).unwrap().unwrap();
            for state in [
                AdmissionOperationState::BrokerAttemptRegistered,
                AdmissionOperationState::BudgetAuthorized,
                AdmissionOperationState::DelegatedBudgetReserved,
                AdmissionOperationState::PaymentAuthorized,
                AdmissionOperationState::ApprovalReserved,
                AdmissionOperationState::ReadyToDispatch,
                AdmissionOperationState::CapturePending,
            ] {
                let AdmissionOperationCasOutcome::Applied(next) = store
                    .compare_and_swap(cas_request(
                        &id,
                        current.version(),
                        current.coordinator_lease_epoch(),
                        state,
                        AdmissionDispatchState::NotStarted,
                        current.coordinator_lease_epoch(),
                        None,
                    ))
                    .unwrap()
                else {
                    panic!("capture-pending setup should apply");
                };
                current = next;
            }
            (store, current)
        }

        let (dispatch_store, pending) = capture_pending_store();
        assert!(matches!(
            dispatch_store
                .compare_and_swap(cas_request(
                    pending.operation_id(),
                    pending.version(),
                    pending.coordinator_lease_epoch(),
                    AdmissionOperationState::DispatchCommitted,
                    AdmissionDispatchState::Committed,
                    pending.coordinator_lease_epoch(),
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
        let terminal_action = AdmissionCleanupAction::pending(
            &pending,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "compensated_before_dispatch"}),
        )
        .unwrap();
        assert!(matches!(
            dispatch_store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        pending.operation_id(),
                        pending.version(),
                        pending.coordinator_lease_epoch(),
                        AdmissionOperationState::CompensationPending,
                        AdmissionDispatchState::NotStarted,
                        pending.coordinator_lease_epoch(),
                        Some("loser".to_string()),
                    ),
                    terminal_action,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(current)
                if current.state() == AdmissionOperationState::DispatchCommitted
        ));

        let (compensation_store, pending) = capture_pending_store();
        let terminal_action = AdmissionCleanupAction::pending(
            &pending,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "compensated_before_dispatch"}),
        )
        .unwrap();
        let AdmissionOperationCasOutcome::Applied(compensation_pending) = compensation_store
            .compare_and_swap_with_cleanup_action(
                cas_request(
                    pending.operation_id(),
                    pending.version(),
                    pending.coordinator_lease_epoch(),
                    AdmissionOperationState::CompensationPending,
                    AdmissionDispatchState::NotStarted,
                    pending.coordinator_lease_epoch(),
                    Some("winner".to_string()),
                ),
                terminal_action.clone(),
            )
            .unwrap()
        else {
            panic!("compensation staging should apply");
        };
        assert!(matches!(
            compensation_store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        compensation_pending.operation_id(),
                        compensation_pending.version(),
                        compensation_pending.coordinator_lease_epoch(),
                        AdmissionOperationState::CompensatedBeforeDispatch,
                        AdmissionDispatchState::NotStarted,
                        compensation_pending.coordinator_lease_epoch(),
                        Some("winner".to_string()),
                    ),
                    terminal_action.clone(),
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
        assert!(matches!(
            compensation_store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        pending.operation_id(),
                        pending.version(),
                        pending.coordinator_lease_epoch(),
                        AdmissionOperationState::CompensatedBeforeDispatch,
                        AdmissionDispatchState::NotStarted,
                        pending.coordinator_lease_epoch(),
                        Some("second contender".to_string()),
                    ),
                    terminal_action,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(current)
                if current.state() == AdmissionOperationState::CompensatedBeforeDispatch
        ));
        assert!(matches!(
            compensation_store
                .compare_and_swap(cas_request(
                    pending.operation_id(),
                    pending.version(),
                    pending.coordinator_lease_epoch(),
                    AdmissionOperationState::DispatchCommitted,
                    AdmissionDispatchState::Committed,
                    pending.coordinator_lease_epoch(),
                    Some("second contender".to_string()),
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(current)
                if current.state() == AdmissionOperationState::CompensatedBeforeDispatch
        ));
    }

    #[test]
    fn approval_only_flow_omits_budget_and_dispatches_after_reservation() {
        let operation = prepared(AdmissionOperationKind::GovernedActiveResponse);
        assert!(operation.budget_hold_id().is_none());
        assert!(operation.execution_nonce_id().is_none());
        let store = InMemoryAdmissionOperationStore::new();
        let id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        let AdmissionOperationCasOutcome::Applied(reserved) = store
            .compare_and_swap(cas_request(
                &id,
                0,
                7,
                AdmissionOperationState::ApprovalReserved,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            ))
            .unwrap()
        else {
            panic!("approval reservation should apply");
        };
        assert!(matches!(
            store
                .compare_and_swap(cas_request(
                    &id,
                    reserved.version(),
                    7,
                    AdmissionOperationState::DispatchCommitted,
                    AdmissionDispatchState::Committed,
                    7,
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
    }

    #[test]
    fn cleanup_action_retries_require_the_exact_payload_and_state() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        store.create_prepared(operation.clone()).unwrap();
        let original = AdmissionCleanupAction::pending(
            &operation,
            AdmissionCleanupActionKind::Budget,
            &serde_json::json!({"participant": "budget", "value": 1}),
        )
        .unwrap();
        assert!(matches!(
            store.create_cleanup_action(original.clone()).unwrap(),
            AdmissionCleanupActionCreateOutcome::Created(_)
        ));

        let mut changed_payload = AdmissionCleanupAction::pending(
            &operation,
            AdmissionCleanupActionKind::Budget,
            &serde_json::json!({"participant": "budget", "value": 2}),
        )
        .unwrap();
        changed_payload.action_id = original.action_id().to_string();
        assert!(matches!(
            store.create_cleanup_action(changed_payload.clone()),
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
                changed_payload,
            ),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert_eq!(store.load(operation.operation_id()).unwrap(), Some(operation.clone()));

        let AdmissionCleanupActionClaimOutcome::Claimed(claimed) = store
            .claim_cleanup_action(original.action_id(), "worker", 100, 200)
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
            store.create_cleanup_action(original.clone()),
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
                original,
            ),
            Err(AdmissionOperationError::Invalid(_))
        ));
    }

    #[test]
    fn completed_terminal_action_cannot_finalize_compensation_pending_operation() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
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
    }

    #[test]
    fn cleanup_journal_recovers_every_participant_and_fences_two_workers() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        store.create_prepared(operation.clone()).unwrap();
        let kinds = [
            AdmissionCleanupActionKind::Budget,
            AdmissionCleanupActionKind::Payment,
            AdmissionCleanupActionKind::DelegatedBudget,
            AdmissionCleanupActionKind::Approval,
            AdmissionCleanupActionKind::ExecutionNonce,
            AdmissionCleanupActionKind::Broker,
        ];
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
            assert!(matches!(
                store.create_cleanup_action(action).unwrap(),
                AdmissionCleanupActionCreateOutcome::Created(_)
            ));
        }
        let terminal_action = AdmissionCleanupAction::pending(
            &operation,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "compensated_before_dispatch"}),
        )
        .unwrap();
        assert!(matches!(
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
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
        assert_eq!(
            store
                .list_compensated_with_pending_cleanup(None, 1)
                .unwrap(),
            vec![operation.operation_id().to_string()]
        );

        let releases = AtomicUsize::new(0);
        for action in store
            .load_cleanup_actions(operation.operation_id())
            .unwrap()
        {
            let AdmissionCleanupActionClaimOutcome::Claimed(crashed_claim) = store
                .claim_cleanup_action(action.action_id(), "crashed-worker", 100, 200)
                .unwrap()
            else {
                panic!("first worker should claim the participant");
            };
            assert!(matches!(
                store
                    .claim_cleanup_action(action.action_id(), "concurrent-worker", 150, 250)
                    .unwrap(),
                AdmissionCleanupActionClaimOutcome::Busy(current)
                    if current.version() == crashed_claim.version()
            ));
            let AdmissionCleanupActionClaimOutcome::Claimed(recovered_claim) = store
                .claim_cleanup_action(action.action_id(), "recovery-worker", 200, 300)
                .unwrap()
            else {
                panic!("expired crash claim should be recoverable");
            };
            releases.fetch_add(1, Ordering::SeqCst);

            // Model a successful participant release followed by loss of the
            // cleanup-state write acknowledgement. The durable state is
            // Completed, so exact retry observes completion and cannot run the
            // participant a second time.
            let acknowledged = store
                .acknowledge_cleanup_action(
                    recovered_claim.action_id(),
                    recovered_claim.version(),
                    "recovery-worker",
                )
                .unwrap();
            assert!(matches!(
                acknowledged,
                AdmissionCleanupActionCasOutcome::Applied(_)
            ));
            assert!(matches!(
                store
                    .acknowledge_cleanup_action(
                        recovered_claim.action_id(),
                        recovered_claim.version(),
                        "recovery-worker",
                    )
                    .unwrap(),
                AdmissionCleanupActionCasOutcome::Conflict(current)
                    if current.state() == AdmissionCleanupActionState::Completed
            ));
            assert!(matches!(
                store
                    .claim_cleanup_action(action.action_id(), "late-worker", 400, 500)
                    .unwrap(),
                AdmissionCleanupActionClaimOutcome::Completed(_)
            ));
        }
        assert_eq!(releases.load(Ordering::SeqCst), kinds.len() + 1);
        assert!(store
            .list_compensated_with_pending_cleanup(None, 8)
            .unwrap()
            .is_empty());
    }
}
