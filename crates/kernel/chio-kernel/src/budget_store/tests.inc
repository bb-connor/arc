    use super::*;

    #[test]
    fn hard_invocation_guarantee_requires_a_matching_authoritative_topology() {
        assert!(BudgetGuaranteeLevel::SingleNodeAtomic
            .supports_hard_invocation_limit(BudgetStoreProfile::SingleNodeDurable, 1,));
        assert!(!BudgetGuaranteeLevel::SingleNodeAtomic
            .supports_hard_invocation_limit(BudgetStoreProfile::SharedLinearizable, 2,));
        assert!(BudgetGuaranteeLevel::HaLinearizable
            .supports_hard_invocation_limit(BudgetStoreProfile::SharedLinearizable, 2,));
        assert!(!BudgetGuaranteeLevel::HaLinearizable
            .supports_hard_invocation_limit(BudgetStoreProfile::SingleNodeDurable, 1,));
        assert!(!BudgetGuaranteeLevel::PartitionEscrowed
            .supports_hard_invocation_limit(BudgetStoreProfile::SharedLinearizable, 2,));
        assert!(!BudgetGuaranteeLevel::AdvisoryPosthoc
            .supports_hard_invocation_limit(BudgetStoreProfile::SharedLinearizable, 2,));
    }

    fn quota(
        profile: BudgetQuotaProfile,
        owner_id: &str,
        grant_index: Option<u32>,
        max_invocations: u32,
    ) -> BudgetInvocationQuota {
        BudgetInvocationQuota {
            key: BudgetQuotaKey {
                profile,
                owner_id: owner_id.to_string(),
                grant_index,
            },
            max_invocations,
        }
    }

    fn composite_operation_binding(hold_id: &str) -> BudgetAdmissionOperationBinding {
        BudgetAdmissionOperationBinding::new(
            format!("operation-{hold_id}"),
            "44".repeat(32),
        )
        .unwrap()
    }

    fn composite_request(
        hold_id: &str,
        event_id: &str,
        quotas: Vec<BudgetInvocationQuota>,
    ) -> BudgetAuthorizeHoldRequest {
        let invocation_admission = VerifiedInvocationAdmission {
            quotas,
            revocation_set: CanonicalRevocationSet::new("cap-composite", &[], &[]).unwrap(),
            aggregate_root_capability_id: None,
            aggregate_binding_digest: None,
            supplemental_binding: Some(SupplementalQuotaBinding {
                artifact_digest: "11".repeat(32),
                verifier_id: "test-verifier".to_string(),
                request_binding_hash: "22".repeat(32),
                negotiated_features_digest: "33".repeat(32),
            }),
        };
        BudgetAuthorizeHoldRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            max_invocations: None,
            requested_exposure_units: 100,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(1_000),
            hold_id: Some(hold_id.to_string()),
            event_id: Some(event_id.to_string()),
            authority: None,
            admission_operation: Some(composite_operation_binding(hold_id)),
            invocation_admission: Some(invocation_admission),
            payment_journal: None,
        }
    }

    fn three_quotas(aggregate_max: u32) -> Vec<BudgetInvocationQuota> {
        vec![
            quota(
                BudgetQuotaProfile::GrantInvocation,
                "cap-composite",
                Some(0),
                2,
            ),
            quota(
                BudgetQuotaProfile::AggregateCapabilityInvocation,
                "cap-composite",
                None,
                aggregate_max,
            ),
            quota(
                BudgetQuotaProfile::SupplementalBrokerExecution,
                &"22".repeat(32),
                None,
                2,
            ),
        ]
    }

    #[test]
    fn authorization_request_exposes_verified_admission_evidence_read_only() {
        let mut quotas = three_quotas(3);
        quotas[1].key.profile = BudgetQuotaProfile::AggregateFamilyInvocation;
        quotas[1].key.owner_id = "55".repeat(32);
        let mut request = composite_request("hold-evidence", "event-evidence", quotas);
        let admission = request.invocation_admission.as_mut().unwrap();
        admission.aggregate_root_capability_id = Some("family-root".to_string());
        admission.aggregate_binding_digest = Some("44".repeat(32));

        let evidence = request
            .invocation_admission_evidence()
            .expect("verified admission evidence");
        assert_eq!(evidence.quotas(), request.invocation_quotas());
        assert_eq!(
            evidence.revocation_set().digest(),
            request.revocation_set().unwrap().digest()
        );
        assert_eq!(
            evidence.aggregate_binding_digest(),
            Some("44".repeat(32).as_str())
        );
        assert_eq!(evidence.aggregate_root_capability_id(), Some("family-root"));
        assert_eq!(
            evidence.supplemental_artifact_digest(),
            Some("11".repeat(32).as_str())
        );
        assert_eq!(evidence.supplemental_verifier_id(), Some("test-verifier"));
        assert_eq!(
            evidence.supplemental_request_binding_hash(),
            Some("22".repeat(32).as_str())
        );
        assert_eq!(
            evidence.supplemental_negotiated_features_digest(),
            Some("33".repeat(32).as_str())
        );
    }

    #[test]
    fn persisted_quota_descriptors_revalidate_the_structured_key() {
        let key = BudgetQuotaKey::from_persisted_parts(
            BudgetQuotaProfile::GrantInvocation,
            "cap-persisted".to_string(),
            Some(7),
        )
        .unwrap();
        let quota = BudgetInvocationQuota::from_persisted_parts(key, 11).unwrap();
        assert_eq!(quota.key().profile(), BudgetQuotaProfile::GrantInvocation);
        assert_eq!(quota.key().owner_id(), "cap-persisted");
        assert_eq!(quota.key().grant_index(), Some(7));
        assert_eq!(quota.max_invocations(), 11);

        assert!(BudgetQuotaKey::from_persisted_parts(
            BudgetQuotaProfile::AggregateFamilyInvocation,
            "not-a-digest".to_string(),
            None,
        )
        .is_err());
        assert!(BudgetQuotaKey::from_persisted_parts(
            BudgetQuotaProfile::AggregateCapabilityInvocation,
            "cap-persisted".to_string(),
            Some(7),
        )
        .is_err());
    }

    #[test]
    fn persisted_quota_usage_revalidates_counters_and_states() {
        let quota = BudgetInvocationQuota::from_persisted_parts(
            BudgetQuotaKey::grant("cap-persisted", 0).unwrap(),
            2,
        )
        .unwrap();
        assert!(BudgetInvocationQuotaUsage {
            quota: quota.clone(),
            reserved_invocations_after: 1,
            captured_invocations_after: 1,
        }
        .validate()
        .is_ok());
        assert!(BudgetInvocationQuotaUsage {
            quota,
            reserved_invocations_after: 2,
            captured_invocations_after: 1,
        }
        .validate()
        .is_err());

        for state in [
            BudgetInvocationReservationState::Absent,
            BudgetInvocationReservationState::Authorized,
            BudgetInvocationReservationState::Captured,
            BudgetInvocationReservationState::Reversed,
            BudgetInvocationReservationState::Denied,
        ] {
            assert_eq!(
                BudgetInvocationReservationState::parse(state.as_str()),
                Some(state)
            );
        }
        assert_eq!(BudgetInvocationReservationState::parse("unknown"), None);

        for state in [
            BudgetMonetaryHoldState::None,
            BudgetMonetaryHoldState::Exposed,
            BudgetMonetaryHoldState::Released,
            BudgetMonetaryHoldState::Reconciled,
            BudgetMonetaryHoldState::Captured,
            BudgetMonetaryHoldState::Reversed,
        ] {
            assert_eq!(BudgetMonetaryHoldState::parse(state.as_str()), Some(state));
        }
        assert_eq!(BudgetMonetaryHoldState::parse("unknown"), None);
    }

    #[test]
    fn composite_hold_reserves_all_quotas_or_none() {
        let store = InMemoryBudgetStore::new();
        assert_eq!(
            store.authority_profile(),
            BudgetStoreProfile::EphemeralLocal
        );
        let first = store
            .authorize_budget_hold(composite_request(
                "hold-composite-1",
                "event-composite-1",
                three_quotas(1),
            ))
            .unwrap();
        let BudgetAuthorizeHoldDecision::Authorized(first) = first else {
            panic!("first composite hold should be authorized");
        };
        assert_eq!(first.invocation_counts_after.len(), 3);
        assert!(first
            .invocation_counts_after
            .iter()
            .all(|count| count.invocation_count_after().unwrap() == 1));
        assert_eq!(
            first.invocation_state,
            BudgetInvocationReservationState::Authorized
        );
        assert_eq!(first.monetary_state, BudgetMonetaryHoldState::Exposed);

        let second = store
            .authorize_budget_hold(composite_request(
                "hold-composite-2",
                "event-composite-2",
                three_quotas(1),
            ))
            .unwrap();
        let BudgetAuthorizeHoldDecision::Denied(second) = second else {
            panic!("exhausted aggregate quota should deny the whole hold");
        };
        assert_eq!(second.invocation_counts_after.len(), 3);
        assert!(second
            .invocation_counts_after
            .iter()
            .all(|count| count.invocation_count_after().unwrap() == 1));
        assert_eq!(second.committed_cost_units_after, 100);
    }

    #[test]
    fn composite_hold_rejects_duplicate_changed_maximum_and_nine_claims() {
        let store = InMemoryBudgetStore::new();
        let mut duplicate = three_quotas(2);
        duplicate.push(duplicate[0].clone());
        assert!(matches!(
            store.authorize_budget_hold(composite_request(
                "hold-duplicate",
                "event-duplicate",
                duplicate,
            )),
            Err(BudgetStoreError::Invariant(_))
        ));

        store
            .authorize_budget_hold(composite_request(
                "hold-max-1",
                "event-max-1",
                three_quotas(2),
            ))
            .unwrap();
        let mut changed = three_quotas(2);
        changed[0].max_invocations = 3;
        assert!(matches!(
            store.authorize_budget_hold(composite_request("hold-max-2", "event-max-2", changed,)),
            Err(BudgetStoreError::Invariant(_))
        ));

        let nine = (0..9)
            .map(|index| {
                quota(
                    BudgetQuotaProfile::AggregateFamilyInvocation,
                    &format!("family-{index}"),
                    None,
                    1,
                )
            })
            .collect();
        assert!(matches!(
            store.authorize_budget_hold(composite_request("hold-nine", "event-nine", nine,)),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn denied_first_presentations_pin_immutable_maxima() {
        let compatibility = InMemoryBudgetStore::new();
        assert!(!compatibility
            .try_increment("cap-denied-first", 0, Some(0))
            .unwrap());
        assert!(matches!(
            compatibility.try_increment("cap-denied-first", 0, Some(1)),
            Err(BudgetStoreError::Invariant(_))
        ));

        let composite = InMemoryBudgetStore::new();
        let denied = composite
            .authorize_budget_hold(composite_request(
                "hold-denied-first",
                "event-denied-first",
                three_quotas(0),
            ))
            .unwrap();
        assert!(matches!(denied, BudgetAuthorizeHoldDecision::Denied(_)));
        assert!(matches!(
            composite.authorize_budget_hold(composite_request(
                "hold-denied-first-raised",
                "event-denied-first-raised",
                three_quotas(1),
            )),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn capture_and_reconcile_have_independent_substates() {
        let store = InMemoryBudgetStore::new();
        store
            .authorize_budget_hold(composite_request(
                "hold-independent",
                "event-independent-authorize",
                three_quotas(2),
            ))
            .unwrap();

        let capture_request = BudgetCaptureInvocationRequest {
            capability_id: "cap-composite".to_string(),
            grant_index: 0,
            hold_id: Some("hold-independent".to_string()),
            event_id: Some("event-independent-capture".to_string()),
            authority: None,
            admission_operation: Some(composite_operation_binding("hold-independent")),
        };
        assert_eq!(
            store.query_invocation_capture(&capture_request).unwrap(),
            None
        );
        let captured = store
            .capture_invocation_reservations(capture_request.clone())
            .unwrap();
        assert_eq!(
            store.query_invocation_capture(&capture_request).unwrap(),
            Some(captured.clone())
        );
        let mut rebound_capture = capture_request;
        rebound_capture.capability_id = "different-capability".to_string();
        assert!(matches!(
            store.query_invocation_capture(&rebound_capture),
            Err(BudgetStoreError::Invariant(_))
        ));
        assert_eq!(
            captured.invocation_state,
            BudgetInvocationReservationState::Captured
        );
        assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Exposed);
        assert_eq!(captured.committed_cost_units_after, 100);

        let reconciled = store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 60,
                hold_id: Some("hold-independent".to_string()),
                event_id: Some("event-independent-reconcile".to_string()),
                authority: None,
                admission_operation: Some(composite_operation_binding("hold-independent")),
            })
            .unwrap();
        assert_eq!(
            reconciled.invocation_state,
            BudgetInvocationReservationState::Captured
        );
        assert_eq!(
            reconciled.monetary_state,
            BudgetMonetaryHoldState::Reconciled
        );
        assert_eq!(reconciled.committed_cost_units_after, 60);
        assert_eq!(
            store
                .get_usage("cap-composite", 0)
                .unwrap()
                .unwrap()
                .total_cost_realized_spend,
            60
        );
        assert!(reconciled
            .invocation_counts_after
            .iter()
            .all(|count| count.invocation_count_after().unwrap() == 1));
    }

    #[test]
    fn operation_owned_reservation_stamp_round_trips_and_rejects_rebinding() {
        let store = InMemoryBudgetStore::new();
        let hold_id = "hold-reservation-stamp";
        let binding = composite_operation_binding(hold_id);
        store
            .authorize_budget_hold(composite_request(
                hold_id,
                "event-reservation-stamp-authorize",
                three_quotas(2),
            ))
            .unwrap();
        let envelope = ReservedHoldEnvelope {
            budget_total: Some(1_000),
            delegation_depth: 2,
            root_budget_holder: "root-capability".to_string(),
        };
        store
            .mark_admission_operation_hold_reserved(
                hold_id,
                &binding,
                1_234,
                Some("USD"),
                Some("payment-reference"),
                &envelope,
            )
            .unwrap();
        store
            .mark_admission_operation_hold_reserved(
                hold_id,
                &binding,
                1_234,
                Some("USD"),
                Some("payment-reference"),
                &envelope,
            )
            .unwrap();
        store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                hold_id: Some(hold_id.to_string()),
                event_id: Some("event-reservation-stamp-capture".to_string()),
                authority: None,
                admission_operation: Some(binding.clone()),
            })
            .unwrap();
        store
            .mark_admission_operation_hold_reserved(
                hold_id,
                &binding,
                1_234,
                Some("USD"),
                Some("payment-reference"),
                &envelope,
            )
            .unwrap();
        let rebound = BudgetAdmissionOperationBinding::new(
            "different-operation".to_string(),
            binding.request_binding_hash().to_string(),
        )
        .unwrap();
        assert!(matches!(
            store.mark_admission_operation_hold_reserved(
                hold_id,
                &rebound,
                1_234,
                Some("USD"),
                Some("payment-reference"),
                &envelope,
            ),
            Err(BudgetStoreError::Conflict(_))
        ));
        let snapshot = store.get_budget_hold(hold_id).unwrap().unwrap();
        assert_eq!(snapshot.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(snapshot.reserved_until, Some(1_234));
        assert_eq!(snapshot.reserved_currency.as_deref(), Some("USD"));
        assert_eq!(
            snapshot.reserved_payment_reference.as_deref(),
            Some("payment-reference")
        );
        assert_eq!(snapshot.reserved_budget_total, Some(1_000));
        assert_eq!(snapshot.reserved_delegation_depth, Some(2));
        assert_eq!(
            snapshot.reserved_root_budget_holder.as_deref(),
            Some("root-capability")
        );
        assert_eq!(store.reap_expired_reserved_holds(1_234).unwrap(), 1);
        let expired = store.get_budget_hold(hold_id).unwrap().unwrap();
        assert_eq!(expired.disposition, BudgetHoldDispositionView::Expired);
        assert_eq!(expired.reserved_until, Some(1_234));
        assert_eq!(expired.reserved_currency.as_deref(), Some("USD"));
        assert_eq!(
            store
                .get_usage("cap-composite", 0)
                .unwrap()
                .unwrap()
                .total_cost_realized_spend,
            100
        );
        assert_eq!(store.reap_expired_reserved_holds(1_234).unwrap(), 0);
    }

    #[test]
    fn zero_exposure_composite_hold_is_stamped_without_a_legacy_hold() {
        let store = InMemoryBudgetStore::new();
        let hold_id = "hold-zero-reservation-stamp";
        let binding = composite_operation_binding(hold_id);
        let mut request = composite_request(
            hold_id,
            "event-zero-reservation-stamp-authorize",
            three_quotas(2),
        );
        request.requested_exposure_units = 0;
        request.max_cost_per_invocation = None;
        request.max_total_cost_units = None;
        store.authorize_budget_hold(request).unwrap();
        let envelope = ReservedHoldEnvelope {
            budget_total: None,
            delegation_depth: 0,
            root_budget_holder: "root-capability".to_string(),
        };
        store
            .mark_admission_operation_hold_reserved(
                hold_id, &binding, 2_345, None, None, &envelope,
            )
            .unwrap();
        store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                hold_id: Some(hold_id.to_string()),
                event_id: Some("event-zero-reservation-stamp-capture".to_string()),
                authority: None,
                admission_operation: Some(binding.clone()),
            })
            .unwrap();

        let snapshot = store.get_budget_hold(hold_id).unwrap().unwrap();
        assert_eq!(snapshot.authorized_exposure_units, 0);
        assert_eq!(snapshot.remaining_exposure_units, 0);
        assert_eq!(snapshot.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(snapshot.reserved_until, Some(2_345));
        assert_eq!(snapshot.reserved_currency, None);
        assert_eq!(snapshot.reserved_budget_total, None);
        assert_eq!(store.reap_expired_reserved_holds(2_345).unwrap(), 1);
        let expired = store.get_budget_hold(hold_id).unwrap().unwrap();
        assert_eq!(expired.disposition, BudgetHoldDispositionView::Expired);
        assert_eq!(expired.reserved_until, Some(2_345));
    }

    #[test]
    fn monetary_capture_preserves_and_then_allows_invocation_capture() {
        let store = InMemoryBudgetStore::new();
        store
            .authorize_budget_hold(composite_request(
                "hold-monetary-capture",
                "event-monetary-capture-authorize",
                three_quotas(2),
            ))
            .unwrap();
        let captured_monetary = store
            .capture_budget_hold(BudgetCaptureHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 60,
                hold_id: Some("hold-monetary-capture".to_string()),
                event_id: Some("event-monetary-capture".to_string()),
                authority: None,
                admission_operation: Some(composite_operation_binding("hold-monetary-capture")),
            })
            .unwrap();
        assert_eq!(
            captured_monetary.invocation_state,
            BudgetInvocationReservationState::Authorized
        );
        assert_eq!(
            captured_monetary.monetary_state,
            BudgetMonetaryHoldState::Captured
        );

        let captured_invocation = store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                hold_id: Some("hold-monetary-capture".to_string()),
                event_id: Some("event-invocation-after-monetary-capture".to_string()),
                authority: None,
                admission_operation: Some(composite_operation_binding("hold-monetary-capture")),
            })
            .unwrap();
        assert_eq!(
            captured_invocation.invocation_state,
            BudgetInvocationReservationState::Captured
        );
        assert_eq!(
            captured_invocation.monetary_state,
            BudgetMonetaryHoldState::Captured
        );
    }

    #[test]
    fn composite_authorize_event_retry_is_snapshot_stable() {
        let store = InMemoryBudgetStore::new();
        let request = composite_request("hold-retry", "event-retry-authorize", three_quotas(2));
        let first = store.authorize_budget_hold(request.clone()).unwrap();
        store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                hold_id: Some("hold-retry".to_string()),
                event_id: Some("event-retry-capture".to_string()),
                authority: None,
                admission_operation: Some(composite_operation_binding("hold-retry")),
            })
            .unwrap();
        assert_eq!(store.authorize_budget_hold(request).unwrap(), first);
    }

    #[test]
    fn concurrent_composite_holds_admit_exactly_one_last_unit() {
        use std::sync::{Arc, Barrier};

        let store = Arc::new(InMemoryBudgetStore::new());
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for index in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store
                    .authorize_budget_hold(composite_request(
                        &format!("hold-race-{index}"),
                        &format!("event-race-{index}"),
                        three_quotas(1),
                    ))
                    .unwrap()
            }));
        }
        barrier.wait();
        let authorized = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(BudgetAuthorizeHoldDecision::is_authorized)
            .count();
        assert_eq!(authorized, 1);
    }

    #[test]
    fn composite_hold_rejects_ambiguous_unsorted_and_mismatched_retries() {
        let store = InMemoryBudgetStore::new();

        let mut ambiguous = composite_request("hold-ambiguous", "event-ambiguous", three_quotas(2));
        ambiguous.max_invocations = Some(2);
        assert!(matches!(
            store.authorize_budget_hold(ambiguous),
            Err(BudgetStoreError::Invariant(_))
        ));

        let mut unsorted = three_quotas(2);
        unsorted.swap(0, 1);
        assert!(matches!(
            store.authorize_budget_hold(composite_request(
                "hold-unsorted",
                "event-unsorted",
                unsorted,
            )),
            Err(BudgetStoreError::Invariant(_))
        ));

        let request = composite_request("hold-mismatch", "event-mismatch", three_quotas(2));
        store.authorize_budget_hold(request.clone()).unwrap();
        let mut changed_event = request.clone();
        changed_event.requested_exposure_units = 99;
        assert!(matches!(
            store.authorize_budget_hold(changed_event),
            Err(BudgetStoreError::Invariant(_))
        ));
        let mut changed_hold = request;
        changed_hold.event_id = Some("event-mismatch-second".to_string());
        assert!(matches!(
            store.authorize_budget_hold(changed_hold),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn composite_predispatch_reverse_restores_every_quota_and_exposure() {
        let store = InMemoryBudgetStore::new();
        store
            .authorize_budget_hold(composite_request(
                "hold-reverse-1",
                "event-reverse-1-authorize",
                three_quotas(1),
            ))
            .unwrap();

        let reversed = store
            .reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                reversed_exposure_units: 100,
                hold_id: Some("hold-reverse-1".to_string()),
                event_id: Some("event-reverse-1".to_string()),
                authority: None,
                admission_operation: Some(composite_operation_binding("hold-reverse-1")),
            })
            .unwrap();
        assert_eq!(
            reversed.invocation_state,
            BudgetInvocationReservationState::Reversed
        );
        assert_eq!(reversed.monetary_state, BudgetMonetaryHoldState::Reversed);
        assert_eq!(reversed.committed_cost_units_after, 0);
        assert!(reversed
            .invocation_counts_after
            .iter()
            .all(|usage| usage.invocation_count_after().unwrap() == 0));

        let second = store
            .authorize_budget_hold(composite_request(
                "hold-reverse-2",
                "event-reverse-2-authorize",
                three_quotas(1),
            ))
            .unwrap();
        assert!(second.is_authorized());
    }

    #[test]
    fn monetary_release_then_invocation_reverse_preserves_terminal_substate() {
        let store = InMemoryBudgetStore::new();
        store
            .authorize_budget_hold(composite_request(
                "hold-release-reverse",
                "event-release-reverse-authorize",
                three_quotas(1),
            ))
            .unwrap();
        let released = store
            .release_budget_hold(BudgetReleaseHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                released_exposure_units: 100,
                hold_id: Some("hold-release-reverse".to_string()),
                event_id: Some("event-release-reverse-release".to_string()),
                authority: None,
                admission_operation: Some(composite_operation_binding("hold-release-reverse")),
            })
            .unwrap();
        assert_eq!(released.monetary_state, BudgetMonetaryHoldState::Released);
        assert_eq!(
            released.invocation_state,
            BudgetInvocationReservationState::Authorized
        );

        let reversed = store
            .reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                reversed_exposure_units: 0,
                hold_id: Some("hold-release-reverse".to_string()),
                event_id: Some("event-release-reverse-reverse".to_string()),
                authority: None,
                admission_operation: Some(composite_operation_binding("hold-release-reverse")),
            })
            .unwrap();
        assert_eq!(
            reversed.invocation_state,
            BudgetInvocationReservationState::Reversed
        );
        assert_eq!(reversed.monetary_state, BudgetMonetaryHoldState::Released);
        assert!(reversed
            .invocation_counts_after
            .iter()
            .all(|usage| usage.invocation_count_after().unwrap() == 0));
        assert!(store
            .authorize_budget_hold(composite_request(
                "hold-release-reverse-next",
                "event-release-reverse-next",
                three_quotas(1),
            ))
            .unwrap()
            .is_authorized());
    }

    #[test]
    fn captured_invocations_are_terminal_while_monetary_exposure_remains_live() {
        let store = InMemoryBudgetStore::new();
        store
            .authorize_budget_hold(composite_request(
                "hold-captured-terminal",
                "event-captured-terminal-authorize",
                three_quotas(2),
            ))
            .unwrap();
        store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                hold_id: Some("hold-captured-terminal".to_string()),
                event_id: Some("event-captured-terminal-capture".to_string()),
                authority: None,
                admission_operation: Some(composite_operation_binding("hold-captured-terminal")),
            })
            .unwrap();

        assert!(matches!(
            store.reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: "cap-composite".to_string(),
                grant_index: 0,
                reversed_exposure_units: 100,
                hold_id: Some("hold-captured-terminal".to_string()),
                event_id: Some("event-captured-terminal-reverse".to_string()),
                authority: None,
                admission_operation: Some(composite_operation_binding("hold-captured-terminal")),
            }),
            Err(BudgetStoreError::Invariant(_))
        ));
        let usage = store.get_usage("cap-composite", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.total_cost_exposed, 100);
        assert!(matches!(
            store.reverse_charge_cost("cap-composite", 0, 0),
            Err(BudgetStoreError::Invariant(_))
        ));
        let usage = store.get_usage("cap-composite", 0).unwrap().unwrap();
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.total_cost_exposed, 100);
    }

    #[test]
    fn compatibility_increment_pins_maximum_and_reverses_the_same_quota() {
        let store = InMemoryBudgetStore::new();
        assert!(store.try_increment("cap-compat", 0, Some(2)).unwrap());
        assert!(store
            .try_charge_cost("cap-compat", 0, Some(2), 1, None, None)
            .unwrap());
        assert!(matches!(
            store.try_increment("cap-compat", 0, Some(3)),
            Err(BudgetStoreError::Invariant(_))
        ));
        store.reverse_charge_cost("cap-compat", 0, 0).unwrap();
        assert!(store.try_increment("cap-compat", 0, Some(2)).unwrap());

        let events = store
            .list_mutation_events(10, Some("cap-compat"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].invocation_counts_after.len(), 1);
        assert_eq!(
            events[0].invocation_state,
            BudgetInvocationReservationState::Captured
        );
    }

    #[test]
    fn compatibility_charge_uses_the_same_immutable_quota_authority() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost("cap-compat-charge", 0, Some(2), 1, None, None)
            .unwrap());
        assert!(matches!(
            store.try_charge_cost("cap-compat-charge", 0, Some(3), 1, None, None),
            Err(BudgetStoreError::Invariant(_))
        ));

        let denied = InMemoryBudgetStore::new();
        assert!(!denied
            .try_charge_cost("cap-compat-charge-denied", 0, Some(2), 2, Some(1), None,)
            .unwrap());
        assert!(matches!(
            denied.try_charge_cost("cap-compat-charge-denied", 0, Some(3), 1, Some(1), None,),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn multi_quota_authority_blocks_legacy_increment_and_charge_bypasses() {
        let increment_store = InMemoryBudgetStore::new();
        assert!(increment_store
            .authorize_budget_hold(composite_request(
                "hold-multi-authority-increment",
                "event-multi-authority-increment",
                three_quotas(1),
            ))
            .unwrap()
            .is_authorized());
        assert!(matches!(
            increment_store.try_increment("cap-composite", 0, Some(2)),
            Err(BudgetStoreError::Invariant(_))
        ));

        let charge_store = InMemoryBudgetStore::new();
        assert!(charge_store
            .authorize_budget_hold(composite_request(
                "hold-multi-authority-charge",
                "event-multi-authority-charge",
                three_quotas(1),
            ))
            .unwrap()
            .is_authorized());
        assert!(matches!(
            charge_store.try_charge_cost("cap-composite", 0, Some(2), 0, None, None),
            Err(BudgetStoreError::Invariant(_))
        ));

        let hold_store = InMemoryBudgetStore::new();
        assert!(hold_store
            .authorize_budget_hold(composite_request(
                "hold-multi-authority-structured",
                "event-multi-authority-structured",
                three_quotas(1),
            ))
            .unwrap()
            .is_authorized());
        assert!(matches!(
            hold_store.authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
                "cap-composite".to_string(),
                0,
                Some(2),
                0,
                None,
                None,
                Some("hold-multi-authority-legacy".to_string()),
                Some("event-multi-authority-legacy".to_string()),
                None,
            )),
            Err(BudgetStoreError::Invariant(_))
        ));

        let denied_store = InMemoryBudgetStore::new();
        assert!(matches!(
            denied_store
                .authorize_budget_hold(composite_request(
                    "hold-multi-authority-denied",
                    "event-multi-authority-denied",
                    three_quotas(0),
                ))
                .unwrap(),
            BudgetAuthorizeHoldDecision::Denied(_)
        ));
        assert!(matches!(
            denied_store.authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
                "cap-composite".to_string(),
                0,
                Some(2),
                0,
                None,
                None,
                Some("hold-multi-authority-after-denial".to_string()),
                Some("event-multi-authority-after-denial".to_string()),
                None,
            )),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn legacy_hold_id_collision_rejects_even_when_second_authorization_would_deny() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-legacy-hold-collision",
                0,
                Some(1),
                1,
                None,
                None,
                Some("hold-legacy-collision"),
                Some("event-legacy-collision-first"),
            )
            .unwrap());

        assert!(matches!(
            store.try_charge_cost_with_ids(
                "cap-legacy-hold-collision",
                0,
                Some(1),
                1,
                None,
                None,
                Some("hold-legacy-collision"),
                Some("event-legacy-collision-denied"),
            ),
            Err(BudgetStoreError::Invariant(_))
        ));
        assert_eq!(
            store
                .list_mutation_events(10, Some("cap-legacy-hold-collision"), Some(0))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn denied_legacy_authorization_permanently_claims_its_hold_id() {
        let store = InMemoryBudgetStore::new();
        assert!(!store
            .try_charge_cost_with_ids(
                "cap-denied-hold-claim",
                0,
                Some(2),
                2,
                Some(1),
                Some(10),
                Some("hold-denied-claim"),
                Some("event-denied-claim-first"),
            )
            .unwrap());
        assert!(!store
            .try_charge_cost_with_ids(
                "cap-denied-hold-claim",
                0,
                Some(2),
                2,
                Some(1),
                Some(10),
                Some("hold-denied-claim"),
                Some("event-denied-claim-first"),
            )
            .unwrap());

        assert!(matches!(
            store.try_charge_cost_with_ids(
                "cap-denied-hold-claim",
                0,
                Some(2),
                1,
                Some(1),
                Some(10),
                Some("hold-denied-claim"),
                Some("event-denied-claim-second"),
            ),
            Err(BudgetStoreError::Invariant(_))
        ));
        assert!(store
            .get_usage("cap-denied-hold-claim", 0)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .list_mutation_events(10, Some("cap-denied-hold-claim"), Some(0))
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            store.authorize_budget_hold(composite_request(
                "hold-denied-claim",
                "event-denied-claim-composite",
                three_quotas(2),
            )),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn legacy_reverse_retry_returns_the_frozen_decision() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-reverse-retry",
                0,
                Some(3),
                100,
                Some(100),
                Some(1_000),
                Some("hold-reverse-retry"),
                Some("event-reverse-retry-authorize"),
            )
            .unwrap());
        let request = BudgetReverseHoldRequest {
            capability_id: "cap-reverse-retry".to_string(),
            grant_index: 0,
            reversed_exposure_units: 100,
            hold_id: Some("hold-reverse-retry".to_string()),
            event_id: Some("event-reverse-retry".to_string()),
            authority: None,
            admission_operation: None,
        };
        let first = store.reverse_budget_hold(request.clone()).unwrap();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-reverse-retry",
                0,
                Some(3),
                25,
                Some(100),
                Some(1_000),
                Some("hold-reverse-retry-later"),
                Some("event-reverse-retry-later"),
            )
            .unwrap());
        assert_eq!(store.reverse_budget_hold(request).unwrap(), first);
    }

    #[test]
    fn legacy_release_retry_returns_the_frozen_decision() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-release-retry",
                0,
                Some(3),
                100,
                Some(100),
                Some(1_000),
                Some("hold-release-retry"),
                Some("event-release-retry-authorize"),
            )
            .unwrap());
        let request = BudgetReleaseHoldRequest {
            capability_id: "cap-release-retry".to_string(),
            grant_index: 0,
            released_exposure_units: 40,
            hold_id: Some("hold-release-retry".to_string()),
            event_id: Some("event-release-retry".to_string()),
            authority: None,
            admission_operation: None,
        };
        let first = store.release_budget_hold(request.clone()).unwrap();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-release-retry",
                0,
                Some(3),
                25,
                Some(100),
                Some(1_000),
                Some("hold-release-retry-later"),
                Some("event-release-retry-later"),
            )
            .unwrap());
        assert_eq!(store.release_budget_hold(request).unwrap(), first);
    }

    #[test]
    fn legacy_reconcile_retry_returns_the_frozen_decision() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-reconcile-retry",
                0,
                Some(3),
                100,
                Some(100),
                Some(1_000),
                Some("hold-reconcile-retry"),
                Some("event-reconcile-retry-authorize"),
            )
            .unwrap());
        let request = BudgetReconcileHoldRequest {
            capability_id: "cap-reconcile-retry".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 70,
            hold_id: Some("hold-reconcile-retry".to_string()),
            event_id: Some("event-reconcile-retry".to_string()),
            authority: None,
            admission_operation: None,
        };
        let first = store.reconcile_budget_hold(request.clone()).unwrap();
        assert!(store
            .try_charge_cost_with_ids(
                "cap-reconcile-retry",
                0,
                Some(3),
                25,
                Some(100),
                Some(1_000),
                Some("hold-reconcile-retry-later"),
                Some("event-reconcile-retry-later"),
            )
            .unwrap());
        assert_eq!(store.reconcile_budget_hold(request).unwrap(), first);
    }

    #[test]
    fn legacy_hold_id_cannot_collide_with_composite_authorization() {
        let store = InMemoryBudgetStore::new();
        store
            .authorize_budget_hold(composite_request(
                "hold-namespace",
                "event-namespace-authorize",
                three_quotas(2),
            ))
            .unwrap();

        assert!(matches!(
            store.try_charge_cost_with_ids(
                "legacy-capability",
                0,
                Some(2),
                1,
                None,
                None,
                Some("hold-namespace"),
                Some("event-legacy-collision"),
            ),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn event_ids_are_globally_unique_across_legacy_and_composite_mutations() {
        let legacy_first = InMemoryBudgetStore::new();
        assert!(legacy_first
            .try_charge_cost_with_ids(
                "legacy-event-capability",
                0,
                Some(2),
                1,
                None,
                None,
                Some("legacy-event-hold"),
                Some("event-global-collision"),
            )
            .unwrap());
        assert!(matches!(
            legacy_first.authorize_budget_hold(composite_request(
                "hold-global-collision",
                "event-global-collision",
                three_quotas(2),
            )),
            Err(BudgetStoreError::Invariant(_))
        ));

        let composite_first = InMemoryBudgetStore::new();
        composite_first
            .authorize_budget_hold(composite_request(
                "hold-global-collision",
                "event-global-collision",
                three_quotas(2),
            ))
            .unwrap();
        assert!(matches!(
            composite_first.try_charge_cost_with_ids(
                "legacy-event-capability",
                0,
                Some(2),
                1,
                None,
                None,
                Some("legacy-event-hold"),
                Some("event-global-collision"),
            ),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn explicit_event_ids_cannot_enter_the_reserved_local_namespace() {
        let store = InMemoryBudgetStore::new();
        assert!(matches!(
            store.try_charge_cost_with_ids(
                "legacy-event-capability",
                0,
                Some(2),
                1,
                None,
                None,
                Some("legacy-event-hold"),
                Some("local-budget-event-1"),
            ),
            Err(BudgetStoreError::Invariant(_))
        ));
        assert!(store
            .get_usage("legacy-event-capability", 0)
            .unwrap()
            .is_none());
    }

    #[test]
    fn legacy_monetary_capture_is_truthful_and_idempotent() {
        let store = InMemoryBudgetStore::new();
        assert!(store
            .try_charge_cost_with_ids(
                "legacy-capture-capability",
                0,
                Some(2),
                100,
                Some(100),
                Some(1_000),
                Some("legacy-capture-hold"),
                Some("legacy-capture-authorize"),
            )
            .unwrap());
        let request = BudgetCaptureHoldRequest {
            capability_id: "legacy-capture-capability".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 70,
            hold_id: Some("legacy-capture-hold".to_string()),
            event_id: Some("legacy-capture-event".to_string()),
            authority: None,
            admission_operation: None,
        };
        let captured = store.capture_budget_hold(request.clone()).unwrap();
        assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Captured);
        assert_eq!(captured.realized_spend_units, 70);
        assert!(store
            .try_charge_cost_with_ids(
                "legacy-capture-capability",
                0,
                Some(2),
                0,
                Some(100),
                Some(1_000),
                Some("legacy-capture-later-hold"),
                Some("legacy-capture-later-authorize"),
            )
            .unwrap());
        assert_eq!(store.capture_budget_hold(request).unwrap(), captured);
        let events = store
            .list_mutation_events(10, Some("legacy-capture-capability"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].kind, BudgetMutationKind::CaptureExposure);
        assert_eq!(events[1].monetary_state, BudgetMonetaryHoldState::Captured);
    }

    #[test]
    fn quota_profiles_use_normative_closed_identifiers() {
        let profiles = [
            BudgetQuotaProfile::GrantInvocation,
            BudgetQuotaProfile::AggregateCapabilityInvocation,
            BudgetQuotaProfile::AggregateFamilyInvocation,
            BudgetQuotaProfile::SupplementalBrokerExecution,
        ];
        for profile in profiles {
            assert_eq!(BudgetQuotaProfile::parse(profile.as_str()), Some(profile));
        }
        assert_eq!(BudgetQuotaProfile::parse("grant_invocation"), None);
    }

    #[test]
    fn authorize_and_reconcile_hold_preserve_authority_metadata() {
        let store = InMemoryBudgetStore::new();
        let authority = BudgetEventAuthority {
            authority_id: "kernel:test-authority".to_string(),
            lease_id: "single-node".to_string(),
            lease_epoch: 0,
        };

        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "cap-budget-1".to_string(),
                grant_index: 0,
                max_invocations: Some(4),
                requested_exposure_units: 100,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1_000),
                hold_id: Some("hold-budget-1".to_string()),
                event_id: Some("hold-budget-1:authorize".to_string()),
                authority: Some(authority.clone()),
                admission_operation: None,
                invocation_admission: None,
                payment_journal: None,
            })
            .unwrap();
        let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
            panic!("budget hold should be authorized");
        };
        assert_eq!(authorized.committed_cost_units_after, 100);
        assert_eq!(
            authorized.metadata.event_id.as_deref(),
            Some("hold-budget-1:authorize")
        );
        assert_eq!(authorized.metadata.budget_commit_index, Some(1));
        assert_eq!(
            authorized.metadata.budget_term().as_deref(),
            Some("kernel:test-authority:0")
        );

        let reconcile = store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-budget-1".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 75,
                hold_id: Some("hold-budget-1".to_string()),
                event_id: Some("hold-budget-1:reconcile".to_string()),
                authority: Some(authority.clone()),
                admission_operation: None,
            })
            .unwrap();
        assert_eq!(reconcile.committed_cost_units_after, 75);
        assert_eq!(reconcile.realized_spend_units, 75);
        assert_eq!(
            reconcile.metadata.event_id.as_deref(),
            Some("hold-budget-1:reconcile")
        );
        assert_eq!(reconcile.metadata.budget_commit_index, Some(2));
        assert_eq!(reconcile.metadata.authority.as_ref(), Some(&authority));

        let usage = store.get_usage("cap-budget-1", 0).unwrap().unwrap();
        assert_eq!(usage.total_cost_exposed, 0);
        assert_eq!(usage.total_cost_realized_spend, 75);
        assert_eq!(usage.committed_cost_units().unwrap(), 75);

        let events = store
            .list_mutation_events(10, Some("cap-budget-1"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, BudgetMutationKind::ReserveInvocations);
        assert_eq!(events[0].authority.as_ref(), Some(&authority));
        assert_eq!(events[1].kind, BudgetMutationKind::ReconcileSpend);
        assert_eq!(events[1].authority.as_ref(), Some(&authority));
        assert_eq!(events[1].realized_spend_units, 75);
    }

    fn authorize_reserved(
        store: &InMemoryBudgetStore,
        hold_id: &str,
        cap: &str,
        reserved_until: i64,
    ) {
        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: cap.to_string(),
                grant_index: 0,
                max_invocations: Some(10),
                requested_exposure_units: 100,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1_000),
                hold_id: Some(hold_id.to_string()),
                event_id: Some(format!("{hold_id}:authorize")),
                authority: None,
                admission_operation: None,
                invocation_admission: None,
                payment_journal: None,
            })
            .unwrap();
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        store
            .mark_hold_reserved(
                hold_id,
                reserved_until,
                "USD",
                None,
                &ReservedHoldEnvelope::default(),
            )
            .unwrap();
    }

    #[test]
    fn ttl_reaper_settles_expired_unreconciled_reserved_holds_at_worst_case() {
        let store = InMemoryBudgetStore::new();
        // Expired reserved hold on cap-a: reserved_until 100 <= now 1000.
        authorize_reserved(&store, "hold-expired", "cap-a", 100);
        // Not-yet-expired reserved hold on cap-b: reserved_until 5000 > now 1000.
        authorize_reserved(&store, "hold-fresh", "cap-b", 5_000);
        // Reconciled reserved hold on cap-c: reconciled before the reap.
        authorize_reserved(&store, "hold-done", "cap-c", 100);
        store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-c".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 40,
                hold_id: Some("hold-done".to_string()),
                event_id: Some("hold-done:reconcile".to_string()),
                authority: None,
                admission_operation: None,
            })
            .unwrap();

        // Before the reap: expired/fresh committed 100 each, reconciled committed 40.
        assert_eq!(
            store
                .get_usage("cap-a", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            100
        );

        let settled = store.reap_expired_reserved_holds(1_000).unwrap();
        assert_eq!(settled, 1, "only the expired reserved hold is settled");

        // cap-a expired reserved hold SETTLED at worst-case: the reserved amount
        // is forfeited to realized spend (committed stays 100), not released to 0.
        let cap_a = store.get_usage("cap-a", 0).unwrap().unwrap();
        assert_eq!(
            cap_a.total_cost_realized_spend, 100,
            "the forfeited worst-case becomes realized spend"
        );
        assert_eq!(
            cap_a.committed_cost_units().unwrap(),
            100,
            "the reserved worst-case stays consumed, the freed difference is gone"
        );
        assert_eq!(
            store
                .get_budget_hold("hold-expired")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Expired
        );
        // A second reap is idempotent: the settled hold is no longer open.
        assert_eq!(store.reap_expired_reserved_holds(1_000).unwrap(), 0);
        // cap-b not-yet-expired reserved hold untouched.
        assert_eq!(
            store
                .get_usage("cap-b", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            100
        );
        assert_eq!(
            store
                .get_budget_hold("hold-fresh")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Open
        );
        // cap-c reconciled hold untouched (still at realized 40).
        assert_eq!(
            store
                .get_usage("cap-c", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            40
        );
        assert_eq!(
            store
                .get_budget_hold("hold-done")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Reconciled
        );
    }

    #[test]
    fn denied_authorize_hold_reports_guarantee_metadata_without_commit_index() {
        let store = InMemoryBudgetStore::new();
        let authority = BudgetEventAuthority {
            authority_id: "kernel:test-authority".to_string(),
            lease_id: "single-node".to_string(),
            lease_epoch: 0,
        };

        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "cap-budget-deny".to_string(),
                grant_index: 0,
                max_invocations: Some(1),
                requested_exposure_units: 150,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1_000),
                hold_id: Some("hold-budget-deny".to_string()),
                event_id: Some("hold-budget-deny:authorize".to_string()),
                authority: Some(authority.clone()),
                admission_operation: None,
                invocation_admission: None,
                payment_journal: None,
            })
            .unwrap();
        let BudgetAuthorizeHoldDecision::Denied(denied) = decision else {
            panic!("budget hold should be denied");
        };
        assert_eq!(denied.committed_cost_units_after, 0);
        assert_eq!(denied.invocation_count_after, 0);
        assert_eq!(
            denied.metadata.event_id.as_deref(),
            Some("hold-budget-deny:authorize")
        );
        assert_eq!(denied.metadata.budget_commit_index, None);
        assert_eq!(
            denied.metadata.guarantee_level,
            BudgetGuaranteeLevel::SingleNodeAtomic
        );
        assert_eq!(denied.metadata.authority.as_ref(), Some(&authority));

        let events = store
            .list_mutation_events(10, Some("cap-budget-deny"), Some(0))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].allowed, Some(false));
        assert_eq!(events[0].authority.as_ref(), Some(&authority));
        assert!(store.get_usage("cap-budget-deny", 0).unwrap().is_none());
    }

    #[test]
    fn request_id_reserved_hold_enumerated_by_prefix_across_capabilities() {
        let store = InMemoryBudgetStore::new();
        // A reservation opened under capability A binds request_id R to a hold
        // whose id embeds A. The reuse guard must report R as taken regardless of
        // which capability opened it.
        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "cap-a".to_string(),
                grant_index: 0,
                max_invocations: Some(4),
                requested_exposure_units: 100,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1_000),
                hold_id: Some("budget-hold:req-shared:cap-a:0".to_string()),
                event_id: Some("budget-hold:req-shared:cap-a:0:authorize".to_string()),
                authority: None,
                admission_operation: None,
                invocation_admission: None,
                payment_journal: None,
            })
            .unwrap();
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));

        // The request_id that backs the hold is reported taken.
        assert_eq!(
            store.request_id_has_reserved_hold("req-shared").unwrap(),
            Some(true)
        );
        // A different request_id has no hold.
        assert_eq!(
            store.request_id_has_reserved_hold("req-other").unwrap(),
            Some(false)
        );
        // The trailing colon delimits the prefix, so a request_id that is only a
        // textual prefix of the reserved one does not spuriously match.
        assert_eq!(
            store.request_id_has_reserved_hold("req").unwrap(),
            Some(false)
        );
    }

    /// Minimal store exercising the DEFAULT `authorize_budget_hold` (unlike
    /// `InMemoryBudgetStore`, which overrides it): the grant answer and the
    /// journal write are scripted so the default impl's ordering between
    /// them is observable.
    struct JournalOrderProbeStore {
        allow: bool,
        journal_write_fails: bool,
        journal: std::sync::Mutex<Vec<crate::payment::PaymentJournalRecord>>,
        reverses: std::sync::Mutex<u32>,
    }

    impl JournalOrderProbeStore {
        fn new(allow: bool, journal_write_fails: bool) -> Self {
            Self {
                allow,
                journal_write_fails,
                journal: std::sync::Mutex::new(Vec::new()),
                reverses: std::sync::Mutex::new(0),
            }
        }

        fn journal_rows(&self) -> usize {
            self.journal.lock().unwrap().len()
        }

        fn reverse_count(&self) -> u32 {
            *self.reverses.lock().unwrap()
        }
    }

    impl BudgetStore for JournalOrderProbeStore {
        fn try_increment(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _max_invocations: Option<u32>,
        ) -> Result<bool, BudgetStoreError> {
            Ok(self.allow)
        }

        fn try_charge_cost(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _max_invocations: Option<u32>,
            _cost_units: u64,
            _max_cost_per_invocation: Option<u64>,
            _max_total_cost_units: Option<u64>,
        ) -> Result<bool, BudgetStoreError> {
            Ok(self.allow)
        }

        fn reverse_charge_cost(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _cost_units: u64,
        ) -> Result<(), BudgetStoreError> {
            *self.reverses.lock().unwrap() += 1;
            Ok(())
        }

        fn reduce_charge_cost(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _cost_units: u64,
        ) -> Result<(), BudgetStoreError> {
            Ok(())
        }

        fn settle_charge_cost(
            &self,
            _capability_id: &str,
            _grant_index: usize,
            _exposed_cost_units: u64,
            _realized_cost_units: u64,
        ) -> Result<(), BudgetStoreError> {
            Ok(())
        }

        fn list_usages(
            &self,
            _limit: usize,
            _capability_id: Option<&str>,
        ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
            Ok(Vec::new())
        }

        fn get_usage(
            &self,
            _capability_id: &str,
            _grant_index: usize,
        ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
            Ok(None)
        }

        fn record_payment_journal(
            &self,
            entry: &crate::payment::PaymentJournalRecord,
        ) -> Result<(), BudgetStoreError> {
            if self.journal_write_fails {
                return Err(BudgetStoreError::Invariant(
                    "journal write scripted to fail".to_string(),
                ));
            }
            self.journal.lock().unwrap().push(entry.clone());
            Ok(())
        }
    }

    fn probe_hold_request() -> BudgetAuthorizeHoldRequest {
        BudgetAuthorizeHoldRequest {
            capability_id: "cap-journal-order".to_string(),
            grant_index: 0,
            max_invocations: Some(1),
            requested_exposure_units: 100,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(1_000),
            hold_id: Some("hold-journal-order".to_string()),
            event_id: Some("hold-journal-order:authorize".to_string()),
            authority: None,
            admission_operation: None,
            invocation_admission: None,
            payment_journal: Some(crate::payment::PaymentJournalRecord {
                request_id: "req-journal-order".to_string(),
                capability_id: "cap-journal-order".to_string(),
                grant_index: 0,
                admission_operation: None,
                authority: None,
                hold_id: Some("hold-journal-order".to_string()),
                rail: "x402".to_string(),
                authorization_id: None,
                transaction_id: None,
                budget_exposure_units: 100,
                amount_units: 100,
                settle_action: None,
                settle_amount_units: None,
                currency: "USD".to_string(),
                state: crate::payment::PaymentJournalState::HoldPlaced,
                created_at_unix_ms: 1,
                tenant_id: None,
            }),
        }
    }

    #[test]
    fn default_authorize_hold_journals_nothing_on_a_budget_deny() {
        let store = JournalOrderProbeStore::new(false, false);
        let decision = store.authorize_budget_hold(probe_hold_request()).unwrap();
        assert!(
            matches!(decision, BudgetAuthorizeHoldDecision::Denied(_)),
            "the scripted store denies the hold"
        );
        assert_eq!(
            store.journal_rows(),
            0,
            "a budget-denied request must leave no journal row: no rail call will follow"
        );
    }

    #[test]
    fn default_authorize_hold_journals_only_a_granted_hold() {
        let store = JournalOrderProbeStore::new(true, false);
        let decision = store.authorize_budget_hold(probe_hold_request()).unwrap();
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        assert_eq!(store.journal_rows(), 1);
        assert_eq!(store.reverse_count(), 0);
    }

    #[test]
    fn default_authorize_hold_revokes_the_grant_when_the_journal_write_fails() {
        let store = JournalOrderProbeStore::new(true, true);
        let error = store
            .authorize_budget_hold(probe_hold_request())
            .expect_err("a granted hold whose journal cannot persist must fail closed");
        assert!(error.to_string().contains("journal write scripted to fail"));
        assert_eq!(store.journal_rows(), 0);
        assert_eq!(
            store.reverse_count(),
            1,
            "the grant must be rolled back so no hold runs without its crash record"
        );
    }
