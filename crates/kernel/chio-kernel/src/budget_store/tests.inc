    use super::*;
    use chio_test_support::prelude::*;

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

    #[test]
    fn in_memory_store_does_not_claim_durable_atomic_payment_journaling() {
        let store = InMemoryBudgetStore::new();
        assert!(!store.supports_durable_atomic_payment_journal());
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
                issuer: chio_core::crypto::Keypair::from_seed(&[72; 32]).public_key(),
                not_before: 90,
                expires_at: 300,
                request_constraint_digest: "34".repeat(32),
                broker_capability_id: "test-broker-capability".to_string(),
                claim_binding_digest: "35".repeat(32),
                verified_at: 100,
            }),
            partition_escrow_evidence: None,
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
            authorization_policy: BudgetAuthorizationPolicy::FreshOrReplay,
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
    fn snapshot_authorization_can_only_replay_an_exact_committed_decision() {
        let store = InMemoryBudgetStore::new();
        let request = composite_request(
            "hold-existing-only-replay",
            "event-existing-only-replay",
            three_quotas(2),
        );
        let snapshot = request
            .cleanup_snapshot(
                "event-existing-only-reverse".to_string(),
                "event-existing-only-capture".to_string(),
            )
            .test_expect("cleanup snapshot");
        let original = store
            .authorize_budget_hold(request)
            .test_expect("fresh authorization");
        let replay = snapshot
            .authorization_request()
            .test_expect("snapshot replay request");
        assert!(replay.requires_existing_authorization_replay());
        assert!(matches!(
            store.authorize_budget_hold(replay.clone()),
            Err(BudgetStoreError::Invariant(_))
        ));
        assert_eq!(
            store
                .replay_budget_authorization(replay)
                .test_expect("exact committed replay"),
            original
        );

        let empty_store = InMemoryBudgetStore::new();
        let absent = snapshot
            .authorization_request()
            .test_expect("absent replay request");
        assert!(matches!(
            empty_store.replay_budget_authorization(absent),
            Err(BudgetStoreError::MissingCommittedReplay(_))
        ));
        assert!(empty_store
            .get_usage("cap-composite", 0)
            .test_expect("empty usage lookup")
            .is_none());
    }

    #[test]
    fn snapshot_replay_rejects_tampered_source_provenance() {
        let store = InMemoryBudgetStore::new();
        let request = composite_request(
            "hold-tampered-replay",
            "event-tampered-replay",
            three_quotas(2),
        );
        let snapshot = request
            .cleanup_snapshot(
                "event-tampered-reverse".to_string(),
                "event-tampered-capture".to_string(),
            )
            .test_expect("cleanup snapshot");
        store
            .authorize_budget_hold(request)
            .test_expect("fresh authorization");
        let mut encoded = serde_json::to_value(&snapshot).test_expect("snapshot JSON");
        encoded["supplementalBinding"]["claimBindingDigest"] =
            serde_json::Value::String("ff".repeat(32));
        let tampered: BudgetAuthorizationCleanupSnapshot =
            serde_json::from_value(encoded).test_expect("structurally valid tampered snapshot");
        let replay = tampered
            .authorization_request()
            .test_expect("tampered replay request");
        assert!(matches!(
            store.replay_budget_authorization(replay),
            Err(BudgetStoreError::Conflict(_))
        ));
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
        let denial_seq = second
            .metadata
            .budget_commit_index
            .test_expect("a durable denial must expose its event sequence");
        let denial_event = store
            .list_mutation_events(10, Some("cap-composite"), Some(0))
            .test_expect("list composite denial event")
            .into_iter()
            .find(|event| event.event_id == "event-composite-2")
            .test_expect("composite denial event");
        assert_eq!(denial_event.allowed, Some(false));
        assert_eq!(denial_event.event_seq, denial_seq);
        assert_eq!(denial_event.usage_seq, None);
    }

    #[test]
    fn monetary_denial_does_not_reserve_quota_and_replays_its_frozen_snapshot() {
        let store = InMemoryBudgetStore::new();
        let first = store
            .authorize_budget_hold(composite_request(
                "hold-monetary-baseline",
                "event-monetary-baseline",
                three_quotas(3),
            ))
            .test_expect("baseline monetary authorization");
        assert!(first.is_authorized());

        let mut denied_request = composite_request(
            "hold-monetary-denied",
            "event-monetary-denied",
            three_quotas(3),
        );
        denied_request.requested_exposure_units = 101;
        denied_request.max_cost_per_invocation = Some(100);
        let denied = store
            .authorize_budget_hold(denied_request.clone())
            .test_expect("monetary denial");
        let denied_snapshot = match &denied {
            BudgetAuthorizeHoldDecision::Denied(denied_snapshot) => Some(denied_snapshot),
            BudgetAuthorizeHoldDecision::Authorized(_) => None,
        }
        .test_expect("monetary overspend denial");
        assert!(denied_snapshot
            .invocation_counts_after
            .iter()
            .all(|usage| usage.invocation_count_after().test_expect("quota count") == 1));
        let denial_seq = denied_snapshot
            .metadata
            .budget_commit_index
            .test_expect("a durable denial must expose its event sequence");

        let later = store
            .authorize_budget_hold(composite_request(
                "hold-monetary-later",
                "event-monetary-later",
                three_quotas(3),
            ))
            .test_expect("later monetary authorization");
        assert!(later.is_authorized());
        assert_eq!(
            store
                .authorize_budget_hold(denied_request.clone())
                .test_expect("replayed monetary denial"),
            denied,
            "exact replay must return the original denial snapshot"
        );
        denied_request.requested_exposure_units = 99;
        assert!(matches!(
            store.authorize_budget_hold(denied_request),
            Err(BudgetStoreError::Conflict(_))
        ));

        let denial_event = store
            .list_mutation_events(10, Some("cap-composite"), Some(0))
            .test_expect("list monetary denial event")
            .into_iter()
            .find(|event| event.event_id == "event-monetary-denied")
            .test_expect("monetary denial event");
        assert_eq!(denial_event.event_seq, denial_seq);
        assert_eq!(denial_event.usage_seq, None);
        assert!(store
            .get_budget_hold("hold-monetary-denied")
            .test_expect("monetary denial hold lookup")
            .is_none());
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
            .mark_admission_operation_hold_reserved(hold_id, &binding, 2_345, None, None, &envelope)
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
    fn atomic_legacy_invocation_hold_stamp_preserves_no_monetary_envelope() {
        let store = InMemoryBudgetStore::new();
        let hold_id = "hold-atomic-invocation-reservation";
        assert!(matches!(
            store
                .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
                    "cap-atomic-invocation".to_string(),
                    0,
                    Some(2),
                    0,
                    None,
                    None,
                    Some(hold_id.to_string()),
                    Some(format!(
                        "{hold_id}{CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX}"
                    )),
                    None,
                ))
                .unwrap(),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        let envelope = ReservedHoldEnvelope {
            budget_total: None,
            delegation_depth: 1,
            root_budget_holder: "root-atomic-invocation".to_string(),
        };
        store
            .mark_invocation_hold_reserved(hold_id, "cap-atomic-invocation", 0, 3_456, &envelope)
            .unwrap();
        store
            .mark_invocation_hold_reserved(hold_id, "cap-atomic-invocation", 0, 3_456, &envelope)
            .unwrap();

        let snapshot = store.get_budget_hold(hold_id).unwrap().unwrap();
        assert_eq!(snapshot.authorized_exposure_units, 0);
        assert_eq!(snapshot.remaining_exposure_units, 0);
        assert_eq!(snapshot.reserved_until, Some(3_456));
        assert_eq!(snapshot.reserved_currency, None);
        assert_eq!(snapshot.reserved_payment_reference, None);
        assert_eq!(snapshot.reserved_budget_total, None);
        assert_eq!(snapshot.reserved_delegation_depth, Some(1));
        assert_eq!(
            snapshot.reserved_root_budget_holder.as_deref(),
            Some("root-atomic-invocation")
        );
        assert!(matches!(
            store.mark_invocation_hold_reserved(hold_id, "cap-atomic-invocation", 0, 3_457, &envelope,),
            Err(BudgetStoreError::Conflict(_))
        ));
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
            Err(BudgetStoreError::Conflict(_))
        ));
        let mut changed_hold = request;
        changed_hold.event_id = Some("event-mismatch-second".to_string());
        assert!(matches!(
            store.authorize_budget_hold(changed_hold),
            Err(BudgetStoreError::Conflict(_))
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
