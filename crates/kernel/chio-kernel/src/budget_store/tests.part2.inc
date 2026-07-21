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
    fn invocation_hold_id_cannot_collide_with_composite_authorization() {
        let envelope = ReservedHoldEnvelope {
            budget_total: None,
            delegation_depth: 0,
            root_budget_holder: "root-holder".to_string(),
        };
        let authorized_store = InMemoryBudgetStore::new();
        let authorized_hold_id = "hold-composite-authorized";
        assert!(matches!(
            authorized_store
                .authorize_budget_hold(composite_request(
                    authorized_hold_id,
                    "event-composite-authorized",
                    three_quotas(2),
                ))
                .unwrap(),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        assert!(matches!(
            authorized_store.reserve_invocation_hold(
                authorized_hold_id,
                "cap-invocation",
                0,
                1_000,
                &envelope,
            ),
            Err(BudgetStoreError::Invariant(_))
        ));
        assert_eq!(
            authorized_store
                .get_budget_hold(authorized_hold_id)
                .unwrap()
                .unwrap()
                .capability_id,
            "cap-composite"
        );

        // A denied composite authorization has no composite hold row, but its
        // authorization tombstone still owns the hold identifier permanently.
        let denied_store = InMemoryBudgetStore::new();
        let denied_hold_id = "hold-composite-denied";
        assert!(matches!(
            denied_store
                .authorize_budget_hold(composite_request(
                    denied_hold_id,
                    "event-composite-denied",
                    three_quotas(0),
                ))
                .unwrap(),
            BudgetAuthorizeHoldDecision::Denied(_)
        ));
        assert!(denied_store
            .get_budget_hold(denied_hold_id)
            .unwrap()
            .is_none());
        assert!(matches!(
            denied_store.reserve_invocation_hold(
                denied_hold_id,
                "cap-invocation",
                0,
                1_000,
                &envelope,
            ),
            Err(BudgetStoreError::Invariant(_))
        ));
    }

    #[test]
    fn request_id_reserved_hold_probe_includes_composite_holds() {
        let store = InMemoryBudgetStore::new();
        assert!(matches!(
            store
                .authorize_budget_hold(composite_request(
                    "budget-hold:req-composite:cap-composite:0",
                    "event-request-probe-composite",
                    three_quotas(2),
                ))
                .unwrap(),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));

        assert_eq!(
            store.request_id_has_reserved_hold("req-composite").unwrap(),
            Some(true)
        );
        assert_eq!(
            store.request_id_has_reserved_hold("req").unwrap(),
            Some(false)
        );
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
