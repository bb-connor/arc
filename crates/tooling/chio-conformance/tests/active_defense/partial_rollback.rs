struct SelectiveRemoveFailingContainmentOverlayStore {
    inner: Arc<SqliteSecurityStateStore>,
    failed_target: TenantScopedId,
}

impl ContainmentOverlayStore for SelectiveRemoveFailingContainmentOverlayStore {
    fn ensure_containment_overlays_ready(&self) -> PortResult<()> {
        self.inner.ensure_containment_overlays_ready()
    }

    fn apply_contribution(&self, request: &OverlayApplyRequest) -> PortResult<OverlaySnapshot> {
        self.inner.apply_contribution(request)
    }

    fn remove_contribution(&self, request: &OverlayRemoveRequest) -> PortResult<OverlaySnapshot> {
        if request.target == self.failed_target {
            return Err(PortError::conflict());
        }
        self.inner.remove_contribution(request)
    }

    fn load_effective(&self, target: &TenantScopedId) -> PortResult<Option<OverlaySnapshot>> {
        self.inner.load_effective(target)
    }

    fn load_containment_overlay_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        self.inner.load_containment_overlay_result(query)
    }
}

#[derive(Default)]
struct RecordingResponseReceipts {
    receipts: Mutex<BTreeMap<String, ActiveDefenseReceiptBody>>,
}

impl RecordingResponseReceipts {
    fn receipts(&self) -> Vec<ActiveDefenseReceiptBody> {
        self.receipts
            .lock()
            .test_expect("response receipt mutex")
            .values()
            .cloned()
            .collect()
    }
}

impl SecurityReceiptSink for RecordingResponseReceipts {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        let receipt: ActiveDefenseReceiptBody =
            serde_json::from_slice(request.canonical_body.as_bytes())
                .map_err(|_| PortError::invalid_data())?;
        receipt.validate().map_err(|_| PortError::invalid_data())?;
        if receipt
            .body_digest()
            .map_err(|_| PortError::invalid_data())?
            != request.body_hash
            || receipt
                .evidence_id()
                .map_err(|_| PortError::invalid_data())?
                != request.evidence_id
        {
            return Err(PortError::integrity_failure());
        }
        let mut receipts = self.receipts.lock().map_err(|_| PortError::unavailable())?;
        match receipts.get(request.evidence_id.as_str()) {
            Some(existing) if existing != &receipt => return Err(PortError::conflict()),
            Some(_) => {}
            None => {
                receipts.insert(request.evidence_id.as_str().to_owned(), receipt);
            }
        }
        Ok(request.evidence_id.clone())
    }
}

#[derive(Default)]
struct RecordingResponseAlerts {
    alerts: Mutex<BTreeMap<String, SecurityAlert>>,
}

impl RecordingResponseAlerts {
    fn alerts(&self) -> Vec<SecurityAlert> {
        self.alerts
            .lock()
            .test_expect("response alert mutex")
            .values()
            .cloned()
            .collect()
    }
}

impl SecurityAlertPort for RecordingResponseAlerts {
    fn ensure_alerts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn page(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus> {
        let mut alerts = self.alerts.lock().map_err(|_| PortError::unavailable())?;
        match alerts.get(alert.idempotency_key.as_str()) {
            Some(existing) if existing != alert => return Err(PortError::conflict()),
            Some(_) => {}
            None => {
                alerts.insert(alert.idempotency_key.as_str().to_owned(), alert.clone());
            }
        }
        Ok(AlertDeliveryStatus::Delivered {
            attempts: 1,
            delivered_at_unix_ms: alert.occurred_at_unix_ms,
        })
    }

    fn load_delivery(&self, query: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>> {
        let alerts = self.alerts.lock().map_err(|_| PortError::unavailable())?;
        match alerts.get(query.alert.idempotency_key.as_str()) {
            Some(existing) if existing == &query.alert => {
                Ok(Some(AlertDeliveryStatus::Delivered {
                    attempts: 1,
                    delivered_at_unix_ms: query.alert.occurred_at_unix_ms,
                }))
            }
            Some(_) => Err(PortError::conflict()),
            None => Ok(None),
        }
    }
}

#[test]
fn partial_rollback_truth() {
    let directory = tempdir().test_expect("temporary directory");
    let path = directory.path().join("partial-rollback.db");
    let store = Arc::new(SqliteSecurityStateStore::open(path).test_expect("open response store"));
    let failed_session_id = "session-partial-rollback-failed";
    let restored_session_id = "session-partial-rollback-restored";
    let failed_target = overlay_target(failed_session_id);
    let restored_target = overlay_target(restored_session_id);
    let failed_contribution = CanonicalBody::new(b"{\"posture_rank\":7}".to_vec())
        .test_expect("failed suspension contribution");
    let failed_contribution_hash = digest(failed_contribution.as_bytes());
    let restored_contribution = CanonicalBody::new(b"{\"posture_rank\":5}".to_vec())
        .test_expect("restored suspension contribution");
    let restored_contribution_hash = digest(restored_contribution.as_bytes());
    let created_at_unix_ms = current_unix_ms();
    let plan = build_response_plan(ResponsePlanInput {
        action_id: action("partial-rollback-action"),
        trigger_finding_id: record("partial-rollback-finding"),
        trigger_finding_hash: digest(b"partial-rollback-finding"),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("partial-rollback-trigger")
            .test_expect("trigger receipt"),
        tenant_id: tenant("tenant-active-defense"),
        policy_version: record("active-defense-rollback-policy"),
        policy_hash: digest(b"active-defense-rollback-policy"),
        affected_ids: vec![record(failed_session_id), record(restored_session_id)],
        effects: vec![
            ResponseEffectSpec {
                kind: ResponseEffectKind::SuspendSession,
                target: ResponseTarget::Session {
                    session_id: SessionId::new(failed_session_id)
                        .test_expect("failed response session"),
                },
                canonical_contribution: failed_contribution,
                contribution_hash: failed_contribution_hash,
                observed_base_version_hash: containment_overlay_version_hash(&empty_overlay(
                    failed_target.clone(),
                ))
                .test_expect("failed empty overlay hash"),
            },
            ResponseEffectSpec {
                kind: ResponseEffectKind::SuspendSession,
                target: ResponseTarget::Session {
                    session_id: SessionId::new(restored_session_id)
                        .test_expect("restored response session"),
                },
                canonical_contribution: restored_contribution,
                contribution_hash: restored_contribution_hash,
                observed_base_version_hash: containment_overlay_version_hash(&empty_overlay(
                    restored_target.clone(),
                ))
                .test_expect("restored empty overlay hash"),
            },
        ],
        ttl_ms: 60_000,
        created_at_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record("partial-rollback-capability"),
            capability_digest: digest(b"partial-rollback-capability"),
            expires_at_unix_ms: created_at_unix_ms.saturating_add(180_000),
            executor_subject: record("partial-rollback-executor"),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: record("partial-rollback-submitter"),
        reason_hash: digest(b"partial-rollback-reason"),
    })
    .test_expect("build partial rollback response plan");
    let expires_at_unix_ms = plan.expires_at_unix_ms;
    let dispatch = prepare_response_dispatch(ResponseDispatchPreparationRequest {
        authorization_capability_hash: plan.operator_capability.capability_digest,
        plan,
        dispatch_id: record("partial-rollback-dispatch"),
        governed_intent_hash: digest(b"partial-rollback-intent"),
        policy_decision_hash: digest(b"partial-rollback-decision"),
        executor_authority_id: record("partial-rollback-authority"),
        executor_authority_generation: 1,
        approval: ResponseDispatchApproval::Automatic,
        authorized_at_unix_ms: created_at_unix_ms,
        initial_lease: ResponseDispatchLease {
            lease_owner_id: LeaseOwnerId::new("partial-rollback-worker")
                .test_expect("response lease owner"),
            lease_expires_at_unix_ms: expires_at_unix_ms,
        },
        commit_mode: chio_security_types::ports::ResponseDispatchCommitMode::Fresh,
    })
    .test_expect("prepare partial rollback dispatch");
    let committed = match store
        .commit_dispatch(&dispatch)
        .test_expect("commit partial rollback dispatch")
    {
        ResponseDispatchCommitOutcome::Committed(record)
        | ResponseDispatchCommitOutcome::Existing(record) => record,
    };
    let overlay_store: Arc<dyn ContainmentOverlayStore> =
        Arc::new(SelectiveRemoveFailingContainmentOverlayStore {
            inner: Arc::clone(&store),
            failed_target: failed_target.clone(),
        });
    let effects = Arc::new(ActiveResponseEffectPort::session_suspension_only(Arc::new(
        SessionSuspensionOverlayBackend::new(overlay_store),
    )));
    let receipts = Arc::new(RecordingResponseReceipts::default());
    let alerts = Arc::new(RecordingResponseAlerts::default());
    let executor = ResponseExecutor::new(
        Arc::clone(&store),
        effects,
        Arc::clone(&receipts),
        Arc::clone(&alerts),
    );
    let active = executor
        .execute(
            &committed.response_plan,
            &committed.initial_work,
            created_at_unix_ms.saturating_add(1),
        )
        .test_expect("apply containment response");
    assert_eq!(
        decode_response_record(&active)
            .test_expect("decode active response")
            .state,
        ResponseState::Active
    );
    let lease_now = current_unix_ms();
    let rollback_work = store
        .renew_lease(&SchedulerLeaseRenewRequest {
            work: committed.initial_work,
            transition_id: record("partial-rollback-lease-renewal"),
            now_unix_ms: lease_now,
            lease_expires_at_unix_ms: expires_at_unix_ms.saturating_add(60_000),
        })
        .test_expect("renew response lease through rollback");
    let partial = executor
        .execute(&active, &rollback_work, expires_at_unix_ms)
        .test_expect("record failed containment rollback");
    let snapshot = decode_response_record(&partial).test_expect("decode partial rollback");
    assert_eq!(snapshot.state, ResponseState::RollbackPartial);
    assert!(snapshot.operator_page_required);
    let failed_effect_id = snapshot.plan.effects.as_slice()[0].effect_id.clone();
    let restored_effect_id = snapshot.plan.effects.as_slice()[1].effect_id.clone();
    assert_eq!(
        snapshot.effect_progress(&failed_effect_id),
        Some(ResponseEffectProgress::RollbackFailed)
    );
    assert_eq!(
        snapshot.effect_progress(&restored_effect_id),
        Some(ResponseEffectProgress::Restored)
    );
    let durable = store
        .load_plan(&ResponsePlanKey {
            tenant_id: partial.tenant_id.clone(),
            action_id: partial.action_id.clone(),
        })
        .test_expect("load durable partial rollback")
        .test_expect("durable partial rollback exists");
    assert_eq!(durable, partial);
    let remaining = store
        .load_effective(&failed_target)
        .test_expect("load remaining containment")
        .test_expect("containment overlay remains");
    assert_eq!(remaining.active_contributions.len(), 1);
    assert_eq!(
        remaining.active_contributions.as_slice()[0].effect_id,
        failed_effect_id
    );
    let restored = store
        .load_effective(&restored_target)
        .test_expect("load restored containment")
        .test_expect("restored containment snapshot remains");
    assert!(restored.active_contributions.is_empty());
    assert_eq!(
        overlay_guard_verdict(Arc::clone(&store), failed_session_id),
        Verdict::Deny
    );
    assert_eq!(
        overlay_guard_verdict(Arc::clone(&store), restored_session_id),
        Verdict::Allow
    );
    let pages = alerts.alerts();
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].alert_type.as_str(), "response_rollback_partial");
    assert_eq!(pages[0].evidence_hash, partial.body_hash);
    let receipts = receipts.receipts();
    assert!(receipts.iter().any(|receipt| matches!(
        receipt,
        ActiveDefenseReceiptBody::EffectTransition(body)
            if body.effect.effect_id == failed_effect_id
                && matches!(&body.outcome, ActiveDefenseEffectOutcome::RollbackFailed { .. })
    )));
    assert!(receipts.iter().any(|receipt| matches!(
        receipt,
        ActiveDefenseReceiptBody::EffectTransition(body)
            if body.effect.effect_id == restored_effect_id
                && matches!(&body.outcome, ActiveDefenseEffectOutcome::Restored { .. })
    )));
    assert!(receipts.iter().any(|receipt| matches!(
        receipt,
        ActiveDefenseReceiptBody::ResponseStateTransition(body)
            if body.to_state == ResponseState::RollbackPartial
                && body.cause == ResponseTransitionCause::RollbackFailed
                && body.error_code.is_some()
    )));
    assert!(!receipts
        .iter()
        .any(|receipt| matches!(receipt, ActiveDefenseReceiptBody::LiftRollbackCompletion(_))));
}
