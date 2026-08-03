fn body(value: &'static [u8]) -> CanonicalBody {
    CanonicalBody::new(value.to_vec()).unwrap_or_else(|error| panic!("canonical body: {error}"))
}

fn label(value: &str) -> InformationLabel {
    InformationLabel::try_known(
        Default::default(),
        BTreeSet::from([
            Compartment::new(value).unwrap_or_else(|error| panic!("compartment: {error}"))
        ]),
    )
    .unwrap_or_else(|error| panic!("information label: {error}"))
}

fn flow_key(session: &str, epoch: &str) -> FlowStateKey {
    FlowStateKey {
        tenant_id: tenant(),
        principal_id: PrincipalId::new(format!("principal-{session}"))
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        lineage_id: LineageId::new(format!("lineage-{session}"))
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        session_id: SessionId::new(session).unwrap_or_else(|error| panic!("session id: {error}")),
        isolation_epoch_id: IsolationEpochId::new(epoch)
            .unwrap_or_else(|error| panic!("isolation epoch id: {error}")),
    }
}

fn scoped_action(value: &str) -> TenantScopedId {
    TenantScopedId {
        tenant_id: tenant(),
        id: record(value),
    }
}

fn overlay_apply_request(
    current: &OverlaySnapshot,
    session_id: &str,
    action_id: ActionId,
    effect_id: EffectId,
    posture_rank: u32,
    scheduler_fencing_token: u64,
    idempotency_suffix: &str,
) -> OverlayApplyRequest {
    let contribution_bytes = format!("{{\"posture_rank\":{posture_rank}}}").into_bytes();
    let contribution_hash = digest(&contribution_bytes);
    let expires_at_unix_ms = now_unix_ms().saturating_add(120_000);
    let effect_request = EffectRequest {
        tenant_id: current.target.tenant_id.clone(),
        action_id: action_id.clone(),
        plan_hash: digest(format!("plan:{idempotency_suffix}").as_bytes()),
        effect_id: effect_id.clone(),
        effect_kind: ResponseEffectKind::SuspendSession,
        target: ResponseTarget::Session {
            session_id: SessionId::new(session_id)
                .unwrap_or_else(|error| panic!("session id: {error}")),
        },
        plan_expires_at_unix_ms: expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record(format!("response_effect_command:{idempotency_suffix}").as_str()),
        expected_version_hash: containment_overlay_version_hash(current)
            .unwrap_or_else(|error| panic!("base version hash: {error}")),
        scheduler_lease_owner_id: LeaseOwnerId::new("overlay-contract-worker")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        scheduler_fencing_token,
        canonical_contribution: CanonicalBody::new(contribution_bytes)
            .unwrap_or_else(|error| panic!("overlay contribution body: {error}")),
        contribution_hash,
    };
    let contribution = OverlayContribution {
        effect_id: effect_id.clone(),
        posture_rank,
        contribution_hash,
        expires_at_unix_ms: Some(expires_at_unix_ms),
    };
    let resulting_snapshot =
        predict_containment_overlay_apply(current, &contribution, scheduler_fencing_token)
            .unwrap_or_else(|error| panic!("predict overlay apply: {error}"));
    OverlayApplyRequest {
        target: current.target.clone(),
        action_id,
        contribution: contribution.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: ContainmentOverlayCommand {
            request: effect_request,
            result: EffectResult {
                effect_id,
                resulting_version_hash: containment_installed_version_hash(
                    &current.target,
                    &contribution,
                )
                .unwrap_or_else(|error| panic!("installed version hash: {error}")),
                applied: true,
            },
            resulting_snapshot,
        },
    }
}

fn overlay_remove_request(
    apply: &OverlayApplyRequest,
    current: &OverlaySnapshot,
    session_id: &str,
    scheduler_fencing_token: u64,
    idempotency_suffix: &str,
) -> OverlayRemoveRequest {
    let mut effect_request = apply.command.request.clone();
    effect_request.target = ResponseTarget::Session {
        session_id: SessionId::new(session_id)
            .unwrap_or_else(|error| panic!("session id: {error}")),
    };
    effect_request.operation = EffectOperation::Remove;
    effect_request.idempotency_key =
        record(format!("response_effect_command:{idempotency_suffix}").as_str());
    effect_request.expected_version_hash = apply.command.result.resulting_version_hash;
    effect_request.scheduler_fencing_token = scheduler_fencing_token;
    let resulting_snapshot = predict_containment_overlay_remove(
        current,
        &apply.contribution.effect_id,
        scheduler_fencing_token,
    )
    .unwrap_or_else(|error| panic!("predict overlay remove: {error}"));
    OverlayRemoveRequest {
        target: current.target.clone(),
        action_id: apply.action_id.clone(),
        effect_id: apply.contribution.effect_id.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: ContainmentOverlayCommand {
            request: effect_request,
            result: EffectResult {
                effect_id: apply.contribution.effect_id.clone(),
                resulting_version_hash: containment_overlay_version_hash(&resulting_snapshot)
                    .unwrap_or_else(|error| panic!("removed version hash: {error}")),
                applied: false,
            },
            resulting_snapshot,
        },
    }
}

fn overlay_target(session_id: &str) -> TenantScopedId {
    containment_session_target(
        &tenant(),
        &SessionId::new(session_id).unwrap_or_else(|error| panic!("session id: {error}")),
    )
    .unwrap_or_else(|error| panic!("containment target: {error}"))
}

fn empty_overlay(target: TenantScopedId) -> OverlaySnapshot {
    OverlaySnapshot {
        target,
        generation: 0,
        effective_posture_rank: 0,
        active_contributions: OverlayContributions::new(Vec::new())
            .unwrap_or_else(|error| panic!("empty overlay: {error}")),
        highest_fencing_token: 0,
    }
}

fn require_unavailable<T>(result: PortResult<T>) {
    let error = result
        .err()
        .unwrap_or_else(|| panic!("fault injection unexpectedly returned success"));
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
    assert!(!error.code().as_str().is_empty());
}

fn require_error_kind<T>(result: PortResult<T>, expected: PortErrorKind) {
    let error = result
        .err()
        .unwrap_or_else(|| panic!("invalid mutation unexpectedly returned success"));
    assert_eq!(error.kind(), expected);
    assert!(!error.code().as_str().is_empty());
}

fn verified_event(value: &str, event_time: u64) -> VerifiedSecurityEvent {
    let canonical_body = body(b"{}");
    VerifiedSecurityEvent {
        tenant_id: tenant(),
        event_id: EventId::new(value).unwrap_or_else(|error| panic!("event id: {error}")),
        producer_id: ProducerId::new("producer-verified")
            .unwrap_or_else(|error| panic!("producer id: {error}")),
        trust_class: ProducerTrustClass::InternalDetector,
        event_time_unix_ms: event_time,
        received_at_unix_ms: event_time,
        body_hash: digest(canonical_body.as_bytes()),
        canonical_body,
        evidence_hash: Digest32::new([9_u8; 32]),
    }
}

fn advisory_event(value: &str, event_time: u64) -> AdvisorySecurityEvent {
    let canonical_body = body(b"{}");
    AdvisorySecurityEvent {
        tenant_id: tenant(),
        event_id: EventId::new(value).unwrap_or_else(|error| panic!("event id: {error}")),
        producer_id: ProducerId::new("producer-advisory")
            .unwrap_or_else(|error| panic!("producer id: {error}")),
        event_time_unix_ms: event_time,
        body_hash: digest(canonical_body.as_bytes()),
        canonical_body,
    }
}

fn response_plan_for_tenant(
    tenant_id: TenantId,
    value: &str,
    generation: u64,
    due_at: Option<u64>,
) -> ResponsePlanRecord {
    let expires_at_unix_ms = due_at.unwrap_or(1_060_000);
    let ttl_ms = 60_000;
    let created_at_unix_ms = expires_at_unix_ms
        .checked_sub(ttl_ms)
        .unwrap_or_else(|| panic!("response expiry is below the fixture TTL"));
    let canonical_contribution = body(b"{}");
    let plan = build_response_plan(ResponsePlanInput {
        action_id: action(value),
        trigger_finding_id: record(&format!("finding-{value}")),
        trigger_finding_hash: digest(format!("finding:{value}").as_bytes()),
        trigger_finding_receipt_id: OpaqueReceiptRef::new(format!("finding-receipt-{value}"))
            .unwrap_or_else(|error| panic!("finding receipt id: {error}")),
        tenant_id,
        policy_version: record(&format!("policy-{value}")),
        policy_hash: digest(format!("policy:{value}").as_bytes()),
        affected_ids: vec![record(&format!("affected-{value}"))],
        effects: vec![ResponseEffectSpec {
            kind: ResponseEffectKind::ThrottleSession,
            target: ResponseTarget::Session {
                session_id: SessionId::new(format!("session-{value}"))
                    .unwrap_or_else(|error| panic!("session id: {error}")),
            },
            contribution_hash: digest(canonical_contribution.as_bytes()),
            canonical_contribution,
            observed_base_version_hash: digest(format!("base-version:{value}").as_bytes()),
        }],
        ttl_ms,
        created_at_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record(&format!("capability-{value}")),
            capability_digest: digest(format!("capability:{value}").as_bytes()),
            expires_at_unix_ms: expires_at_unix_ms.saturating_add(ttl_ms),
            executor_subject: record(&format!("executor-{value}")),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: record(&format!("submitter-{value}")),
        reason_hash: digest(format!("reason:{value}").as_bytes()),
    })
    .unwrap_or_else(|error| panic!("response plan: {error}"));
    let store = Arc::new(ModelStore::default());
    let machine = ResponseStateMachine::new(Arc::clone(&store));
    let planned = machine
        .create(plan)
        .unwrap_or_else(|error| panic!("planned response: {error}"));
    match generation {
        0 => planned,
        1 => machine
            .transition(
                &planned,
                &ResponseTransitionRequest {
                    expected_generation: 0,
                    target_state: ResponseState::Cancelled,
                    occurred_at_unix_ms: created_at_unix_ms.saturating_add(1),
                    applying_lease_expires_at_unix_ms: None,
                    error_code: None,
                },
            )
            .unwrap_or_else(|error| panic!("cancelled response: {error}")),
        _ => panic!("unsupported response fixture generation {generation}"),
    }
}

fn response_plan(value: &str, generation: u64, due_at: Option<u64>) -> ResponsePlanRecord {
    response_plan_for_tenant(tenant(), value, generation, due_at)
}

fn response_transition_id(record: &ResponsePlanRecord) -> RecordId {
    decode_response_record(record)
        .unwrap_or_else(|error| panic!("response record: {error}"))
        .mutations
        .as_slice()
        .last()
        .unwrap_or_else(|| panic!("response mutation log is empty"))
        .transition_id()
        .clone()
}

struct AcceptIsolationEvidence;

impl IsolationEpochEvidenceVerifierPort for AcceptIsolationEvidence {
    fn verify(
        &self,
        transition: &IsolationEpochTransition,
    ) -> PortResult<VerifiedIsolationEvidence> {
        if transition.verification_evidence_hash != Digest32::new([8_u8; 32]) {
            return Err(PortError::invalid_data());
        }
        Ok(VerifiedIsolationEvidence {
            verifier_id: record("contract-verifier"),
            receipt_ref: OpaqueReceiptRef::new("contract-receipt").map_err(PortError::from)?,
        })
    }
}

fn exercise_contracts<S>(store: &Faulting<S>)
where
    S: FlowStateStore
        + SecurityEventStore
        + ResponseStore
        + ContainmentOverlayStore
        + LineageFenceStore,
{
    let clock = now_unix_ms();
    let expiry = clock.saturating_add(120_000);

    let first_key = flow_key("session-flow-before", "epoch-base");
    let first_join = FlowJoinRequest {
        key: first_key.clone(),
        principal_join: label("principal-before"),
        lineage_join: label("lineage-before"),
        session_join: label("session-before"),
        transition_id: record("flow-before"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.join(&first_join));
    assert_eq!(
        store
            .load(&first_key)
            .unwrap_or_else(|error| panic!("load flow before retry: {error}")),
        None
    );
    let first_snapshot = store
        .join(&first_join)
        .unwrap_or_else(|error| panic!("retry flow join: {error}"));

    let second_key = flow_key("session-flow-after", "epoch-base");
    let second_join = FlowJoinRequest {
        key: second_key.clone(),
        principal_join: label("principal-after"),
        lineage_join: label("lineage-after"),
        session_join: label("session-after"),
        transition_id: record("flow-after"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.join(&second_join));
    let committed_snapshot = store
        .load(&second_key)
        .unwrap_or_else(|error| panic!("load committed flow: {error}"))
        .unwrap_or_else(|| panic!("committed flow missing"));
    assert_eq!(
        store
            .join(&second_join)
            .unwrap_or_else(|error| panic!("recover flow join: {error}")),
        committed_snapshot
    );

    let isolation_before = IsolationEpochTransition {
        tenant_id: tenant(),
        principal_id: first_key.principal_id.clone(),
        lineage_id: first_key.lineage_id.clone(),
        previous_isolation_epoch_id: first_key.isolation_epoch_id.clone(),
        new_isolation_epoch_id: IsolationEpochId::new("epoch-before")
            .unwrap_or_else(|error| panic!("epoch id: {error}")),
        new_session_id: SessionId::new("session-isolation-before")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        verification_evidence_hash: Digest32::new([8_u8; 32]),
        transition_id: record("isolation-before"),
        effective_at_unix_ms: clock,
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.open_isolation_epoch(&isolation_before));
    let isolated_before = store
        .open_isolation_epoch(&isolation_before)
        .unwrap_or_else(|error| panic!("retry isolation epoch: {error}"));
    assert_eq!(isolated_before.principal_label, InformationLabel::bottom());

    let isolation_after = IsolationEpochTransition {
        new_isolation_epoch_id: IsolationEpochId::new("epoch-after")
            .unwrap_or_else(|error| panic!("epoch id: {error}")),
        new_session_id: SessionId::new("session-isolation-after")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        transition_id: record("isolation-after"),
        ..isolation_before
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.open_isolation_epoch(&isolation_after));
    let isolated_key = FlowStateKey {
        tenant_id: isolation_after.tenant_id.clone(),
        principal_id: isolation_after.principal_id.clone(),
        lineage_id: isolation_after.lineage_id.clone(),
        session_id: isolation_after.new_session_id.clone(),
        isolation_epoch_id: isolation_after.new_isolation_epoch_id.clone(),
    };
    let stored_isolation = store
        .load(&isolated_key)
        .unwrap_or_else(|error| panic!("load committed isolation epoch: {error}"))
        .unwrap_or_else(|| panic!("committed isolation epoch missing"));
    assert_eq!(
        store
            .open_isolation_epoch(&isolation_after)
            .unwrap_or_else(|error| panic!("recover isolation epoch: {error}")),
        stored_isolation
    );

    let fence_before_request = EgressFenceRequest {
        key: first_key.clone(),
        request_id: RequestId::new("egress-before")
            .unwrap_or_else(|error| panic!("request id: {error}")),
        request_hash: Digest32::new([11; 32]),
        expected_context_generation: first_snapshot.context_generation,
        expires_at_unix_ms: expiry,
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.acquire_egress_fence(&fence_before_request));
    let fence_before = store
        .acquire_egress_fence(&fence_before_request)
        .unwrap_or_else(|error| panic!("retry egress fence: {error}"));
    store
        .validate_egress_fence(&fence_before)
        .unwrap_or_else(|error| panic!("validate egress fence: {error}"));

    let fence_after_request = EgressFenceRequest {
        key: second_key,
        request_id: RequestId::new("egress-after")
            .unwrap_or_else(|error| panic!("request id: {error}")),
        request_hash: Digest32::new([12; 32]),
        expected_context_generation: committed_snapshot.context_generation,
        expires_at_unix_ms: expiry,
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.acquire_egress_fence(&fence_after_request));
    let fence_after = store
        .acquire_egress_fence(&fence_after_request)
        .unwrap_or_else(|error| panic!("recover egress fence: {error}"));

    let commit_before = EgressFenceCommit {
        fence: fence_before,
        dispatch_commitment_id: record("dispatch-before"),
        committed_at_unix_ms: clock,
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.commit_egress_fence(&commit_before));
    let committed_before = store
        .commit_egress_fence(&commit_before)
        .unwrap_or_else(|error| panic!("retry egress commit: {error}"));
    assert_eq!(
        committed_before.dispatch_commitment_id,
        record("dispatch-before")
    );

    let commit_after = EgressFenceCommit {
        fence: fence_after,
        dispatch_commitment_id: record("dispatch-after"),
        committed_at_unix_ms: clock,
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.commit_egress_fence(&commit_after));
    assert_eq!(
        store
            .commit_egress_fence(&commit_after)
            .unwrap_or_else(|error| panic!("recover egress commit: {error}"))
            .dispatch_commitment_id,
        record("dispatch-after")
    );

    exercise_events(store, clock);
    let (claimed_before, claimed_after) = exercise_responses(store, clock, expiry);
    exercise_overlays(store, &claimed_before, &claimed_after);
    exercise_lineage_fences(store, expiry);
}

fn correlation_key(value: u8) -> CorrelationPartitionKey {
    CorrelationPartitionKey {
        tenant_id: tenant(),
        rule_id: RuleId::new(format!("rule-{value}"))
            .unwrap_or_else(|error| panic!("rule id: {error}")),
        partition_hash: Digest32::new([value; 32]),
    }
}

fn scan_for(key: &CorrelationPartitionKey, through: u64) -> EventPartitionScan {
    EventPartitionScan {
        tenant_id: key.tenant_id.clone(),
        rule_id: key.rule_id.clone(),
        partition_hash: key.partition_hash,
        after_event_time_unix_ms: None,
        after_event_id: None,
        through_event_time_unix_ms: through,
        max_results: 8,
    }
}

fn partial(key: &CorrelationPartitionKey, generation: u64, watermark: u64) -> CorrelationPartial {
    let canonical_body = body(b"{}");
    CorrelationPartial {
        key: key.clone(),
        generation,
        watermark_unix_ms: watermark,
        expires_at_unix_ms: watermark.saturating_add(60_000),
        body_hash: digest(canonical_body.as_bytes()),
        canonical_body,
    }
}

fn correlation_outcome_publication(
    key: &CorrelationPartitionKey,
    event: &VerifiedSecurityEvent,
    rule_version_byte: u8,
) -> CorrelationOutcomePublication {
    let canonical_body = body(b"{}");
    CorrelationOutcomePublication {
        key: CorrelationOutcomeKey {
            tenant_id: key.tenant_id.clone(),
            rule_id: key.rule_id.clone(),
            event_id: event.event_id.clone(),
        },
        partition_hash: key.partition_hash,
        status: CorrelationOutcomeStatus::Accepted,
        watermark_unix_ms: event.event_time_unix_ms,
        rule_version_hash: Digest32::new([rule_version_byte; 32]),
        event_body_hash: event.body_hash,
        event_evidence_hash: event.evidence_hash,
        body_hash: digest(canonical_body.as_bytes()),
        canonical_body,
    }
}

fn exercise_events<S: SecurityEventStore>(store: &Faulting<S>, clock: u64) {
    let verified_before = verified_event("verified-before", clock);
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.append_verified(&verified_before));
    assert_eq!(
        store
            .append_verified(&verified_before)
            .unwrap_or_else(|error| panic!("retry verified append: {error}")),
        EventAppend::Inserted
    );

    let verified_after = verified_event("verified-after", clock.saturating_add(1));
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.append_verified(&verified_after));
    assert_eq!(
        store
            .append_verified(&verified_after)
            .unwrap_or_else(|error| panic!("recover verified append: {error}")),
        EventAppend::Duplicate
    );

    let advisory_before = advisory_event("advisory-before", clock);
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.append_advisory(&advisory_before));
    assert_eq!(
        store
            .append_advisory(&advisory_before)
            .unwrap_or_else(|error| panic!("retry advisory append: {error}")),
        EventAppend::Inserted
    );

    let advisory_after = advisory_event("advisory-after", clock.saturating_add(1));
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.append_advisory(&advisory_after));
    assert_eq!(
        store
            .append_advisory(&advisory_after)
            .unwrap_or_else(|error| panic!("recover advisory append: {error}")),
        EventAppend::Duplicate
    );

    let before_key = correlation_key(3);
    let before_index = CorrelationEventIndexRequest {
        key: before_key.clone(),
        event_id: verified_before.event_id.clone(),
        transition_id: record("index-before"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.index_partition_event(&before_index));
    assert!(store
        .scan_partition(&scan_for(&before_key, clock.saturating_add(10)))
        .unwrap_or_else(|error| panic!("scan before index retry: {error}"))
        .events
        .is_empty());
    store
        .index_partition_event(&before_index)
        .unwrap_or_else(|error| panic!("retry event index: {error}"));

    let after_key = correlation_key(4);
    let after_index = CorrelationEventIndexRequest {
        key: after_key.clone(),
        event_id: verified_after.event_id,
        transition_id: record("index-after"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.index_partition_event(&after_index));
    assert_eq!(
        store
            .scan_partition(&scan_for(&after_key, clock.saturating_add(10)))
            .unwrap_or_else(|error| panic!("scan committed index: {error}"))
            .events
            .len(),
        1
    );
    store
        .index_partition_event(&after_index)
        .unwrap_or_else(|error| panic!("recover event index: {error}"));

    let before_scan = scan_for(&before_key, clock);
    let before_cas = CorrelationCasRequest {
        scan: before_scan,
        observed_partition_generation: 1,
        partial: partial(&before_key, 0, clock),
        expected_generation: None,
        transition_id: record("correlation-before"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.compare_and_swap_correlation(&before_cas));
    assert_eq!(
        store
            .load_correlation(&before_key)
            .unwrap_or_else(|error| panic!("load correlation before retry: {error}")),
        None
    );
    store
        .compare_and_swap_correlation(&before_cas)
        .unwrap_or_else(|error| panic!("retry correlation CAS: {error}"));

    let after_cas = CorrelationCasRequest {
        scan: scan_for(&after_key, clock.saturating_add(1)),
        observed_partition_generation: 1,
        partial: partial(&after_key, 0, clock.saturating_add(1)),
        expected_generation: None,
        transition_id: record("correlation-after"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.compare_and_swap_correlation(&after_cas));
    assert_eq!(
        store
            .load_correlation(&after_key)
            .unwrap_or_else(|error| panic!("load committed correlation: {error}")),
        Some(after_cas.partial.clone())
    );
    store
        .compare_and_swap_correlation(&after_cas)
        .unwrap_or_else(|error| panic!("recover correlation CAS: {error}"));

    let outcome_before_event = verified_event("outcome-before", clock.saturating_add(2));
    let outcome_before_key = correlation_key(21);
    store
        .append_verified(&outcome_before_event)
        .unwrap_or_else(|error| panic!("append before-write outcome event: {error}"));
    store
        .index_partition_event(&CorrelationEventIndexRequest {
            key: outcome_before_key.clone(),
            event_id: outcome_before_event.event_id.clone(),
            transition_id: record("index-outcome-before"),
        })
        .unwrap_or_else(|error| panic!("index before-write outcome event: {error}"));
    let outcome_before = CorrelationOutcomeCommitRequest {
        correlation: CorrelationCasRequest {
            scan: scan_for(&outcome_before_key, clock.saturating_add(2)),
            observed_partition_generation: 1,
            partial: partial(&outcome_before_key, 0, clock.saturating_add(2)),
            expected_generation: None,
            transition_id: record("correlation-outcome-before"),
        },
        outcome: correlation_outcome_publication(
            &outcome_before_key,
            &outcome_before_event,
            21,
        ),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.commit_correlation_outcome(&outcome_before));
    assert_eq!(
        store
            .load_correlation(&outcome_before_key)
            .unwrap_or_else(|error| panic!("load before-write outcome partial: {error}")),
        None
    );
    assert_eq!(
        store
            .load_correlation_outcome(&outcome_before.outcome.key)
            .unwrap_or_else(|error| panic!("load before-write outcome journal: {error}")),
        None
    );
    store
        .commit_correlation_outcome(&outcome_before)
        .unwrap_or_else(|error| panic!("retry correlation outcome commit: {error}"));
    assert_eq!(
        store
            .load_correlation(&outcome_before_key)
            .unwrap_or_else(|error| panic!("load committed outcome partial: {error}")),
        Some(outcome_before.correlation.partial.clone())
    );
    assert_eq!(
        store
            .load_correlation_outcome(&outcome_before.outcome.key)
            .unwrap_or_else(|error| panic!("load committed outcome journal: {error}")),
        Some(outcome_before.outcome.clone())
    );

    let outcome_after_event = verified_event("outcome-after", clock.saturating_add(3));
    let outcome_after_key = correlation_key(22);
    store
        .append_verified(&outcome_after_event)
        .unwrap_or_else(|error| panic!("append after-commit outcome event: {error}"));
    store
        .index_partition_event(&CorrelationEventIndexRequest {
            key: outcome_after_key.clone(),
            event_id: outcome_after_event.event_id.clone(),
            transition_id: record("index-outcome-after"),
        })
        .unwrap_or_else(|error| panic!("index after-commit outcome event: {error}"));
    let outcome_after = CorrelationOutcomeCommitRequest {
        correlation: CorrelationCasRequest {
            scan: scan_for(&outcome_after_key, clock.saturating_add(3)),
            observed_partition_generation: 1,
            partial: partial(&outcome_after_key, 0, clock.saturating_add(3)),
            expected_generation: None,
            transition_id: record("correlation-outcome-after"),
        },
        outcome: correlation_outcome_publication(
            &outcome_after_key,
            &outcome_after_event,
            22,
        ),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.commit_correlation_outcome(&outcome_after));
    assert_eq!(
        store
            .load_correlation(&outcome_after_key)
            .unwrap_or_else(|error| panic!("load post-commit outcome partial: {error}")),
        Some(outcome_after.correlation.partial.clone())
    );
    assert_eq!(
        store
            .load_correlation_outcome(&outcome_after.outcome.key)
            .unwrap_or_else(|error| panic!("load post-commit outcome journal: {error}")),
        Some(outcome_after.outcome.clone())
    );
    store
        .commit_correlation_outcome(&outcome_after)
        .unwrap_or_else(|error| panic!("recover correlation outcome ack loss: {error}"));
    let mut equivocated_outcome_replay = outcome_after.clone();
    equivocated_outcome_replay.correlation.transition_id =
        record("correlation-outcome-after-equivocated");
    require_error_kind(
        store.commit_correlation_outcome(&equivocated_outcome_replay),
        PortErrorKind::Conflict,
    );
    let mut deferred_outcome_replay = outcome_after.clone();
    deferred_outcome_replay.outcome.status = CorrelationOutcomeStatus::Deferred;
    require_error_kind(
        store.commit_correlation_outcome(&deferred_outcome_replay),
        PortErrorKind::InvalidData,
    );

    let unindexed_late_event = verified_event("outcome-unindexed-late", clock.saturating_add(2));
    store
        .append_verified(&unindexed_late_event)
        .unwrap_or_else(|error| panic!("append unindexed late event: {error}"));
    let mut unindexed_late_outcome =
        correlation_outcome_publication(&outcome_after_key, &unindexed_late_event, 23);
    unindexed_late_outcome.status = CorrelationOutcomeStatus::TooLate;
    assert_eq!(
        store
            .commit_correlation_outcome_only(&unindexed_late_outcome)
            .unwrap_or_else(|error| panic!("commit unindexed late outcome: {error}")),
        CreateOutcome::Created
    );
    assert_eq!(
        store
            .load_correlation_outcome(&unindexed_late_outcome.key)
            .unwrap_or_else(|error| panic!("load unindexed late outcome: {error}")),
        Some(unindexed_late_outcome)
    );

    let unindexed_future_event =
        verified_event("outcome-unindexed-future", clock.saturating_add(4));
    store
        .append_verified(&unindexed_future_event)
        .unwrap_or_else(|error| panic!("append unindexed future event: {error}"));
    let mut unindexed_future_outcome =
        correlation_outcome_publication(&outcome_after_key, &unindexed_future_event, 24);
    unindexed_future_outcome.status = CorrelationOutcomeStatus::TooLate;
    require_error_kind(
        store.commit_correlation_outcome_only(&unindexed_future_outcome),
        PortErrorKind::Conflict,
    );

    let unindexed_matched_event =
        verified_event("outcome-unindexed-matched", clock.saturating_add(2));
    store
        .append_verified(&unindexed_matched_event)
        .unwrap_or_else(|error| panic!("append unindexed matched event: {error}"));
    let mut unindexed_matched_outcome =
        correlation_outcome_publication(&outcome_after_key, &unindexed_matched_event, 25);
    unindexed_matched_outcome.status = CorrelationOutcomeStatus::Matched;
    require_error_kind(
        store.commit_correlation_outcome_only(&unindexed_matched_outcome),
        PortErrorKind::Conflict,
    );

    let stale_key = correlation_key(13);
    let stale_first = verified_event("verified-stale-first", clock.saturating_add(2));
    let stale_second = verified_event("verified-stale-second", clock.saturating_add(3));
    store
        .append_verified(&stale_first)
        .unwrap_or_else(|error| panic!("append first revision event: {error}"));
    store
        .index_partition_event(&CorrelationEventIndexRequest {
            key: stale_key.clone(),
            event_id: stale_first.event_id,
            transition_id: record("index-stale-first"),
        })
        .unwrap_or_else(|error| panic!("index first revision event: {error}"));
    let observed = store
        .scan_partition(&scan_for(&stale_key, clock.saturating_add(3)))
        .unwrap_or_else(|error| panic!("scan first partition revision: {error}"));
    assert_eq!(observed.partition_generation, 1);
    store
        .append_verified(&stale_second)
        .unwrap_or_else(|error| panic!("append second revision event: {error}"));
    store
        .index_partition_event(&CorrelationEventIndexRequest {
            key: stale_key.clone(),
            event_id: stale_second.event_id,
            transition_id: record("index-stale-second"),
        })
        .unwrap_or_else(|error| panic!("index second revision event: {error}"));
    let stale_cas = CorrelationCasRequest {
        scan: scan_for(&stale_key, clock.saturating_add(3)),
        observed_partition_generation: observed.partition_generation,
        partial: partial(&stale_key, 0, clock.saturating_add(3)),
        expected_generation: None,
        transition_id: record("correlation-stale-revision"),
    };
    require_error_kind(
        store.compare_and_swap_correlation(&stale_cas),
        PortErrorKind::Conflict,
    );
    assert_eq!(
        store
            .load_correlation(&stale_key)
            .unwrap_or_else(|error| panic!("load rejected stale correlation: {error}")),
        None
    );

    require_error_kind(
        store.delete_correlation(&CorrelationDeleteRequest {
            key: before_key.clone(),
            expected_generation: 1,
            transition_id: record("correlation-delete-wrong-generation"),
        }),
        PortErrorKind::Conflict,
    );
    assert!(store
        .load_correlation(&before_key)
        .unwrap_or_else(|error| panic!("load correlation after rejected delete: {error}"))
        .is_some());

    let delete_before = CorrelationDeleteRequest {
        key: before_key.clone(),
        expected_generation: 0,
        transition_id: record("correlation-delete-before"),
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.delete_correlation(&delete_before));
    assert!(store
        .load_correlation(&before_key)
        .unwrap_or_else(|error| panic!("load correlation before delete retry: {error}"))
        .is_some());
    store
        .delete_correlation(&delete_before)
        .unwrap_or_else(|error| panic!("retry correlation delete: {error}"));

    let delete_after = CorrelationDeleteRequest {
        key: after_key.clone(),
        expected_generation: 0,
        transition_id: record("correlation-delete-after"),
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.delete_correlation(&delete_after));
    assert_eq!(
        store
            .load_correlation(&after_key)
            .unwrap_or_else(|error| panic!("load deleted correlation: {error}")),
        None
    );
    store
        .delete_correlation(&delete_after)
        .unwrap_or_else(|error| panic!("recover correlation delete: {error}"));
}

fn claim_request(owner: &str, clock: u64, expiry: u64) -> SchedulerClaimRequest {
    SchedulerClaimRequest {
        tenant_id: tenant(),
        claim_id: record(&format!("claim-{owner}")),
        lease_owner_id: LeaseOwnerId::new(owner)
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms: clock,
        lease_expires_at_unix_ms: expiry,
        max_claims: 1,
    }
}

fn response_effect(
    action_id: &ActionId,
    effect_id: &str,
    owner: &LeaseOwnerId,
    token: u64,
) -> ResponseEffectRecord {
    let canonical_body = body(b"{}");
    ResponseEffectRecord {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        effect_id: effect(effect_id),
        generation: 0,
        scheduler_lease_owner_id: owner.clone(),
        scheduler_fencing_token: token,
        state: record("applied"),
        body_hash: digest(canonical_body.as_bytes()),
        canonical_body,
        encrypted_rollback_ref: None,
    }
}

fn exercise_responses<S: ResponseStore>(
    store: &Faulting<S>,
    clock: u64,
    expiry: u64,
) -> (ScheduledWork, ScheduledWork) {
    let create_before = response_plan("response-create-before", 0, None);
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.create(&create_before));
    assert_eq!(
        store
            .create(&create_before)
            .unwrap_or_else(|error| panic!("retry response create: {error}")),
        CreateOutcome::Created
    );

    let create_after = response_plan("response-create-after", 0, None);
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.create(&create_after));
    assert_eq!(
        store
            .create(&create_after)
            .unwrap_or_else(|error| panic!("recover response create: {error}")),
        CreateOutcome::Existing
    );

    let cas_before_record = response_plan("response-create-before", 1, None);
    let cas_before = ResponseCasRequest {
        transition_id: response_transition_id(&cas_before_record),
        record: cas_before_record,
        expected_generation: 0,
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.compare_and_swap(&cas_before));
    assert_eq!(
        store
            .compare_and_swap(&cas_before)
            .unwrap_or_else(|error| panic!("retry response CAS: {error}")),
        cas_before.record
    );

    let cas_after_record = response_plan("response-create-after", 1, None);
    let cas_after = ResponseCasRequest {
        transition_id: response_transition_id(&cas_after_record),
        record: cas_after_record,
        expected_generation: 0,
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.compare_and_swap(&cas_after));
    assert_eq!(
        store
            .compare_and_swap(&cas_after)
            .unwrap_or_else(|error| panic!("recover response CAS: {error}")),
        cas_after.record
    );

    let due_before = response_plan("scheduler-before", 0, Some(clock.saturating_sub(1)));
    store
        .create(&due_before)
        .unwrap_or_else(|error| panic!("create scheduler plan: {error}"));
    let claim_before = claim_request("scheduler-owner-before", clock, expiry);
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.claim_due(&claim_before));
    let claimed_before = store
        .claim_due(&claim_before)
        .unwrap_or_else(|error| panic!("retry scheduler claim: {error}"));
    assert_eq!(claimed_before.len(), 1);
    let claimed_before = claimed_before
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("scheduler claim was empty"));

    let due_after = response_plan("scheduler-after", 0, Some(clock.saturating_sub(1)));
    store
        .create(&due_after)
        .unwrap_or_else(|error| panic!("create second scheduler plan: {error}"));
    let claim_after = claim_request("scheduler-owner-after", clock, expiry);
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.claim_due(&claim_after));
    let recovered_after = store
        .claim_due(&claim_after)
        .unwrap_or_else(|error| panic!("retry committed scheduler claim: {error}"));
    assert_eq!(recovered_after.len(), 1);
    let recovered_after = recovered_after
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("recovered scheduler claim was empty"));
    assert_eq!(recovered_after.action_id, due_after.action_id);
    assert_eq!(
        store
            .claim_due(&claim_after)
            .unwrap_or_else(|error| panic!("repeat exact scheduler claim: {error}")),
        vec![recovered_after.clone()]
    );
    let mismatched_claim = SchedulerClaimRequest {
        max_claims: 2,
        ..claim_after.clone()
    };
    require_error_kind(store.claim_due(&mismatched_claim), PortErrorKind::Conflict);
    let tenant_b =
        TenantId::new("tenant-contract-b").unwrap_or_else(|error| panic!("tenant id: {error}"));
    let tenant_b_plan = response_plan_for_tenant(
        tenant_b.clone(),
        "scheduler-tenant-b",
        0,
        Some(clock.saturating_sub(1)),
    );
    store
        .create(&tenant_b_plan)
        .unwrap_or_else(|error| panic!("create other tenant scheduler plan: {error}"));
    let tenant_b_claim = SchedulerClaimRequest {
        tenant_id: tenant_b.clone(),
        ..claim_after.clone()
    };
    let tenant_b_work = store
        .claim_due(&tenant_b_claim)
        .unwrap_or_else(|error| panic!("claim other tenant plan: {error}"));
    assert_eq!(tenant_b_work.len(), 1);
    assert_eq!(tenant_b_work[0].tenant_id, tenant_b);
    assert_eq!(tenant_b_work[0].action_id, tenant_b_plan.action_id);
    assert_eq!(
        store
            .claim_due(&claim_after)
            .unwrap_or_else(|error| panic!("recover original tenant claim: {error}")),
        vec![recovered_after.clone()]
    );
    let committed_lease_probe = response_effect(
        &due_after.action_id,
        "scheduler-after-lease-probe",
        &recovered_after.lease_owner_id,
        recovered_after.fencing_token,
    );
    assert_eq!(
        store
            .persist_effect(&committed_lease_probe)
            .unwrap_or_else(|error| panic!("probe committed scheduler lease: {error}")),
        CreateOutcome::Created
    );

    let effect_before = response_effect(
        &claimed_before.action_id,
        "response-effect-before",
        &claimed_before.lease_owner_id,
        claimed_before.fencing_token,
    );
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.persist_effect(&effect_before));
    assert_eq!(
        store
            .persist_effect(&effect_before)
            .unwrap_or_else(|error| panic!("retry response effect: {error}")),
        CreateOutcome::Created
    );

    let effect_after = response_effect(
        &claimed_before.action_id,
        "response-effect-after",
        &claimed_before.lease_owner_id,
        claimed_before.fencing_token,
    );
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.persist_effect(&effect_after));
    assert_eq!(
        store
            .persist_effect(&effect_after)
            .unwrap_or_else(|error| panic!("recover response effect: {error}")),
        CreateOutcome::Existing
    );
    (claimed_before, recovered_after)
}

fn exercise_overlays<S: ContainmentOverlayStore>(
    store: &Faulting<S>,
    claimed_before: &ScheduledWork,
    claimed_after: &ScheduledWork,
) {
    let before_session = "overlay-before-session";
    let before_target = overlay_target(before_session);
    let before_empty = empty_overlay(before_target.clone());
    let before_apply = overlay_apply_request(
        &before_empty,
        before_session,
        claimed_before.action_id.clone(),
        effect("overlay-effect-before"),
        4,
        claimed_before.fencing_token,
        "overlay-before-apply",
    );
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.apply_contribution(&before_apply));
    assert_eq!(
        store
            .load_effective(&before_target)
            .unwrap_or_else(|error| panic!("load overlay before retry: {error}")),
        None
    );
    let before_snapshot = store
        .apply_contribution(&before_apply)
        .unwrap_or_else(|error| panic!("retry overlay apply: {error}"));
    assert_eq!(before_snapshot.generation, 1);

    let after_session = "overlay-after-session";
    let after_target = overlay_target(after_session);
    let after_empty = empty_overlay(after_target.clone());
    let after_apply = overlay_apply_request(
        &after_empty,
        after_session,
        claimed_after.action_id.clone(),
        effect("overlay-effect-after"),
        7,
        claimed_after.fencing_token,
        "overlay-after-apply",
    );
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.apply_contribution(&after_apply));
    let after_snapshot = store
        .load_effective(&after_target)
        .unwrap_or_else(|error| panic!("load committed overlay: {error}"))
        .unwrap_or_else(|| panic!("committed overlay missing"));
    assert_eq!(after_snapshot.generation, 1);
    assert_eq!(
        store
            .apply_contribution(&after_apply)
            .unwrap_or_else(|error| panic!("recover overlay apply: {error}")),
        after_snapshot
    );

    let before_remove = overlay_remove_request(
        &before_apply,
        &before_snapshot,
        before_session,
        claimed_before.fencing_token,
        "overlay-before-remove",
    );
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.remove_contribution(&before_remove));
    assert_eq!(
        store
            .load_effective(&before_target)
            .unwrap_or_else(|error| panic!("load overlay before remove retry: {error}"))
            .unwrap_or_else(|| panic!("overlay missing before remove retry"))
            .active_contributions
            .len(),
        1
    );
    assert!(store
        .remove_contribution(&before_remove)
        .unwrap_or_else(|error| panic!("retry overlay remove: {error}"))
        .active_contributions
        .is_empty());

    let after_remove = overlay_remove_request(
        &after_apply,
        &after_snapshot,
        after_session,
        claimed_after.fencing_token,
        "overlay-after-remove",
    );
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.remove_contribution(&after_remove));
    assert!(store
        .load_effective(&after_target)
        .unwrap_or_else(|error| panic!("load committed overlay removal: {error}"))
        .unwrap_or_else(|| panic!("overlay state missing after removal"))
        .active_contributions
        .is_empty());
    assert!(store
        .remove_contribution(&after_remove)
        .unwrap_or_else(|error| panic!("recover overlay removal: {error}"))
        .active_contributions
        .is_empty());
}

fn fence_request(value: &str, expiry: u64) -> LineageFenceRequest {
    LineageFenceRequest {
        tenant_id: tenant(),
        action_id: action(value),
        expected_commit_index: 7,
        expected_affected_set_hash: digest(value.as_bytes()),
        scheduler_lease_owner_id: LeaseOwnerId::new("lineage-contract-worker")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        scheduler_fencing_token: 9,
        expires_at_unix_ms: expiry,
    }
}

fn exercise_lineage_fences<S: LineageFenceStore>(store: &Faulting<S>, expiry: u64) {
    let acquire_before = fence_request("lineage-acquire-before", expiry);
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.acquire(&acquire_before));
    assert_eq!(
        store
            .query(&scoped_action("lineage-acquire-before"))
            .unwrap_or_else(|error| panic!("query lineage fence: {error}")),
        None
    );
    let fence_before = store
        .acquire(&acquire_before)
        .unwrap_or_else(|error| panic!("retry lineage acquire: {error}"));

    let acquire_after = fence_request("lineage-acquire-after", expiry);
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.acquire(&acquire_after));
    let fence_after = store
        .query(&scoped_action("lineage-acquire-after"))
        .unwrap_or_else(|error| panic!("query committed lineage fence: {error}"))
        .unwrap_or_else(|| panic!("committed lineage fence missing"));
    assert_eq!(
        store
            .acquire(&acquire_after)
            .unwrap_or_else(|error| panic!("recover lineage acquire: {error}")),
        fence_after
    );

    let release_before = LineageFenceRelease {
        tenant_id: tenant(),
        action_id: fence_before.action_id.clone(),
        fencing_token: fence_before.fencing_token,
        scheduler_lease_owner_id: fence_before.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: fence_before.scheduler_fencing_token,
    };
    store.arm(FaultMoment::BeforeWrite);
    require_unavailable(store.release(&release_before));
    assert!(store
        .query(&scoped_action("lineage-acquire-before"))
        .unwrap_or_else(|error| panic!("query fence before release retry: {error}"))
        .is_some());
    store
        .release(&release_before)
        .unwrap_or_else(|error| panic!("retry lineage release: {error}"));

    let release_after = LineageFenceRelease {
        tenant_id: tenant(),
        action_id: fence_after.action_id.clone(),
        fencing_token: fence_after.fencing_token,
        scheduler_lease_owner_id: fence_after.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: fence_after.scheduler_fencing_token,
    };
    store.arm(FaultMoment::AfterCommit);
    require_unavailable(store.release(&release_after));
    assert_eq!(
        store
            .query(&scoped_action("lineage-acquire-after"))
            .unwrap_or_else(|error| panic!("query released lineage fence: {error}")),
        None
    );
    store
        .release(&release_after)
        .unwrap_or_else(|error| panic!("recover lineage release: {error}"));
}

fn has_compartment(label: &InformationLabel, value: &str) -> bool {
    label.compartments().is_some_and(|compartments| {
        compartments.contains(
            &Compartment::new(value).unwrap_or_else(|error| panic!("compartment: {error}")),
        )
    })
}

fn exercise_cross_key_flow_contract<S: FlowStateStore>(store: &S) {
    let first = FlowStateKey {
        tenant_id: tenant(),
        principal_id: PrincipalId::new("scope-principal")
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        lineage_id: LineageId::new("scope-lineage-a")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        session_id: SessionId::new("scope-shared-session")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        isolation_epoch_id: IsolationEpochId::new("scope-epoch")
            .unwrap_or_else(|error| panic!("isolation epoch id: {error}")),
    };
    store
        .join(&FlowJoinRequest {
            key: first.clone(),
            principal_join: label("scope-principal-secret"),
            lineage_join: label("scope-lineage-secret"),
            session_join: label("scope-session-secret"),
            transition_id: record("scope-first-join"),
        })
        .unwrap_or_else(|error| panic!("join first scope: {error}"));

    let sibling = FlowStateKey {
        lineage_id: LineageId::new("scope-lineage-b")
            .unwrap_or_else(|error| panic!("lineage id: {error}")),
        ..first.clone()
    };
    let sibling_snapshot = store
        .join(&FlowJoinRequest {
            key: sibling.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("scope-sibling-join"),
        })
        .unwrap_or_else(|error| panic!("join sibling scope: {error}"));
    assert!(has_compartment(
        &sibling_snapshot.principal_label,
        "scope-principal-secret"
    ));
    assert!(has_compartment(
        &sibling_snapshot.session_label,
        "scope-session-secret"
    ));

    let fence = store
        .acquire_egress_fence(&EgressFenceRequest {
            key: sibling.clone(),
            request_id: RequestId::new("scope-sibling-fence")
                .unwrap_or_else(|error| panic!("request id: {error}")),
            request_hash: Digest32::new([21; 32]),
            expected_context_generation: sibling_snapshot.context_generation,
            expires_at_unix_ms: now_unix_ms().saturating_add(120_000),
        })
        .unwrap_or_else(|error| panic!("acquire sibling fence: {error}"));
    store
        .join(&FlowJoinRequest {
            key: first.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: label("scope-session-late"),
            transition_id: record("scope-session-advance"),
        })
        .unwrap_or_else(|error| panic!("advance shared session: {error}"));
    require_error_kind(store.validate_egress_fence(&fence), PortErrorKind::Conflict);
    let refreshed = store
        .load(&sibling)
        .unwrap_or_else(|error| panic!("load sibling scope: {error}"))
        .unwrap_or_else(|| panic!("sibling scope missing"));
    assert!(has_compartment(
        &refreshed.session_label,
        "scope-session-late"
    ));

    let new_session = FlowStateKey {
        session_id: SessionId::new("scope-new-session")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        ..sibling
    };
    let inherited = store
        .load(&new_session)
        .unwrap_or_else(|error| panic!("load inherited session: {error}"))
        .unwrap_or_else(|| panic!("inherited session missing"));
    assert!(has_compartment(
        &inherited.principal_label,
        "scope-principal-secret"
    ));
    assert!(!has_compartment(
        &inherited.session_label,
        "scope-session-secret"
    ));

    let other_principal = FlowStateKey {
        principal_id: PrincipalId::new("scope-principal-b")
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        session_id: SessionId::new("scope-other-principal-session")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        isolation_epoch_id: IsolationEpochId::new("scope-other-principal-epoch")
            .unwrap_or_else(|error| panic!("isolation epoch id: {error}")),
        ..first
    };
    let lineage_inherited = store
        .join(&FlowJoinRequest {
            key: other_principal,
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: InformationLabel::bottom(),
            transition_id: record("scope-other-principal-join"),
        })
        .unwrap_or_else(|error| panic!("join other principal: {error}"));
    assert!(has_compartment(
        &lineage_inherited.lineage_label,
        "scope-lineage-secret"
    ));
}

fn exercise_scheduler_takeover_contract<S: ResponseStore>(store: &S) {
    let clock = now_unix_ms();
    let plan = response_plan("takeover-contract-action", 0, Some(clock.saturating_sub(1)));
    assert_eq!(
        store
            .create(&plan)
            .unwrap_or_else(|error| panic!("create takeover plan: {error}")),
        CreateOutcome::Created
    );
    let first_request = SchedulerClaimRequest {
        tenant_id: tenant(),
        claim_id: record("takeover-contract-first-claim"),
        lease_owner_id: LeaseOwnerId::new("takeover-contract-first-owner")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms: clock,
        lease_expires_at_unix_ms: clock.saturating_add(200),
        max_claims: 1,
    };
    let first = store
        .claim_due(&first_request)
        .unwrap_or_else(|error| panic!("claim first lease: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("first lease missing"));
    std::thread::sleep(Duration::from_millis(250));
    let second_clock = now_unix_ms();
    let second_request = SchedulerClaimRequest {
        tenant_id: tenant(),
        claim_id: record("takeover-contract-second-claim"),
        lease_owner_id: LeaseOwnerId::new("takeover-contract-second-owner")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms: second_clock,
        lease_expires_at_unix_ms: second_clock.saturating_add(120_000),
        max_claims: 1,
    };
    let second = store
        .claim_due(&second_request)
        .unwrap_or_else(|error| panic!("claim takeover lease: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("takeover lease missing"));
    assert_eq!(second.action_id, first.action_id);
    assert!(second.fencing_token > first.fencing_token);
    require_error_kind(
        store.persist_effect(&response_effect(
            &first.action_id,
            "takeover-contract-stale-effect",
            &first.lease_owner_id,
            first.fencing_token,
        )),
        PortErrorKind::Conflict,
    );
    assert_eq!(
        store
            .persist_effect(&response_effect(
                &second.action_id,
                "takeover-contract-current-effect",
                &second.lease_owner_id,
                second.fencing_token,
            ))
            .unwrap_or_else(|error| panic!("persist current effect: {error}")),
        CreateOutcome::Created
    );
}

fn exercise_response_effect_recovery_contract<S: ResponseStore>(store: &S) {
    let clock = now_unix_ms();
    let plan = response_plan(
        "effect-recovery-contract-action",
        0,
        Some(clock.saturating_sub(1)),
    );
    assert_eq!(
        store
            .create(&plan)
            .unwrap_or_else(|error| panic!("create recovery plan: {error}")),
        CreateOutcome::Created
    );
    assert_eq!(
        store
            .load_plan(&ResponsePlanKey {
                tenant_id: plan.tenant_id.clone(),
                action_id: plan.action_id.clone(),
            })
            .unwrap_or_else(|error| panic!("load recovery plan: {error}")),
        Some(plan.clone())
    );

    let first_request = SchedulerClaimRequest {
        tenant_id: tenant(),
        claim_id: record("effect-recovery-first-claim"),
        lease_owner_id: LeaseOwnerId::new("effect-recovery-first-owner")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms: clock,
        lease_expires_at_unix_ms: clock.saturating_add(200),
        max_claims: 1,
    };
    let first = store
        .claim_due(&first_request)
        .unwrap_or_else(|error| panic!("claim first recovery lease: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("first recovery lease missing"));
    let mut intent = response_effect(
        &first.action_id,
        "effect-recovery-contract-effect",
        &first.lease_owner_id,
        first.fencing_token,
    );
    intent.generation = 0;
    intent.state = record("apply_requested");
    assert_eq!(
        store
            .persist_effect(&intent)
            .unwrap_or_else(|error| panic!("persist durable effect intent: {error}")),
        CreateOutcome::Created
    );
    let effect_key = ResponseEffectKey {
        tenant_id: intent.tenant_id.clone(),
        effect_id: intent.effect_id.clone(),
    };
    assert_eq!(
        store
            .load_effect(&effect_key)
            .unwrap_or_else(|error| panic!("load durable effect intent: {error}")),
        Some(intent.clone())
    );

    std::thread::sleep(Duration::from_millis(250));
    let second_clock = now_unix_ms();
    let second_request = SchedulerClaimRequest {
        tenant_id: tenant(),
        claim_id: record("effect-recovery-second-claim"),
        lease_owner_id: LeaseOwnerId::new("effect-recovery-second-owner")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms: second_clock,
        lease_expires_at_unix_ms: second_clock.saturating_add(120_000),
        max_claims: 1,
    };
    let second = store
        .claim_due(&second_request)
        .unwrap_or_else(|error| panic!("claim takeover recovery lease: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("takeover recovery lease missing"));
    assert!(second.fencing_token > first.fencing_token);

    let applied_body = body(br#"{"phase":"applied"}"#);
    let applied = ResponseEffectRecord {
        generation: 1,
        scheduler_lease_owner_id: second.lease_owner_id.clone(),
        scheduler_fencing_token: second.fencing_token,
        state: record("applied"),
        body_hash: digest(applied_body.as_bytes()),
        canonical_body: applied_body,
        ..intent.clone()
    };
    let stale_request = ResponseEffectCasRequest {
        record: ResponseEffectRecord {
            scheduler_lease_owner_id: first.lease_owner_id.clone(),
            scheduler_fencing_token: first.fencing_token,
            ..applied.clone()
        },
        expected_generation: 0,
        transition_id: record("effect-recovery-stale-result"),
    };
    require_error_kind(
        store.compare_and_swap_effect(&stale_request),
        PortErrorKind::Conflict,
    );

    let takeover_request = ResponseEffectCasRequest {
        record: applied.clone(),
        expected_generation: 0,
        transition_id: record("effect-recovery-current-result"),
    };
    assert_eq!(
        store
            .compare_and_swap_effect(&takeover_request)
            .unwrap_or_else(|error| panic!("persist takeover effect result: {error}")),
        applied
    );
    assert_eq!(
        store
            .compare_and_swap_effect(&takeover_request)
            .unwrap_or_else(|error| panic!("replay takeover effect result: {error}")),
        takeover_request.record
    );
    assert_eq!(
        store
            .load_effect(&effect_key)
            .unwrap_or_else(|error| panic!("load takeover effect result: {error}")),
        Some(takeover_request.record.clone())
    );
    require_error_kind(
        store.compare_and_swap_effect(&ResponseEffectCasRequest {
            record: ResponseEffectRecord {
                state: record("forged-result"),
                ..takeover_request.record.clone()
            },
            ..takeover_request
        }),
        PortErrorKind::Conflict,
    );
}

fn exercise_overlay_action_binding_contract<S: ResponseStore + ContainmentOverlayStore>(store: &S) {
    let clock = now_unix_ms();
    for value in ["binding-action-a", "binding-action-b"] {
        store
            .create(&response_plan(value, 0, Some(clock.saturating_sub(1))))
            .unwrap_or_else(|error| panic!("create binding plan: {error}"));
    }
    let claim = SchedulerClaimRequest {
        tenant_id: tenant(),
        claim_id: record("binding-contract-claim"),
        lease_owner_id: LeaseOwnerId::new("binding-contract-owner")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms: clock,
        lease_expires_at_unix_ms: clock.saturating_add(120_000),
        max_claims: 2,
    };
    let claimed = store
        .claim_due(&claim)
        .unwrap_or_else(|error| panic!("claim binding actions: {error}"));
    assert_eq!(claimed.len(), 2);
    let action_a = claimed
        .iter()
        .find(|work| work.action_id == action("binding-action-a"))
        .unwrap_or_else(|| panic!("binding action A missing"));
    let action_b = claimed
        .iter()
        .find(|work| work.action_id == action("binding-action-b"))
        .unwrap_or_else(|| panic!("binding action B missing"));
    let overlay_session = "binding-contract-session";
    let target = overlay_target(overlay_session);
    let empty = empty_overlay(target.clone());
    let apply_a = overlay_apply_request(
        &empty,
        overlay_session,
        action_a.action_id.clone(),
        effect("binding-effect-a"),
        4,
        action_a.fencing_token,
        "binding-apply-a",
    );
    let after_a = store
        .apply_contribution(&apply_a)
        .unwrap_or_else(|error| panic!("apply action A contribution: {error}"));
    let apply_b = overlay_apply_request(
        &after_a,
        overlay_session,
        action_b.action_id.clone(),
        effect("binding-effect-b"),
        7,
        action_b.fencing_token,
        "binding-apply-b",
    );
    let after_b = store
        .apply_contribution(&apply_b)
        .unwrap_or_else(|error| panic!("apply action B contribution: {error}"));
    let mut wrong_action_remove = overlay_remove_request(
        &apply_a,
        &after_b,
        overlay_session,
        action_b.fencing_token,
        "binding-wrong-remove",
    );
    wrong_action_remove.action_id = action_b.action_id.clone();
    wrong_action_remove.command.request.action_id = action_b.action_id.clone();
    require_error_kind(
        store.remove_contribution(&wrong_action_remove),
        PortErrorKind::Conflict,
    );
    assert_eq!(
        store
            .load_effective(&target)
            .unwrap_or_else(|error| panic!("load binding overlay: {error}"))
            .unwrap_or_else(|| panic!("binding overlay missing"))
            .active_contributions
            .len(),
        2
    );
}

#[test]
fn cross_key_flow_contract_holds_for_in_memory_model() {
    exercise_cross_key_flow_contract(&ModelStore::default());
}

#[test]
fn cross_key_flow_contract_holds_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("flow-contract.db"))
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    exercise_cross_key_flow_contract(&store);
}

#[test]
fn scheduler_takeover_contract_holds_for_in_memory_model() {
    exercise_scheduler_takeover_contract(&ModelStore::default());
}

#[test]
fn scheduler_takeover_contract_holds_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("scheduler-contract.db"))
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    exercise_scheduler_takeover_contract(&store);
}

#[test]
fn response_effect_recovery_contract_holds_for_in_memory_model() {
    exercise_response_effect_recovery_contract(&ModelStore::default());
}

#[test]
fn response_effect_recovery_contract_holds_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("effect-recovery.db"))
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    exercise_response_effect_recovery_contract(&store);
}

#[test]
fn overlay_action_binding_contract_holds_for_in_memory_model() {
    exercise_overlay_action_binding_contract(&ModelStore::default());
}

#[test]
fn overlay_action_binding_contract_holds_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = SqliteSecurityStateStore::open(directory.path().join("overlay-contract.db"))
        .unwrap_or_else(|error| panic!("open security store: {error}"));
    exercise_overlay_action_binding_contract(&store);
}

#[test]
fn durable_write_contracts_hold_for_in_memory_model() {
    let store = Faulting::new(ModelStore::default());
    exercise_contracts(&store);
}

#[test]
fn durable_write_contracts_hold_for_sqlite() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("security-contract.db");
    let sqlite = SqliteSecurityStateStore::open_with_isolation_epoch_verifier(
        &path,
        Arc::new(AcceptIsolationEvidence),
    )
    .unwrap_or_else(|error| panic!("open security store: {error}"));
    let store = Faulting::new(sqlite);
    exercise_contracts(&store);
}
