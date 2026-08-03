#[cfg(target_os = "linux")]
#[test]
fn recovery_outcomes_reject_either_predecessor_binding_mutation() {
    for (variant, state) in [
        ("undelivered", DeclassificationUseState::DispatchFailed),
        ("unknown", DeclassificationUseState::OutcomeUnknown),
    ] {
        for mutate_evidence_id in [true, false] {
            let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
            let path = temp.path().join(format!(
                "recovery-{variant}-{}.sqlite",
                if mutate_evidence_id {
                    "evidence-rebind"
                } else {
                    "transition-rebind"
                }
            ));
            let store = Arc::new(
                SqliteSecurityStateStore::open(&path)
                    .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
            );
            seal_live(&store);
            let consumption_receipt = test_consumption_receipt(
                "recovery-binding-consumption",
                "recovery-binding-consumption-transition",
                0,
            );
            store
                .commit_declassification_consumption_evidence(&consumption_commit(
                    consumption_receipt.clone(),
                ))
                .unwrap_or_else(|error| panic!("commit recovery fixture: {error:?}"));
            drop(store);

            let (reopened, _lifecycle_owner) = open_store_for_owner_takeover(&path);
            reopened
                .begin_declassification_reconciliation()
                .unwrap_or_else(|error| panic!("begin recovery fixture: {error:?}"));
            let predecessor_evidence_id = if mutate_evidence_id {
                OpaqueReceiptRef::new(format!("forged-{variant}-evidence"))
                    .unwrap_or_else(|error| panic!("forged evidence id: {error}"))
            } else {
                consumption_receipt.evidence_id.clone()
            };
            let predecessor_transition_id = if mutate_evidence_id {
                consumption_receipt.transition_id.clone()
            } else {
                record(&format!("forged-{variant}-transition"))
            };
            let transition_binding = match state {
                DeclassificationUseState::DispatchFailed => {
                    DeclassificationTransitionBinding::RecoveryUndeliveredConsumption {
                        tenant_id: tenant(),
                        grant_id: grant(),
                        request_hash: Digest32::new([31_u8; 32]),
                        predecessor_evidence_id,
                        predecessor_transition_id,
                    }
                }
                DeclassificationUseState::OutcomeUnknown => {
                    DeclassificationTransitionBinding::RecoveryOutcomeUnknown {
                        tenant_id: tenant(),
                        grant_id: grant(),
                        request_hash: Digest32::new([31_u8; 32]),
                        predecessor_evidence_id,
                        predecessor_transition_id,
                    }
                }
                DeclassificationUseState::ConsumedPendingDispatch
                | DeclassificationUseState::Released => {
                    panic!("recovery fixture requires a recovery terminal state")
                }
            };
            let outcome_receipt = test_outcome_receipt_for_binding(
                &transition_binding,
                20,
                consumption_receipt.evidence_id.clone(),
                state,
            );
            let Err(error) = reopened.commit_declassification_outcome_evidence(
                &DeclassificationOutcomeEvidenceCommit {
                    transition_binding,
                    outcome: DeclassificationOutcomeRequest {
                        tenant_id: tenant(),
                        grant_id: grant(),
                        request_hash: Digest32::new([31_u8; 32]),
                        expected_state: DeclassificationUseState::ConsumedPendingDispatch,
                        new_state: state,
                        transition_id: outcome_receipt.transition_id.clone(),
                    },
                    predecessor_evidence_id: consumption_receipt.evidence_id.clone(),
                    receipt: outcome_receipt,
                },
            ) else {
                panic!("recovery binding unexpectedly rebound its predecessor");
            };
            assert_eq!(error.kind(), PortErrorKind::Conflict);
            assert_eq!(
                reopened
                    .load_declassification_use(&use_query())
                    .unwrap_or_else(|error| panic!("load rejected recovery use: {error:?}"))
                    .unwrap_or_else(|| panic!("rejected recovery use missing"))
                    .state,
                DeclassificationUseState::ConsumedPendingDispatch
            );
            reopened
                .end_declassification_reconciliation()
                .unwrap_or_else(|error| panic!("end recovery fixture: {error:?}"));
        }
    }
}

#[test]
fn transaction_failure_before_commit_has_no_state_or_receipt_side_effects() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("transaction-failure.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    seal_live(&store);
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("open fault injection connection: {error}"));
    connection
        .execute_batch(
            r#"
            CREATE TRIGGER fail_declassification_receipt_outbox_insert
            BEFORE INSERT ON security_declassification_receipt_outbox
            BEGIN
                SELECT RAISE(ABORT, 'injected declassification outbox failure');
            END;
            "#,
        )
        .unwrap_or_else(|error| panic!("install outbox failure trigger: {error}"));
    let sink = Arc::new(ScriptedReceiptSink::default());
    let receipt = test_consumption_receipt(
        "declassification-consumption-transaction-failure",
        "declassification-consumption-transaction-failure-transition",
        0,
    );
    assert!(store
        .commit_declassification_consumption_evidence(&consumption_commit(receipt))
        .is_err());
    assert!(store
        .load_declassification_use(&use_query())
        .unwrap_or_else(|error| panic!("load use after failed transaction: {error:?}"))
        .is_none());
    assert!(store
        .load_pending_declassification_evidence(&pending_query(8))
        .unwrap_or_else(|error| panic!("load outbox after failed transaction: {error:?}"))
        .is_empty());
    assert!(sink.attempts().is_empty());
    assert!(sink.accepted().is_empty());
}

#[test]
fn wrong_kind_or_non_domain_digest_receipt_is_rejected_before_state_commit() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("invalid-receipt-semantics.sqlite");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
    seal_live(&store);
    let wrong_kind = test_outcome_receipt(
        "declassification-outcome-wrong-kind",
        "declassification-outcome-wrong-kind-transition",
        0,
        OpaqueReceiptRef::new("declassification-consumption-wrong-kind-predecessor")
            .unwrap_or_else(|error| panic!("wrong-kind predecessor: {error}")),
        DeclassificationUseState::DispatchFailed,
    );
    let Err(wrong_kind_error) =
        store.commit_declassification_consumption_evidence(&consumption_commit(wrong_kind))
    else {
        panic!("outcome body unexpectedly committed as consumption");
    };
    assert_eq!(wrong_kind_error.kind(), PortErrorKind::InvalidData);

    let mut wrong_digest = test_consumption_receipt(
        "declassification-consumption-wrong-digest",
        "declassification-consumption-wrong-digest-transition",
        0,
    );
    wrong_digest.body_hash = digest(wrong_digest.canonical_body.as_bytes());
    let Err(wrong_digest_error) =
        store.commit_declassification_consumption_evidence(&consumption_commit(wrong_digest))
    else {
        panic!("plain body sha unexpectedly replaced the domain-separated digest");
    };
    assert_eq!(wrong_digest_error.kind(), PortErrorKind::InvalidData);
    assert!(store
        .load_declassification_use(&use_query())
        .unwrap_or_else(|error| panic!("load use after invalid receipts: {error:?}"))
        .is_none());
}

#[test]
fn changed_body_time_or_policy_cannot_rebind_a_declassification_transition() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("canonical-rebinding.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    seal_live(&store);
    let original = test_consumption_receipt(
        "declassification-consumption-rebinding",
        "declassification-consumption-rebinding-transition",
        0,
    );
    store
        .commit_declassification_consumption_evidence(&consumption_commit(original.clone()))
        .unwrap_or_else(|error| panic!("commit original evidence: {error:?}"));
    let mut changed_body_value =
        serde_json::from_slice::<ActiveDefenseReceiptBody>(original.canonical_body.as_bytes())
            .unwrap_or_else(|error| panic!("decode original rebinding body: {error}"));
    let ActiveDefenseReceiptBody::DeclassificationConsumption(changed_consumption) =
        &mut changed_body_value
    else {
        panic!("original rebinding body is not consumption");
    };
    changed_consumption.grant_hash = digest(b"changed-grant-hash");
    let changed_body = receipt_request(changed_body_value);
    let changed_time = test_consumption_receipt(
        "declassification-consumption-rebinding",
        original.transition_id.as_str(),
        1,
    );
    let changed_policy = test_consumption_receipt_for(
        tenant(),
        grant(),
        "declassification-consumption-rebinding",
        original.transition_id.as_str(),
        0,
        "flow-policy-v2",
    );
    for (label, conflicting) in [
        ("body", changed_body),
        ("time", changed_time),
        ("policy", changed_policy),
    ] {
        let Err(error) =
            store.commit_declassification_consumption_evidence(&consumption_commit(conflicting))
        else {
            panic!("conflicting logical evidence mapping unexpectedly succeeded");
        };
        assert_eq!(error.kind(), PortErrorKind::Conflict, "changed {label}");
    }
    let pending = store
        .load_pending_declassification_evidence(&pending_query(8))
        .unwrap_or_else(|error| panic!("load original pending evidence: {error:?}"));
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].receipt, original);
}

#[test]
fn acknowledgement_is_bound_to_exact_evidence_identity() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("ack-binding.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    seal_live(&store);
    let receipt = test_consumption_receipt(
        "declassification-consumption-ack-binding",
        "declassification-consumption-ack-binding-transition",
        0,
    );
    store
        .commit_declassification_consumption_evidence(&consumption_commit(receipt.clone()))
        .unwrap_or_else(|error| panic!("commit evidence for ack test: {error:?}"));
    let exact = DeclassificationEvidenceAckRequest {
        tenant_id: tenant(),
        grant_id: grant(),
        phase: DeclassificationEvidencePhase::Consumption,
        evidence_id: receipt.evidence_id.clone(),
        body_hash: receipt.body_hash,
        transition_id: receipt.transition_id.clone(),
        durable_sink_record_hash: durable_receipt_hash(&receipt),
        verified_at_unix_ms: NOW_UNIX_MS.saturating_add(1),
    };
    let mut wrong_body_hash = exact.clone();
    wrong_body_hash.body_hash = Digest32::new([255_u8; 32]);
    let mut wrong_evidence_id = exact.clone();
    wrong_evidence_id.evidence_id = OpaqueReceiptRef::new("wrong-declassification-evidence-id")
        .unwrap_or_else(|error| panic!("wrong evidence id: {error}"));
    let mut wrong_transition_id = exact.clone();
    wrong_transition_id.transition_id = record("wrong-declassification-transition-id");
    let mut wrong_phase = exact.clone();
    wrong_phase.phase = DeclassificationEvidencePhase::Outcome;
    for (label, wrong, expected_kind) in [
        ("body hash", wrong_body_hash, PortErrorKind::Conflict),
        ("evidence id", wrong_evidence_id, PortErrorKind::Conflict),
        (
            "transition id",
            wrong_transition_id,
            PortErrorKind::Conflict,
        ),
        ("phase", wrong_phase, PortErrorKind::InvalidData),
    ] {
        let Err(error) = store.acknowledge_declassification_evidence(&wrong) else {
            panic!("wrong acknowledgement identity unexpectedly succeeded");
        };
        assert_eq!(error.kind(), expected_kind, "wrong {label}");
    }
    assert_eq!(
        store
            .load_pending_declassification_evidence(&pending_query(8))
            .unwrap_or_else(|error| panic!("load pending evidence after bad ack: {error:?}"))
            .len(),
        1
    );
    store
        .acknowledge_declassification_evidence(&exact)
        .unwrap_or_else(|error| panic!("acknowledge exact evidence: {error:?}"));
    store
        .acknowledge_declassification_evidence(&exact)
        .unwrap_or_else(|error| panic!("retry exact acknowledgement: {error:?}"));
    let mut rebound_sink_hash = exact.clone();
    rebound_sink_hash.durable_sink_record_hash = Digest32::new([253_u8; 32]);
    let Err(error) = store.acknowledge_declassification_evidence(&rebound_sink_hash) else {
        panic!("acknowledged durable sink hash unexpectedly rebound");
    };
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    assert!(store
        .load_pending_declassification_evidence(&pending_query(8))
        .unwrap_or_else(|error| panic!("load evidence after exact acknowledgement: {error:?}"))
        .is_empty());
}

#[test]
fn exact_consumption_and_outcome_commit_retries_are_idempotent() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("exact-commit-retries.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    seal_live(&store);
    let consumption_receipt = test_consumption_receipt(
        "declassification-consumption-exact-retry",
        "declassification-consumption-exact-retry-transition",
        0,
    );
    let consumption = consumption_commit(consumption_receipt.clone());
    assert_eq!(
        store
            .commit_declassification_consumption_evidence(&consumption)
            .unwrap_or_else(|error| panic!("commit consumption evidence: {error:?}")),
        DeclassificationConsume::Consumed
    );
    assert_eq!(
        store
            .commit_declassification_consumption_evidence(&consumption)
            .unwrap_or_else(|error| panic!("retry consumption evidence: {error:?}")),
        DeclassificationConsume::AlreadyConsumed {
            request_hash: consumption.consumption.request_hash,
            state: DeclassificationUseState::ConsumedPendingDispatch,
        }
    );

    let outcome_receipt = test_outcome_receipt(
        "declassification-outcome-exact-retry",
        "declassification-outcome-exact-retry-transition",
        1,
        consumption_receipt.evidence_id.clone(),
        DeclassificationUseState::Released,
    );
    let outcome = outcome_commit(
        DeclassificationUseState::Released,
        outcome_receipt.clone(),
        consumption_receipt.evidence_id.clone(),
    );
    store
        .commit_declassification_outcome_evidence(&outcome)
        .unwrap_or_else(|error| panic!("commit outcome evidence: {error:?}"));
    store
        .commit_declassification_outcome_evidence(&outcome)
        .unwrap_or_else(|error| panic!("retry outcome evidence: {error:?}"));

    let pending = store
        .load_pending_declassification_evidence(&pending_query(8))
        .unwrap_or_else(|error| panic!("load exact retry evidence: {error:?}"));
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].receipt, consumption_receipt);
    assert_eq!(pending[1].receipt, outcome_receipt);
    assert_eq!(
        store
            .load_declassification_use(&use_query())
            .unwrap_or_else(|error| panic!("load exact retry use: {error:?}"))
            .unwrap_or_else(|| panic!("exact retry use missing"))
            .state,
        DeclassificationUseState::Released
    );
}

#[test]
fn retention_is_fixed_from_grant_expiry_and_overflow_or_rebinding_fails_closed() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("fixed-declassification-retention.sqlite");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
    seal_live(&store);
    let receipt = test_consumption_receipt(
        "declassification-consumption-retention",
        "declassification-consumption-retention-transition",
        0,
    );
    let commit = consumption_commit(receipt);
    store
        .commit_declassification_consumption_evidence(&commit)
        .unwrap_or_else(|error| panic!("commit retained consumption: {error:?}"));
    let persisted = store
        .load_declassification_use(&use_query())
        .unwrap_or_else(|error| panic!("load retained consumption: {error:?}"))
        .unwrap_or_else(|| panic!("retained consumption missing"));
    assert_eq!(
        persisted.retain_until_unix_ms,
        declassification_retain_until_unix_ms(commit.consumption.grant_expires_at_unix_ms)
            .unwrap_or_else(|error| panic!("derive fixed retention: {error:?}"))
    );

    let mut rebound = commit.clone();
    rebound.consumption.grant_expires_at_unix_ms = rebound
        .consumption
        .grant_expires_at_unix_ms
        .saturating_add(1);
    let Err(error) = store.commit_declassification_consumption_evidence(&rebound) else {
        panic!("grant expiry unexpectedly rebound after consumption");
    };
    assert_eq!(error.kind(), PortErrorKind::Conflict);

    let overflow_tenant = tenant_named("tenant-retention-overflow");
    let overflow_grant = grant_named("grant-retention-overflow");
    let overflow_receipt = test_consumption_receipt_for(
        overflow_tenant.clone(),
        overflow_grant.clone(),
        "declassification-consumption-retention-overflow",
        "declassification-consumption-retention-overflow-transition",
        0,
        "flow-policy-v1",
    );
    let mut overflow = consumption_commit_for(
        overflow_tenant.clone(),
        overflow_grant.clone(),
        overflow_receipt,
    );
    overflow.consumption.grant_expires_at_unix_ms = u64::MAX;
    let Err(error) = store.commit_declassification_consumption_evidence(&overflow) else {
        panic!("retention overflow unexpectedly mutated state");
    };
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    assert!(store
        .load_declassification_use(&DeclassificationUseQuery {
            tenant_id: overflow_tenant,
            grant_id: overflow_grant,
        })
        .unwrap_or_else(|error| panic!("load overflow use: {error:?}"))
        .is_none());
}

#[test]
fn compaction_revalidates_use_and_evidence_bindings_inside_its_transaction() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("compaction-binding-revalidation.sqlite");
    let sink = Arc::new(ScriptedReceiptSink::default());
    let (resolver, store, context, request) = resolver(&path, sink);
    let mut recorder = resolver
        .commit_dispatch(
            &FlowPreInvocationInput {
                security_context: &context,
                request: &request,
            },
            record("compaction-original-dispatch"),
        )
        .unwrap_or_else(|error| panic!("commit compaction fixture dispatch: {error}"))
        .unwrap_or_else(|| panic!("compaction fixture recorder missing"));
    recorder
        .record(DeclassificationDispatchOutcome::Released)
        .unwrap_or_else(|error| panic!("record compaction fixture release: {error}"));

    let readiness_cursor = store
        .declassification_evidence_readiness_cursor()
        .unwrap_or_else(|error| panic!("load compaction readiness cursor: {error:?}"));
    let retain_until_unix_ms = store
        .load_declassification_use(&use_query())
        .unwrap_or_else(|error| panic!("load retained terminal use: {error:?}"))
        .unwrap_or_else(|| panic!("retained terminal use missing"))
        .retain_until_unix_ms;
    let before_retention = store
        .load_declassification_compaction_candidates(&DeclassificationCompactionQuery {
            readiness_cursor: readiness_cursor.clone(),
            now_unix_ms: retain_until_unix_ms.saturating_sub(1),
            after_tenant_id: None,
            after_grant_id: None,
            max_records: 1,
        })
        .unwrap_or_else(|error| panic!("load pre-retention candidates: {error:?}"));
    assert!(before_retention.is_empty());
    let mut candidates = store
        .load_declassification_compaction_candidates(&DeclassificationCompactionQuery {
            readiness_cursor: readiness_cursor.clone(),
            now_unix_ms: retain_until_unix_ms,
            after_tenant_id: None,
            after_grant_id: None,
            max_records: 1,
        })
        .unwrap_or_else(|error| panic!("load compaction candidate: {error:?}"));
    assert_eq!(candidates.len(), 1);
    let candidate = candidates
        .pop()
        .unwrap_or_else(|| panic!("compaction candidate missing"));
    let compaction_request = DeclassificationCompactionRequest {
        readiness_cursor,
        tenant_id: candidate.use_record.tenant_id.clone(),
        grant_id: candidate.use_record.grant_id.clone(),
        request_hash: candidate.use_record.request_hash,
        terminal_state: candidate.use_record.state,
        consumption_evidence_id: candidate.consumption.receipt.evidence_id.clone(),
        consumption_body_hash: candidate.consumption.receipt.body_hash,
        consumption_transition_id: candidate.consumption.receipt.transition_id.clone(),
        consumption_occurred_at_unix_ms: candidate.consumption.receipt.occurred_at_unix_ms,
        consumption_sink_record_hash: candidate
            .consumption
            .durable_sink_record_hash
            .unwrap_or_else(|| panic!("consumption exact-sink hash missing")),
        outcome_evidence_id: candidate.outcome.receipt.evidence_id.clone(),
        outcome_body_hash: candidate.outcome.receipt.body_hash,
        outcome_transition_id: candidate.outcome.receipt.transition_id.clone(),
        outcome_occurred_at_unix_ms: candidate.outcome.receipt.occurred_at_unix_ms,
        outcome_sink_record_hash: candidate
            .outcome
            .durable_sink_record_hash
            .unwrap_or_else(|| panic!("outcome exact-sink hash missing")),
        policy_hash: policy().policy_hash,
        compacted_at_unix_ms: candidate.use_record.retain_until_unix_ms,
    };

    let rebound_binding = DeclassificationTransitionBinding::Released {
        tenant_id: candidate.use_record.tenant_id,
        grant_id: candidate.use_record.grant_id,
        request_hash: candidate.use_record.request_hash,
        request_id: RequestId::new("compaction-rebound-request")
            .unwrap_or_else(|error| panic!("compaction rebound request: {error}")),
        dispatch_commitment_id: record("compaction-rebound-dispatch"),
    };
    let rebound_binding = chio_core::canonical::canonical_json_bytes(&rebound_binding)
        .unwrap_or_else(|error| panic!("canonical rebound binding: {error}"));
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("open compaction mutation connection: {error}"));
    connection
        .execute_batch("DROP TRIGGER security_declassification_use_immutable;")
        .unwrap_or_else(|error| panic!("drop compaction mutation guard: {error}"));
    let changed = connection
        .execute(
            "UPDATE security_declassification_uses SET outcome_binding = ?1
             WHERE tenant_id = ?2 AND grant_id = ?3",
            params![
                rebound_binding,
                compaction_request.tenant_id.as_str(),
                compaction_request.grant_id.as_str(),
            ],
        )
        .unwrap_or_else(|error| panic!("mutate compaction use binding: {error}"));
    assert_eq!(changed, 1);
    connection
        .execute_batch(
            r#"
            CREATE TRIGGER IF NOT EXISTS security_declassification_use_immutable
            BEFORE UPDATE ON security_declassification_uses
            WHEN NEW.tenant_id != OLD.tenant_id
              OR NEW.grant_id != OLD.grant_id
              OR NEW.request_hash != OLD.request_hash
              OR NEW.consumed_at != OLD.consumed_at
              OR NEW.grant_expires_at != OLD.grant_expires_at
              OR NEW.retain_until != OLD.retain_until
              OR NEW.consumption_binding != OLD.consumption_binding
              OR OLD.state != 'consumed_pending_dispatch'
              OR NEW.state NOT IN ('released', 'dispatch_failed', 'outcome_unknown')
              OR OLD.transition_id IS NOT NULL
              OR NEW.transition_id IS NULL
              OR OLD.outcome_binding IS NOT NULL
              OR NEW.outcome_binding IS NULL
            BEGIN
                SELECT RAISE(ABORT, 'declassification use mapping is immutable');
            END;
            "#,
        )
        .unwrap_or_else(|error| panic!("restore compaction mutation guard: {error}"));
    drop(connection);

    let Err(error) = store.compact_declassification_evidence(&compaction_request) else {
        panic!("compaction unexpectedly accepted rebound use-to-evidence bindings");
    };
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("inspect rejected compaction: {error}"));
    let tombstones: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_declassification_tombstones",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count rejected compaction tombstones: {error}"));
    assert_eq!(tombstones, 0);
}

#[test]
fn successful_compaction_rejects_fresh_request_id_replay_of_the_same_grant() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("post-compaction-grant-replay.sqlite");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
    seal_live(&store);

    let consumption_receipt = test_consumption_receipt(
        "post-compaction-consumption",
        "post-compaction-consumption-transition",
        0,
    );
    let consumption = consumption_commit(consumption_receipt.clone());
    assert_eq!(
        store
            .commit_declassification_consumption_evidence(&consumption)
            .unwrap_or_else(|error| panic!("commit compacted consumption: {error:?}")),
        DeclassificationConsume::Consumed
    );
    let outcome_receipt = test_outcome_receipt(
        "post-compaction-outcome",
        "post-compaction-outcome-transition",
        1,
        consumption_receipt.evidence_id.clone(),
        DeclassificationUseState::Released,
    );
    store
        .commit_declassification_outcome_evidence(&outcome_commit(
            DeclassificationUseState::Released,
            outcome_receipt.clone(),
            consumption_receipt.evidence_id.clone(),
        ))
        .unwrap_or_else(|error| panic!("commit compacted outcome: {error:?}"));
    for (phase, receipt) in [
        (
            DeclassificationEvidencePhase::Consumption,
            &consumption_receipt,
        ),
        (DeclassificationEvidencePhase::Outcome, &outcome_receipt),
    ] {
        store
            .acknowledge_declassification_evidence(&DeclassificationEvidenceAckRequest {
                tenant_id: tenant(),
                grant_id: grant(),
                phase,
                evidence_id: receipt.evidence_id.clone(),
                body_hash: receipt.body_hash,
                transition_id: receipt.transition_id.clone(),
                durable_sink_record_hash: durable_receipt_hash(receipt),
                verified_at_unix_ms: receipt.occurred_at_unix_ms.saturating_add(1),
            })
            .unwrap_or_else(|error| panic!("acknowledge compacted evidence: {error:?}"));
    }

    let readiness_cursor = store
        .declassification_evidence_readiness_cursor()
        .unwrap_or_else(|error| panic!("load compaction readiness cursor: {error:?}"));
    let mut candidates = store
        .load_declassification_compaction_candidates(&DeclassificationCompactionQuery {
            readiness_cursor: readiness_cursor.clone(),
            now_unix_ms: 8_000_000_000,
            after_tenant_id: None,
            after_grant_id: None,
            max_records: 1,
        })
        .unwrap_or_else(|error| panic!("load compaction candidate: {error:?}"));
    let candidate = candidates
        .pop()
        .unwrap_or_else(|| panic!("compaction candidate missing"));
    assert!(candidates.is_empty());
    let compaction = DeclassificationCompactionRequest {
        readiness_cursor,
        tenant_id: candidate.use_record.tenant_id.clone(),
        grant_id: candidate.use_record.grant_id.clone(),
        request_hash: candidate.use_record.request_hash,
        terminal_state: candidate.use_record.state,
        consumption_evidence_id: candidate.consumption.receipt.evidence_id.clone(),
        consumption_body_hash: candidate.consumption.receipt.body_hash,
        consumption_transition_id: candidate.consumption.receipt.transition_id.clone(),
        consumption_occurred_at_unix_ms: candidate.consumption.receipt.occurred_at_unix_ms,
        consumption_sink_record_hash: candidate
            .consumption
            .durable_sink_record_hash
            .unwrap_or_else(|| panic!("consumption exact-sink hash missing")),
        outcome_evidence_id: candidate.outcome.receipt.evidence_id.clone(),
        outcome_body_hash: candidate.outcome.receipt.body_hash,
        outcome_transition_id: candidate.outcome.receipt.transition_id.clone(),
        outcome_occurred_at_unix_ms: candidate.outcome.receipt.occurred_at_unix_ms,
        outcome_sink_record_hash: candidate
            .outcome
            .durable_sink_record_hash
            .unwrap_or_else(|| panic!("outcome exact-sink hash missing")),
        policy_hash: policy().policy_hash,
        compacted_at_unix_ms: candidate.use_record.retain_until_unix_ms,
    };
    store
        .compact_declassification_evidence(&compaction)
        .unwrap_or_else(|error| panic!("compact acknowledged evidence: {error:?}"));
    assert!(store
        .load_declassification_use(&use_query())
        .unwrap_or_else(|error| panic!("load compacted use: {error:?}"))
        .is_none());

    let replay_binding = DeclassificationTransitionBinding::Consumption {
        tenant_id: tenant(),
        grant_id: grant(),
        request_hash: consumption.consumption.request_hash,
        request_id: RequestId::new("post-compaction-fresh-request")
            .unwrap_or_else(|error| panic!("fresh replay request id: {error}")),
    };
    let replay_transition_id = derive_declassification_transition_id(&replay_binding)
        .unwrap_or_else(|error| panic!("derive replay transition id: {error}"));
    let replay_event_id = derive_declassification_event_id(&replay_binding)
        .unwrap_or_else(|error| panic!("derive replay event id: {error}"));
    let replay_occurred_at_unix_ms = NOW_UNIX_MS.saturating_add(2);
    let replay_receipt = receipt_request(ActiveDefenseReceiptBody::DeclassificationConsumption(
        DeclassificationConsumptionReceiptBody {
            header: ActiveDefenseReceiptHeader::new(
                replay_occurred_at_unix_ms,
                tenant(),
                replay_transition_id,
                Vec::new(),
            )
            .unwrap_or_else(|error| panic!("replay receipt header: {error}")),
            policy: policy(),
            grant_id: grant(),
            grant_hash: digest(b"post-compaction-replay-grant"),
            request_hash: consumption.consumption.request_hash,
            event_id: replay_event_id,
            state: DeclassificationUseState::ConsumedPendingDispatch,
        },
    ));
    let replay = DeclassificationConsumptionEvidenceCommit {
        transition_binding: replay_binding,
        consumption: DeclassificationConsumeRequest {
            tenant_id: tenant(),
            grant_id: grant(),
            request_hash: consumption.consumption.request_hash,
            consumed_at_unix_ms: replay_occurred_at_unix_ms,
            grant_expires_at_unix_ms: replay_occurred_at_unix_ms.saturating_add(60_000),
        },
        receipt: replay_receipt,
    };
    let Err(error) = store.commit_declassification_consumption_evidence(&replay) else {
        panic!("fresh request id replay resurrected a compacted grant");
    };
    assert_eq!(error.kind(), PortErrorKind::Conflict);

    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("inspect compacted replay state: {error}"));
    let replay_binding = chio_core::canonical::canonical_json_bytes(&replay.transition_binding)
        .unwrap_or_else(|error| panic!("canonical replay binding: {error}"));
    let Err(error) = connection.execute(
        r#"
        INSERT INTO security_declassification_uses (
            grant_id, tenant_id, request_hash, state, consumed_at,
            grant_expires_at, retain_until, consumption_binding
        ) VALUES (?1, ?2, ?3, 'consumed_pending_dispatch', ?4, ?5, ?6, ?7)
        "#,
        params![
            replay.consumption.grant_id.as_str(),
            replay.consumption.tenant_id.as_str(),
            consumption.consumption.request_hash.as_bytes().as_slice(),
            sqlite_integer(replay_occurred_at_unix_ms, "consumed_at"),
            sqlite_integer(
                replay_occurred_at_unix_ms.saturating_add(60_000),
                "grant_expires_at",
            ),
            sqlite_integer(
                replay_occurred_at_unix_ms.saturating_add(120_000),
                "retain_until",
            ),
            replay_binding,
        ],
    ) else {
        panic!("canonical tombstone trigger accepted a raw grant replay");
    };
    assert!(error
        .to_string()
        .contains("declassification tombstone replay is rejected"));
    let counts: (i64, i64) = connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM security_declassification_uses),
                (SELECT COUNT(*) FROM security_declassification_tombstones)
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|error| panic!("count compacted replay state: {error}"));
    assert_eq!(counts, (0, 1));
}

#[test]
fn readiness_rejects_simultaneous_live_use_and_tombstone_rows() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("simultaneous-live-tombstone.sqlite");
    let sink = Arc::new(ScriptedReceiptSink::default());
    let (resolver, store, context, request) = resolver(&path, sink);
    let mut recorder = resolver
        .commit_dispatch(
            &FlowPreInvocationInput {
                security_context: &context,
                request: &request,
            },
            record("simultaneous-live-tombstone-dispatch"),
        )
        .unwrap_or_else(|error| panic!("commit simultaneous-row dispatch: {error}"))
        .unwrap_or_else(|| panic!("simultaneous-row outcome recorder missing"));
    recorder
        .record(DeclassificationDispatchOutcome::Released)
        .unwrap_or_else(|error| panic!("record simultaneous-row release: {error}"));

    let readiness_cursor = store
        .declassification_evidence_readiness_cursor()
        .unwrap_or_else(|error| panic!("load simultaneous-row readiness cursor: {error:?}"));
    let mut candidates = store
        .load_declassification_compaction_candidates(&DeclassificationCompactionQuery {
            readiness_cursor,
            now_unix_ms: 8_000_000_000,
            after_tenant_id: None,
            after_grant_id: None,
            max_records: 1,
        })
        .unwrap_or_else(|error| panic!("load simultaneous-row candidate: {error:?}"));
    let candidate = candidates
        .pop()
        .unwrap_or_else(|| panic!("simultaneous-row candidate missing"));
    let consumption_sink_record_hash = candidate
        .consumption
        .durable_sink_record_hash
        .unwrap_or_else(|| panic!("consumption exact-sink hash missing"));
    let outcome_sink_record_hash = candidate
        .outcome
        .durable_sink_record_hash
        .unwrap_or_else(|| panic!("outcome exact-sink hash missing"));
    let policy_hash = policy().policy_hash;
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("open simultaneous-row mutation connection: {error}"));
    let inserted = connection
        .execute(
            r#"
            INSERT INTO security_declassification_tombstones (
                tenant_id, grant_id, request_hash, terminal_state,
                consumption_evidence_id, consumption_body_hash,
                consumption_transition_id, consumption_occurred_at,
                consumption_sink_record_hash, outcome_evidence_id,
                outcome_body_hash, outcome_transition_id, outcome_occurred_at,
                outcome_sink_record_hash, policy_hash, compacted_at
            ) VALUES (
                ?1, ?2, ?3, 'released', ?4, ?5, ?6, ?7, ?8,
                ?9, ?10, ?11, ?12, ?13, ?14, ?15
            )
            "#,
            params![
                candidate.use_record.tenant_id.as_str(),
                candidate.use_record.grant_id.as_str(),
                candidate.use_record.request_hash.as_bytes().as_slice(),
                candidate.consumption.receipt.evidence_id.as_str(),
                candidate
                    .consumption
                    .receipt
                    .body_hash
                    .as_bytes()
                    .as_slice(),
                candidate.consumption.receipt.transition_id.as_str(),
                sqlite_integer(
                    candidate.consumption.receipt.occurred_at_unix_ms,
                    "consumption_occurred_at",
                ),
                consumption_sink_record_hash.as_bytes().as_slice(),
                candidate.outcome.receipt.evidence_id.as_str(),
                candidate.outcome.receipt.body_hash.as_bytes().as_slice(),
                candidate.outcome.receipt.transition_id.as_str(),
                sqlite_integer(
                    candidate.outcome.receipt.occurred_at_unix_ms,
                    "outcome_occurred_at",
                ),
                outcome_sink_record_hash.as_bytes().as_slice(),
                policy_hash.as_bytes().as_slice(),
                sqlite_integer(candidate.use_record.retain_until_unix_ms, "compacted_at",),
            ],
        )
        .unwrap_or_else(|error| panic!("seed simultaneous live and tombstone rows: {error}"));
    assert_eq!(inserted, 1);
    let overlap: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM security_declassification_uses AS use_record
            INNER JOIN security_declassification_tombstones AS tombstone
              ON tombstone.tenant_id = use_record.tenant_id
             AND tombstone.grant_id = use_record.grant_id
            "#,
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count simultaneous rows: {error}"));
    assert_eq!(overlap, 1);
    let Err(error) = store.ensure_declassification_evidence_ready() else {
        panic!("simultaneous live use and tombstone rows passed readiness");
    };
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn outcome_cannot_rebind_the_persisted_consumption_grant_hash() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("outcome-grant-hash-rebinding.sqlite");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
    seal_live(&store);
    let consumption = test_consumption_receipt(
        "declassification-consumption-grant-hash",
        "declassification-consumption-grant-hash-transition",
        0,
    );
    store
        .commit_declassification_consumption_evidence(&consumption_commit(consumption.clone()))
        .unwrap_or_else(|error| panic!("commit grant-hash consumption: {error:?}"));
    let outcome = test_outcome_receipt(
        "declassification-outcome-grant-hash",
        "declassification-outcome-grant-hash-transition",
        1,
        consumption.evidence_id.clone(),
        DeclassificationUseState::Released,
    );
    let body =
        serde_json::from_slice::<ActiveDefenseReceiptBody>(outcome.canonical_body.as_bytes())
            .unwrap_or_else(|error| panic!("decode outcome body: {error}"));
    let ActiveDefenseReceiptBody::DeclassificationOutcome(mut body) = body else {
        panic!("expected declassification outcome body");
    };
    body.grant_hash = Digest32::new([201_u8; 32]);
    let conflicting = receipt_request(ActiveDefenseReceiptBody::DeclassificationOutcome(body));
    let Err(error) = store.commit_declassification_outcome_evidence(&outcome_commit(
        DeclassificationUseState::Released,
        conflicting,
        consumption.evidence_id,
    )) else {
        panic!("outcome grant hash unexpectedly rebound");
    };
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    assert_eq!(
        store
            .load_declassification_use(&use_query())
            .unwrap_or_else(|error| panic!("load use after grant-hash conflict: {error:?}"))
            .unwrap_or_else(|| panic!("use missing after grant-hash conflict"))
            .state,
        DeclassificationUseState::ConsumedPendingDispatch
    );
}

#[test]
fn outcome_policy_must_equal_the_consumption_policy() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("outcome-policy-rebinding.sqlite");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
    seal_live(&store);
    let consumption = test_consumption_receipt(
        "declassification-consumption-policy-binding",
        "declassification-consumption-policy-binding-transition",
        0,
    );
    store
        .commit_declassification_consumption_evidence(&consumption_commit(consumption.clone()))
        .unwrap_or_else(|error| panic!("commit policy-bound consumption: {error:?}"));
    let outcome = test_outcome_receipt(
        "declassification-outcome-policy-binding",
        "declassification-outcome-policy-binding-transition",
        1,
        consumption.evidence_id.clone(),
        DeclassificationUseState::Released,
    );
    let body =
        serde_json::from_slice::<ActiveDefenseReceiptBody>(outcome.canonical_body.as_bytes())
            .unwrap_or_else(|error| panic!("decode policy-bound outcome: {error}"));
    let ActiveDefenseReceiptBody::DeclassificationOutcome(mut body) = body else {
        panic!("expected policy-bound outcome body");
    };
    body.policy = policy_with_version("flow-policy-v2");
    let conflicting = receipt_request(ActiveDefenseReceiptBody::DeclassificationOutcome(body));
    let Err(error) = store.commit_declassification_outcome_evidence(&outcome_commit(
        DeclassificationUseState::Released,
        conflicting,
        consumption.evidence_id,
    )) else {
        panic!("outcome policy unexpectedly rebound");
    };
    assert_eq!(error.kind(), PortErrorKind::Conflict);
}

#[test]
fn outcome_cannot_precede_its_consumption_time() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("outcome-time-regression.sqlite");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
    seal_live(&store);
    let consumption = test_consumption_receipt(
        "declassification-consumption-time-regression",
        "declassification-consumption-time-regression-transition",
        1,
    );
    store
        .commit_declassification_consumption_evidence(&consumption_commit(consumption.clone()))
        .unwrap_or_else(|error| panic!("commit later consumption: {error:?}"));
    let outcome = test_outcome_receipt(
        "declassification-outcome-time-regression",
        "declassification-outcome-time-regression-transition",
        0,
        consumption.evidence_id.clone(),
        DeclassificationUseState::Released,
    );
    let Err(error) = store.commit_declassification_outcome_evidence(&outcome_commit(
        DeclassificationUseState::Released,
        outcome,
        consumption.evidence_id,
    )) else {
        panic!("outcome time unexpectedly preceded consumption");
    };
    assert_eq!(error.kind(), PortErrorKind::InvalidData);
    assert_eq!(
        store
            .load_declassification_use(&use_query())
            .unwrap_or_else(|error| panic!("load use after time regression: {error:?}"))
            .unwrap_or_else(|| panic!("use missing after time regression"))
            .state,
        DeclassificationUseState::ConsumedPendingDispatch
    );
}

#[test]
fn outcome_is_never_sent_before_its_unacknowledged_consumption() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("outcome-predecessor-order.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    seal_live(&store);
    let consumption = test_consumption_receipt(
        "declassification-consumption-predecessor-order",
        "declassification-consumption-predecessor-order-transition",
        0,
    );
    store
        .commit_declassification_consumption_evidence(&consumption_commit(consumption.clone()))
        .unwrap_or_else(|error| panic!("commit ordered consumption: {error:?}"));
    let outcome = test_outcome_receipt(
        "declassification-outcome-predecessor-order",
        "declassification-outcome-predecessor-order-transition",
        1,
        consumption.evidence_id.clone(),
        DeclassificationUseState::Released,
    );
    store
        .commit_declassification_outcome_evidence(&outcome_commit(
            DeclassificationUseState::Released,
            outcome.clone(),
            consumption.evidence_id.clone(),
        ))
        .unwrap_or_else(|error| panic!("commit ordered outcome: {error:?}"));

    let sink = Arc::new(ScriptedReceiptSink::fail_attempts([1]));
    let drainer = DeclassificationReceiptOutboxDrainer::new_with_clock(
        store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
        sink.clone(),
        Arc::new(SequenceClock::new(vec![
            NOW_UNIX_MS,
            NOW_UNIX_MS.saturating_add(1_000),
            NOW_UNIX_MS.saturating_add(1_001),
        ])),
    )
    .unwrap_or_else(|error| panic!("construct ordered drainer: {error:?}"));
    let deferred = drainer
        .drain_once(8)
        .unwrap_or_else(|error| panic!("defer unavailable receipt: {error:?}"));
    assert_eq!(
        (
            deferred.appended,
            deferred.acknowledged,
            deferred.deferred,
            deferred.remaining,
        ),
        (0, 0, 1, 2)
    );
    assert_eq!(sink.attempts(), vec![consumption.clone()]);
    assert_eq!(
        store
            .load_pending_declassification_evidence(&pending_query(8))
            .unwrap_or_else(|error| panic!("load blocked outcome evidence: {error:?}"))
            .len(),
        2
    );

    sink.allow_all();
    let report = drainer
        .drain_once(8)
        .unwrap_or_else(|error| panic!("recover ordered evidence: {error:?}"));
    assert_eq!(
        (report.appended, report.acknowledged, report.remaining),
        (1, 1, 1)
    );
    let outcome_report = drainer
        .drain_once(8)
        .unwrap_or_else(|error| panic!("drain ordered outcome: {error:?}"));
    assert_eq!(
        (
            outcome_report.appended,
            outcome_report.acknowledged,
            outcome_report.remaining,
        ),
        (1, 1, 0)
    );
    assert_eq!(sink.accepted(), vec![consumption, outcome]);
}

#[test]
fn drainer_does_not_acknowledge_a_sink_response_for_the_wrong_evidence_id() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("wrong-sink-evidence-id.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    seal_live(&store);
    let receipt = test_consumption_receipt(
        "declassification-consumption-wrong-sink-id",
        "declassification-consumption-wrong-sink-id-transition",
        0,
    );
    store
        .commit_declassification_consumption_evidence(&consumption_commit(receipt.clone()))
        .unwrap_or_else(|error| panic!("commit wrong-id evidence: {error:?}"));
    let sink = Arc::new(ScriptedReceiptSink::returning_evidence_id(
        OpaqueReceiptRef::new("different-declassification-evidence")
            .unwrap_or_else(|error| panic!("wrong returned evidence id: {error}")),
    ));
    let drainer = DeclassificationReceiptOutboxDrainer::new(
        store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
        sink.clone(),
    )
    .unwrap_or_else(|error| panic!("construct wrong-id drainer: {error:?}"));

    assert!(drainer.drain_once(8).is_err());
    assert_eq!(sink.attempts(), vec![receipt.clone()]);
    assert_eq!(sink.accepted(), vec![receipt.clone()]);
    assert_eq!(
        store
            .load_pending_declassification_evidence(&pending_query(8))
            .unwrap_or_else(|error| panic!("load evidence after wrong sink id: {error:?}"))[0]
            .receipt,
        receipt
    );
}

#[test]
fn drainer_rejects_append_success_without_exact_durable_readback() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("missing-exact-sink-readback.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    seal_live(&store);
    let receipt = test_consumption_receipt(
        "declassification-consumption-missing-readback",
        "declassification-consumption-missing-readback-transition",
        0,
    );
    store
        .commit_declassification_consumption_evidence(&consumption_commit(receipt.clone()))
        .unwrap_or_else(|error| panic!("commit missing-readback evidence: {error:?}"));
    let drainer = DeclassificationReceiptOutboxDrainer::new(
        store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
        Arc::new(AppendWithoutExactReadback),
    )
    .unwrap_or_else(|error| panic!("construct missing-readback drainer: {error:?}"));
    let Err(error) = drainer.drain_once(1) else {
        panic!("append without durable exact readback unexpectedly succeeded");
    };
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    let pending = store
        .load_declassification_evidence(
            &chio_security_types::ports::DeclassificationEvidenceQuery {
                tenant_id: tenant(),
                grant_id: grant(),
                phase: DeclassificationEvidencePhase::Consumption,
            },
        )
        .unwrap_or_else(|error| panic!("load missing-readback evidence: {error:?}"))
        .unwrap_or_else(|| panic!("missing-readback evidence missing"));
    assert!(!pending.acknowledged);
}

#[test]
fn pending_evidence_queries_reject_zero_and_oversized_batches() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("pending-batch-bounds.sqlite");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}")),
    );
    let drainer = DeclassificationReceiptOutboxDrainer::new(
        store.clone() as Arc<dyn DeclassificationEvidenceCommitStore>,
        Arc::new(ScriptedReceiptSink::default()),
    )
    .unwrap_or_else(|error| panic!("construct bounded drainer: {error:?}"));

    for max_records in [0, MAX_DECLASSIFICATION_EVIDENCE_BATCH.saturating_add(1)] {
        let Err(global_error) =
            store.load_pending_declassification_evidence_batch(u64::MAX, max_records)
        else {
            panic!("invalid global pending batch unexpectedly succeeded");
        };
        assert_eq!(global_error.kind(), PortErrorKind::InvalidData);
        let Err(scoped_error) =
            store.load_pending_declassification_evidence(&pending_query(max_records))
        else {
            panic!("invalid scoped pending batch unexpectedly succeeded");
        };
        assert_eq!(scoped_error.kind(), PortErrorKind::InvalidData);
        let Err(drain_error) = drainer.drain_once(max_records) else {
            panic!("invalid drain batch unexpectedly succeeded");
        };
        assert_eq!(drain_error.kind(), PortErrorKind::InvalidData);
    }
}

#[test]
fn global_pending_batch_round_robins_due_records_across_tenants() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("global-pending-order.sqlite");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
    seal_live(&store);
    let cases = [
        ("tenant-b", "grant-b", "evidence-b", "transition-b"),
        ("tenant-a", "grant-z", "evidence-a-z", "transition-a-z"),
        ("tenant-a", "grant-a", "evidence-a-a", "transition-a-a"),
    ];
    for (tenant_id, grant_id, evidence_id, transition_id) in cases {
        let tenant_id = tenant_named(tenant_id);
        let grant_id = grant_named(grant_id);
        let receipt = test_consumption_receipt_for(
            tenant_id.clone(),
            grant_id.clone(),
            evidence_id,
            transition_id,
            0,
            "flow-policy-v1",
        );
        store
            .commit_declassification_consumption_evidence(&consumption_commit_for(
                tenant_id, grant_id, receipt,
            ))
            .unwrap_or_else(|error| panic!("commit global pending evidence: {error:?}"));
    }

    let pending = store
        .load_pending_declassification_evidence_batch(u64::MAX, 8)
        .unwrap_or_else(|error| panic!("load global pending evidence: {error:?}"));
    let order = pending
        .iter()
        .map(|evidence| {
            (
                evidence.tenant_id.as_str(),
                evidence.grant_id.as_str(),
                evidence.phase,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        order,
        vec![
            (
                "tenant-a",
                "grant-a",
                DeclassificationEvidencePhase::Consumption
            ),
            (
                "tenant-b",
                "grant-b",
                DeclassificationEvidencePhase::Consumption
            ),
            (
                "tenant-a",
                "grant-z",
                DeclassificationEvidencePhase::Consumption
            ),
        ]
    );
}

#[test]
fn evidence_identity_reservations_cannot_preempt_another_tenant() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("global-evidence-id.sqlite");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
    seal_live(&store);
    let first_tenant = tenant_named("tenant-global-a");
    let second_tenant = tenant_named("tenant-global-b");
    let first_grant = grant_named("grant-global-a");
    let second_grant = grant_named("grant-global-b");
    let first = test_consumption_receipt_for(
        first_tenant.clone(),
        first_grant.clone(),
        "global-declassification-event-a",
        "global-evidence-transition-a",
        0,
        "flow-policy-v1",
    );
    store
        .commit_declassification_consumption_evidence(&consumption_commit_for(
            first_tenant.clone(),
            first_grant.clone(),
            first,
        ))
        .unwrap_or_else(|error| panic!("commit first global evidence id: {error:?}"));
    let conflicting = test_consumption_receipt_for(
        second_tenant.clone(),
        second_grant.clone(),
        "global-declassification-event-b",
        "global-evidence-transition-b",
        0,
        "flow-policy-v1",
    );
    let conflicting_evidence_id = conflicting.evidence_id.clone();
    let conflicting_transition_id = conflicting.transition_id.clone();
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("open global identity injection connection: {error}"));
    connection
        .execute(
            r#"
            INSERT INTO security_declassification_evidence_identity (
                evidence_id, transition_id, tenant_id, grant_id, phase, body_hash
            ) VALUES (?1, ?2, ?3, ?4, 'consumption', ?5)
            "#,
            rusqlite::params![
                conflicting.evidence_id.as_str(),
                conflicting.transition_id.as_str(),
                first_tenant.as_str(),
                first_grant.as_str(),
                conflicting.body_hash.as_bytes().as_slice(),
            ],
        )
        .unwrap_or_else(|error| panic!("seed global identity conflict: {error}"));
    store
        .commit_declassification_consumption_evidence(&consumption_commit_for(
            second_tenant.clone(),
            second_grant.clone(),
            conflicting,
        ))
        .unwrap_or_else(|error| panic!("commit tenant-scoped evidence identity: {error:?}"));
    assert!(store
        .load_declassification_use(&DeclassificationUseQuery {
            tenant_id: second_tenant,
            grant_id: second_grant,
        })
        .unwrap_or_else(|load_error| panic!("load tenant-scoped use: {load_error:?}"))
        .is_some());
    let duplicate_identity_count: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM security_declassification_evidence_identity
            WHERE evidence_id = ?1 AND transition_id = ?2
            "#,
            rusqlite::params![
                conflicting_evidence_id.as_str(),
                conflicting_transition_id.as_str(),
            ],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("count tenant-scoped identities: {error}"));
    assert_eq!(duplicate_identity_count, 2);
}

#[test]
fn populated_legacy_evidence_keys_migrate_losslessly_and_reopen() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp
        .path()
        .join("legacy-declassification-tenant-keys.sqlite");
    let receipt = test_consumption_receipt(
        "legacy-declassification-consumption",
        "legacy-declassification-transition",
        0,
    );
    {
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
        seal_live(&store);
        store
            .commit_declassification_consumption_evidence(&consumption_commit(receipt.clone()))
            .unwrap_or_else(|error| panic!("commit legacy migration evidence: {error:?}"));
    }
    rewrite_declassification_evidence_keys_as_legacy(&path);
    {
        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("inspect legacy schema: {error}"));
        assert_eq!(
            table_primary_key_columns(&connection, "security_declassification_evidence_identity"),
            ["evidence_id"]
        );
    }

    for attempt in 0..2 {
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open migrated store attempt {attempt}: {error:?}"));
        store
            .ensure_declassification_evidence_ready()
            .unwrap_or_else(|error| panic!("migrated readiness attempt {attempt}: {error:?}"));
        let loaded = store
            .load_declassification_evidence(
                &chio_security_types::ports::DeclassificationEvidenceQuery {
                    tenant_id: tenant(),
                    grant_id: grant(),
                    phase: DeclassificationEvidencePhase::Consumption,
                },
            )
            .unwrap_or_else(|error| panic!("load migrated evidence attempt {attempt}: {error:?}"))
            .unwrap_or_else(|| panic!("migrated evidence missing on attempt {attempt}"));
        assert_eq!(loaded.receipt, receipt);
    }
    let connection =
        Connection::open(&path).unwrap_or_else(|error| panic!("inspect migrated schema: {error}"));
    assert_eq!(
        table_primary_key_columns(&connection, "security_declassification_evidence_identity"),
        ["tenant_id", "evidence_id"]
    );
}

#[test]
fn corrupt_legacy_evidence_tenant_rejects_without_partial_migration() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp
        .path()
        .join("corrupt-legacy-declassification-tenant.sqlite");
    let receipt = test_consumption_receipt(
        "corrupt-legacy-declassification-consumption",
        "corrupt-legacy-declassification-transition",
        0,
    );
    {
        let store = SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
        seal_live(&store);
        store
            .commit_declassification_consumption_evidence(&consumption_commit(receipt))
            .unwrap_or_else(|error| panic!("commit corrupt migration evidence: {error:?}"));
    }
    rewrite_declassification_evidence_keys_as_legacy(&path);
    {
        let connection = Connection::open(&path)
            .unwrap_or_else(|error| panic!("open legacy corruption connection: {error}"));
        connection
            .execute(
                r#"
                UPDATE security_declassification_evidence_identity
                SET tenant_id = 'tenant-cross-boundary'
                "#,
                [],
            )
            .unwrap_or_else(|error| panic!("corrupt legacy identity tenant: {error}"));
    }
    let error = match SqliteSecurityStateStore::open(&path) {
        Ok(_) => panic!("corrupt legacy tenant binding unexpectedly migrated"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);

    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("inspect rejected legacy migration: {error}"));
    assert_eq!(
        table_primary_key_columns(&connection, "security_declassification_evidence_identity"),
        ["evidence_id"]
    );
    let preserved_counts = (
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_evidence_identity",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("count preserved identities: {error}")),
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_declassification_receipt_outbox",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("count preserved outbox rows: {error}")),
        connection
            .query_row(
                r#"
                SELECT COUNT(*) FROM sqlite_master
                WHERE name LIKE 'security_declassification_%_tenant_migration'
                "#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|error| panic!("count rolled-back staging tables: {error}")),
    );
    assert_eq!(preserved_counts, (1, 1, 0));
}

#[test]
fn readiness_rejects_a_comment_spoofed_weakened_trigger() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("comment-spoofed-trigger.sqlite");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("open schema tamper connection: {error}"));
    connection
        .execute_batch(
            r#"
            DROP TRIGGER security_declassification_use_delete_rejected;
            CREATE TRIGGER security_declassification_use_delete_rejected
            BEFORE DELETE ON security_declassification_uses
            WHEN 0
            BEGIN
                SELECT RAISE(ABORT, 'declassification use deletion is rejected');
                /* WHEN (SELECT compaction_active FROM security_declassification_lifecycle
                   WHERE singleton = 1) != 1 */
            END;
            "#,
        )
        .unwrap_or_else(|error| panic!("install comment-spoofed trigger: {error}"));
    let Err(error) = store.ensure_declassification_evidence_ready() else {
        panic!("comment-spoofed weakened trigger unexpectedly passed readiness");
    };
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn readiness_rejects_an_arbitrary_named_trigger_on_a_protected_table() {
    let temp = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = temp.path().join("arbitrary-named-trigger.sqlite");
    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open security state store: {error:?}"));
    let connection = Connection::open(&path)
        .unwrap_or_else(|error| panic!("open schema tamper connection: {error}"));
    connection
        .execute_batch(
            r#"
            CREATE TRIGGER forge_acknowledgement
            AFTER INSERT ON security_declassification_receipt_outbox
            BEGIN
                UPDATE security_declassification_receipt_outbox
                SET acknowledged = 1,
                    acknowledged_at = NEW.occurred_at,
                    durable_sink_record_hash = zeroblob(32)
                WHERE tenant_id = NEW.tenant_id
                  AND grant_id = NEW.grant_id
                  AND phase_ordinal = NEW.phase_ordinal;
            END;
            "#,
        )
        .unwrap_or_else(|error| panic!("install arbitrary-named trigger: {error}"));
    let Err(error) = store.ensure_declassification_evidence_ready() else {
        panic!("arbitrary-named protected-table trigger unexpectedly passed readiness");
    };
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}
