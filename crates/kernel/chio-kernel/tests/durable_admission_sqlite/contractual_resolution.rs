use super::*;
use chio_kernel::payment::*;

#[test]
fn capture_waiver_requires_original_terms_and_keeps_positive_budget() -> Result<(), Box<dyn Error>>
{
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let locks = temp.path().join("locks");
    create_private_directory(&locks)?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    let receiver = Keypair::generate();
    let buyer = Keypair::generate();
    let observer = Keypair::generate();
    let calls = Arc::new(PaymentCalls::default());
    calls.fail_next_capture.store(true, Ordering::SeqCst);
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let operations = Arc::new(authority.admission_operation_store());
    let fence = authority.mutation_fence();
    let mut kernel = ChioKernel::new(kernel_config(receiver.clone()));
    kernel.require_durable_request_retention();
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(calls.clone()),
    }));
    kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: Arc::new(AtomicU64::new(0)),
    }));
    kernel.set_durable_admission_store(
        operations.clone(),
        Arc::new(authority.tool_outcome_store()),
        fence.clone(),
    )?;
    let cap = kernel.issue_capability(&buyer.public_key(), paid_scope(), 300)?;
    let mut request = paid_request(&cap);
    let policy = ContractualCaptureWaiverPolicyV1 {
        receiver_key: receiver.public_key(),
        counterparty_key: buyer.public_key(),
        observation_key: observer.public_key(),
        rail: "sqlite-test-reversible".into(),
        currency: "USD".into(),
    };
    let at = now_unix_ms()?;
    let terms = ContractualCaptureWaiverTermsV1 {
        schema: CONTRACTUAL_CAPTURE_WAIVER_SCHEMA.into(),
        policy_digest: capture_waiver_digest(&policy)?,
        contract_context_digest: "a".repeat(64),
        capability_digest: capture_waiver_digest(&cap)?,
        request_id: request.request_id.clone(),
        issued_at_unix_ms: at,
        expires_at_unix_ms: at + 600000,
    };
    let terms = SignedContractualCaptureWaiverTermsV1::sign(terms, &receiver, &buyer)?;
    request.arguments[CAPTURE_WAIVER_TERMS_ARGUMENT] =
        serde_json::json!(capture_waiver_digest(&terms)?);
    assert!(kernel.evaluate_tool_call_blocking(&request).is_err());
    let pending = operations.list_recoverable(now_unix_ms()? + 120000, 10)?;
    let operation_id = pending[0].binding().operation_id().clone();
    let id = operation_id.as_str();
    let source = operations.capture_waiver_source(id, &fence)?;
    let original = source.journal.clone();
    assert!(original
        .apply_transition(&PaymentJournalTransition::BeginRelease {
            authority: PaymentReleaseAuthorityBinding {
                kind: PaymentReleaseAuthorityKind::ContractualZeroCharge,
                operation_id: id.into(),
                operation_version: 1,
                evidence_id: "release".into(),
                evidence_digest: "b".repeat(64)
            }
        })
        .is_err());
    let observation = SignedCaptureWaiverObservationV1::sign(
        CaptureWaiverObservationV1 {
            terms_digest: capture_waiver_digest(&terms)?,
            operation_id: id.into(),
            journal_digest: capture_waiver_digest(&original)?,
            raw_output_digest: source.raw_output_digest.clone(),
            contract_context_digest: "a".repeat(64),
            agreement_digest: "a".repeat(64),
            allocation_id: "allocation-1".into(),
            refund_reference: "refund-1".into(),
            evidence_digest: "b".repeat(64),
            observed_at_unix_ms: now_unix_ms()?,
        },
        &observer,
    )?;
    let resolution = ContractualCaptureWaiverRequestV1 { terms, observation };
    assert!(operations
        .begin_capture_waiver(&policy, &resolution, &fence, now_unix_ms()?)
        .is_err());
    // Even an expired coordinator claim does not prove its rail callback stopped.
    assert!(operations
        .begin_capture_waiver(&policy, &resolution, &fence, at + 120000)
        .err()
        .ok_or("expired-owner waiver accepted")?
        .to_string()
        .contains("handoff"));
    drop(kernel);
    drop(operations);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let operations = Arc::new(authority.admission_operation_store());
    let fence = authority.mutation_fence();
    let mut paid_source = source.clone();
    paid_source.journal =
        original.apply_transition(&PaymentJournalTransition::SettlementCompleted {
            transaction_id: "paid-capture".into(),
        })?;
    let mut paid_waiver = resolution.clone();
    paid_waiver.observation.body.journal_digest = capture_waiver_digest(&paid_source.journal)?;
    paid_waiver.observation =
        SignedCaptureWaiverObservationV1::sign(paid_waiver.observation.body, &observer)?;
    assert!(paid_waiver
        .qualify(&policy, &paid_source, now_unix_ms()?)
        .is_err());
    let mut prepaid_source = source.clone();
    prepaid_source.journal.rail_mode = PaymentRailMode::PrepaidFinal;
    prepaid_source.journal.state = PaymentJournalState::Settled;
    prepaid_source.journal.settle_action = None;
    prepaid_source.journal.settle_amount_units = None;
    prepaid_source.journal.validate()?;
    let mut prepaid_waiver = resolution.clone();
    prepaid_waiver.observation.body.journal_digest =
        capture_waiver_digest(&prepaid_source.journal)?;
    prepaid_waiver.observation =
        SignedCaptureWaiverObservationV1::sign(prepaid_waiver.observation.body, &observer)?;
    assert!(prepaid_waiver
        .qualify(&policy, &prepaid_source, now_unix_ms()?)
        .is_err());
    let mut zero_source = source.clone();
    zero_source.journal.settle_amount_units = Some(0);
    assert!(resolution
        .qualify(&policy, &zero_source, now_unix_ms()?)
        .is_err());
    let mut forged = resolution.clone();
    forged.observation.body.refund_reference = "forged".into();
    assert!(operations
        .begin_capture_waiver(&policy, &forged, &fence, now_unix_ms()?)
        .is_err());
    for field in [
        "termsDigest",
        "journalDigest",
        "rawOutputDigest",
        "contractContextDigest",
    ] {
        let mut wrong = resolution.clone();
        let mut body = serde_json::to_value(&wrong.observation.body)?;
        body[field] = serde_json::json!("c".repeat(64));
        wrong.observation =
            SignedCaptureWaiverObservationV1::sign(serde_json::from_value(body)?, &observer)?;
        assert!(
            operations
                .begin_capture_waiver(&policy, &wrong, &fence, now_unix_ms()?)
                .is_err(),
            "accepted altered {field}"
        );
    }
    let mut wrong_policy = policy.clone();
    wrong_policy.observation_key = buyer.public_key();
    assert!(operations
        .begin_capture_waiver(&wrong_policy, &resolution, &fence, now_unix_ms()?)
        .is_err());
    let mut wrong = resolution.clone();
    wrong.terms.body.contract_context_digest = "c".repeat(64);
    wrong.terms = SignedContractualCaptureWaiverTermsV1::sign(wrong.terms.body, &receiver, &buyer)?;
    assert!(operations
        .begin_capture_waiver(&policy, &wrong, &fence, now_unix_ms()?)
        .is_err());
    assert!(operations
        .begin_capture_waiver(&policy, &resolution, &fence, at - 1)
        .is_err());
    assert!(operations
        .begin_capture_waiver(&policy, &resolution, &fence, at + 600000)
        .is_err());
    let mut stale = fence.clone();
    stale.owner_epoch += 1;
    assert!(operations
        .begin_capture_waiver(&policy, &resolution, &stale, now_unix_ms()?)
        .is_err());
    {
        let expires = resolution.terms.body.expires_at_unix_ms;
        let _expired_clock = chio_kernel::scope_fixed_runtime_for_current_thread(
            (expires + 1000) / 1000,
            std::iter::empty(),
        );
        let expired = operations
            .begin_capture_waiver(&policy, &resolution, &fence, expires - 1000)
            .err()
            .ok_or("backdated decision revived expired waiver")?;
        assert!(
            expired
                .to_string()
                .contains("outside its original time window"),
            "{expired}"
        );
    }
    // Two independently valid signed successor intents race at the same owner.
    // Exactly one may win; the loser cannot append or reconcile budget again.
    let mut competing = resolution.clone();
    competing.observation.body.refund_reference = "competing-refund".into();
    competing.observation =
        SignedCaptureWaiverObservationV1::sign(competing.observation.body, &observer)?;
    let barrier = std::sync::Barrier::new(3);
    let race_now = now_unix_ms()?;
    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            operations.begin_capture_waiver(&policy, &resolution, &fence, race_now)
        });
        let second = scope.spawn(|| {
            barrier.wait();
            operations.begin_capture_waiver(&policy, &competing, &fence, race_now)
        });
        barrier.wait();
        (first.join(), second.join())
    });
    let (accepted, resolution) = match (
        first.map_err(|_| "first waiver worker panicked")?,
        second.map_err(|_| "second waiver worker panicked")?,
    ) {
        (Ok(accepted), Err(_)) => (accepted, resolution),
        (Err(_), Ok(accepted)) => (accepted, competing),
        _ => return Err("conflicting waiver race did not have exactly one winner".into()),
    };
    assert!(!accepted.is_complete());
    let pending_journal = operations
        .load_payment_journal(id, &fence)?
        .ok_or("pending journal missing")?;
    assert_eq!(pending_journal.state, PaymentJournalState::Resolving);
    assert!(pending_journal
        .apply_transition(&PaymentJournalTransition::SettlementCompleted {
            transaction_id: "counterfeit-capture".into()
        })
        .is_err());
    let db = rusqlite::Connection::open(&database)?;
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM capture_waiver_records", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM authority_global_commits WHERE mutation_kind='capture_waiver'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    let commit_count = || {
        db.query_row("SELECT COUNT(*) FROM authority_global_commits", [], |r| {
            r.get::<_, i64>(0)
        })
    };
    let before = commit_count()?;
    let anchor = std::fs::read(locks.join(format!("{}.lock", fence.store_uuid)))?;
    operations.begin_capture_waiver(&policy, &resolution, &fence, now_unix_ms()?)?;
    assert_eq!(commit_count()?, before);
    assert_eq!(
        std::fs::read(locks.join(format!("{}.lock", fence.store_uuid)))?,
        anchor
    );
    let mut conflict = resolution.clone();
    conflict.observation.body.refund_reference = "another-refund".into();
    conflict.observation =
        SignedCaptureWaiverObservationV1::sign(conflict.observation.body, &observer)?;
    assert!(operations
        .begin_capture_waiver(&policy, &conflict, &fence, now_unix_ms()?)
        .is_err());

    // Restart between append-only acceptance and completion.
    drop(operations);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let operations = Arc::new(authority.admission_operation_store());
    let fence = authority.mutation_fence();
    let completed = operations.complete_capture_waiver(
        id,
        &capture_waiver_digest(&resolution)?,
        &fence,
        now_unix_ms()?,
    )?;
    assert!(completed.is_complete());
    let before = commit_count()?;
    let anchor = std::fs::read(locks.join(format!("{}.lock", fence.store_uuid)))?;
    operations.complete_capture_waiver(
        id,
        &capture_waiver_digest(&resolution)?,
        &fence,
        now_unix_ms()?,
    )?;
    assert_eq!(commit_count()?, before);
    assert_eq!(
        std::fs::read(locks.join(format!("{}.lock", fence.store_uuid)))?,
        anchor
    );

    let effective = operations
        .load_payment_journal(id, &fence)?
        .ok_or("no journal")?;
    assert_eq!(effective.state, PaymentJournalState::Resolved);
    assert_eq!(effective.settle_amount_units, original.settle_amount_units);
    assert_eq!(effective.settle_action, Some(PaymentSettleAction::Capture));
    let db = rusqlite::Connection::open(&database)?;
    let (count, spend): (i64, i64) = db.query_row("SELECT COUNT(*), SUM(realized_spend_units) FROM budget_mutation_events WHERE kind='reconcile_spend'", [], |r| Ok((r.get(0)?,r.get(1)?)))?;
    assert_eq!(count, 1);
    assert_eq!(
        u64::try_from(spend)?,
        original.settle_amount_units.ok_or("no amount")?
    );
    drop(operations);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let operations = Arc::new(authority.admission_operation_store());
    let new_fence = authority.mutation_fence();
    assert!(operations.load_capture_waiver(id, &fence).is_err());
    let mut kernel = ChioKernel::new(kernel_config(receiver));
    kernel.require_durable_request_retention();
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(calls.clone()),
    }));
    kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: Arc::new(AtomicU64::new(0)),
    }));
    kernel.set_durable_admission_store(
        operations.clone(),
        Arc::new(authority.tool_outcome_store()),
        new_fence.clone(),
    )?;
    assert_eq!(kernel.reconcile_durable_admission_startup()?, 1);
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    let financial = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("financial"))
        .ok_or("financial absent")?;
    assert_eq!(financial["cost_charged"], serde_json::json!(0));
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        financial["cost_breakdown"]["payment"]["recorded_units"],
        serde_json::json!(5)
    );
    assert_eq!(financial["budget_remaining"], serde_json::json!(95));

    assert_eq!(financial["settlement_status"], serde_json::json!("failed"));
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(
        operations.capture_waiver_source(id, &new_fence)?.journal,
        original
    );
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM budget_mutation_events WHERE kind='reconcile_spend'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        1
    );
    assert!(db
        .execute("DELETE FROM capture_waiver_records", [])
        .is_err());
    assert!(db
        .execute(
            "UPDATE capture_waiver_records SET record_digest=record_digest",
            []
        )
        .is_err());
    db.execute_batch("DROP TRIGGER capture_waiver_records_immutable")?;
    db.execute(
        "UPDATE capture_waiver_records SET record_digest=? WHERE sequence=1",
        ["c".repeat(64)],
    )?;
    assert!(operations.load_capture_waiver(id, &new_fence).is_err());
    Ok(())
}

struct DelayedElicitation;
#[async_trait::async_trait]
impl ToolServerConnection for DelayedElicitation {
    fn server_id(&self) -> &str {
        "sqlite-durable-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    async fn invoke(
        &self,
        _tool: &str,
        _arguments: serde_json::Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        std::thread::sleep(std::time::Duration::from_millis(25));
        Err(KernelError::UrlElicitationsRequired {
            message: "delayed external consent".into(),
            elicitations: vec![],
        })
    }
}

#[test]
fn delayed_elicitation_terminalization_refreshes_authority_time() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let locks = temp.path().join("locks");
    create_private_directory(&locks)?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let receiver = Keypair::generate();
    let buyer = Keypair::generate();
    let operations = Arc::new(authority.admission_operation_store());
    let mut kernel = ChioKernel::new(kernel_config(receiver));
    kernel.register_tool_server(Box::new(DelayedElicitation));
    kernel.set_durable_admission_store(
        operations.clone(),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    let capability = kernel.issue_capability(&buyer.public_key(), scope(), 300)?;
    let error = kernel
        .evaluate_tool_call_blocking(&request(&capability))
        .err()
        .ok_or("expected elicitation")?;
    assert!(
        matches!(error, KernelError::UrlElicitationsRequired { .. }),
        "{error}"
    );
    let connection = rusqlite::Connection::open(&database)?;
    let state: String =
        connection.query_row("SELECT state FROM admission_operations", [], |r| r.get(0))?;
    assert_eq!(state, "outcome_unknown_after_dispatch");
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM tool_outcomes", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(kernel.reconcile_durable_admission_startup()?, 0);
    Ok(())
}
