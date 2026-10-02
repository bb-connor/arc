use super::*;
use chio_kernel::payment::*;

#[test]
fn mutual_release_recovers_without_rewriting_unknown_work() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let locks = temp.path().join("locks");
    create_private_directory(&locks)?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    let receiver = Keypair::generate();
    let buyer = Keypair::generate();
    let calls = Arc::new(PaymentCalls::default());
    let invocations = Arc::new(AtomicU64::new(0));
    let (id, cap) = {
        let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
        let operations = Arc::new(authority.admission_operation_store());
        let mut kernel = ChioKernel::new(kernel_config(receiver.clone()));
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(calls.clone()),
        }));
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));
        kernel.set_durable_admission_store(
            operations.clone(),
            Arc::new(FailOnceOutcomeStore {
                inner: authority.tool_outcome_store(),
                fail_record: AtomicBool::new(true),
            }),
            authority.mutation_fence(),
        )?;
        let cap = kernel.issue_capability(&buyer.public_key(), paid_scope(), 300)?;
        assert!(kernel
            .evaluate_tool_call_blocking(&paid_request(&cap))
            .is_err());
        let operations = operations.list_recoverable(now_unix_ms()? + 120_000, 10)?;
        assert_eq!(operations.len(), 1);
        (operations[0].binding().operation_id().clone(), cap)
    };
    let (consent, incident_bytes, original_bytes) = {
        let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
        let operations = Arc::new(authority.admission_operation_store());
        let fence = authority.mutation_fence();
        let mut kernel = ChioKernel::new(kernel_config(receiver.clone()));
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(calls.clone()),
        }));
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));
        kernel.set_durable_admission_store(
            operations.clone(),
            Arc::new(authority.tool_outcome_store()),
            fence.clone(),
        )?;
        assert_eq!(kernel.reconcile_durable_admission_startup()?, 1);
        let (operation, journal) = operations.unknown_release_source(id.as_str(), &fence)?;
        let incident = operations.export_outcome_unknown_projection(&id, &receiver)?;
        let incident_bytes = canonical_json_bytes(&incident)?;
        let original_bytes = canonical_json_bytes(&journal)?;
        let policy = UnknownPaymentReleasePolicyV1 {
            receiver_key: receiver.public_key(),
            counterparty_key: buyer.public_key(),
            rail: "sqlite-test-reversible".into(),
            currency: "USD".into(),
        };
        let at = now_unix_ms()?;
        let terms = UnknownPaymentReleaseTermsV1 {
            schema: UNKNOWN_PAYMENT_RELEASE_SCHEMA.into(),
            policy_digest: unknown_release_digest(&policy)?,
            operation_id: id.as_str().into(),
            terminal_projection_digest: operation
                .terminal_replay()
                .ok_or("no terminal")?
                .projection_digest()
                .as_str()
                .into(),
            incident,
            capability: cap.clone(),
            authorized_journal: journal.clone(),
            issued_at_unix_ms: at,
            expires_at_unix_ms: at + 60_000,
        };
        let consent =
            UnknownPaymentReleaseProposalV1::sign(terms, &receiver)?.countersign(&buyer)?;
        let adapter = ReversiblePaymentAdapter {
            calls: Some(calls.clone()),
        };
        let runtime =
            UnknownPaymentReleaseRuntime::new(operations.as_ref(), &adapter, &receiver, &fence);
        let mut wrong = consent.clone();
        wrong.counterparty_signature = wrong.proposal.receiver_signature.clone();
        assert!(runtime.resolve(&policy, &wrong, at).is_err());
        let mut wrong = consent.clone();
        wrong.proposal.body.authorized_journal.amount_units += 1;
        wrong = UnknownPaymentReleaseProposalV1::sign(wrong.proposal.body, &receiver)?
            .countersign(&buyer)?;
        assert!(runtime.resolve(&policy, &wrong, at).is_err());
        assert!(runtime.resolve(&policy, &consent, at - 1).is_err());
        assert!(runtime.resolve(&policy, &consent, at + 60_000).is_err());
        assert_eq!(calls.releases.load(Ordering::SeqCst), 0);
        calls.fail_next_release.store(true, Ordering::SeqCst);
        assert!(runtime.resolve(&policy, &consent, at).is_err());
        let pending = operations
            .load_unknown_release(id.as_str(), &fence)?
            .ok_or("no intent")?;
        assert!(!pending.is_complete());
        assert_eq!(
            operations
                .load_payment_journal(id.as_str(), &fence)?
                .ok_or("no journal")?
                .state,
            PaymentJournalState::Settling
        );
        let usage = authority
            .budget_store()
            .get_usage(&cap.id, 0)?
            .ok_or("no budget")?;
        assert_eq!(usage.total_cost_exposed, 0);
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(
            canonical_json_bytes(&operations.export_outcome_unknown_projection(&id, &receiver)?)?,
            incident_bytes
        );
        (consent, incident_bytes, original_bytes)
    };
    // A new serving lease completes the retained intent, even after its admission window.
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let operations = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let adapter = ReversiblePaymentAdapter {
        calls: Some(calls.clone()),
    };
    let runtime = UnknownPaymentReleaseRuntime::new(&operations, &adapter, &receiver, &fence);
    let at = consent.proposal.body.expires_at_unix_ms + 1;
    assert_eq!(runtime.reconcile_pending(at)?, 1);
    assert_eq!(runtime.reconcile_pending(at)?, 0);
    let receipt = runtime.resume(id.as_str(), at)?;
    verify_unknown_payment_release_receipt(&receipt, &receiver.public_key(), &buyer.public_key())?;
    let replay = runtime.resolve(receipt.body.record.policy(), &consent, at)?;
    assert_eq!(
        canonical_json_bytes(&receipt)?,
        canonical_json_bytes(&replay)?
    );
    assert_eq!(calls.releases.load(Ordering::SeqCst), 2);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        operations
            .load_payment_journal(id.as_str(), &fence)?
            .ok_or("no journal")?
            .state,
        PaymentJournalState::Settled
    );
    assert_eq!(
        canonical_json_bytes(&operations.unknown_release_source(id.as_str(), &fence)?.1)?,
        original_bytes
    );
    assert_eq!(
        canonical_json_bytes(&operations.export_outcome_unknown_projection(&id, &receiver)?)?,
        incident_bytes
    );
    let connection = rusqlite::Connection::open(&database)?;
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM unknown_payment_release_records",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        2
    );
    assert!(connection
        .execute("DELETE FROM unknown_payment_release_records", [])
        .is_err());
    assert!(connection
        .execute(
            "UPDATE unknown_payment_release_records SET record_digest=record_digest",
            []
        )
        .is_err());
    // Corrupt only this disposable fixture after bypassing its immutable trigger.
    connection.execute_batch("DROP TRIGGER unknown_payment_release_records_immutable")?;
    connection.execute(
        "UPDATE unknown_payment_release_records SET record_digest=? WHERE sequence=1",
        ["a".repeat(64)],
    )?;
    assert!(operations
        .load_unknown_release(id.as_str(), &fence)
        .is_err());
    Ok(())
}
