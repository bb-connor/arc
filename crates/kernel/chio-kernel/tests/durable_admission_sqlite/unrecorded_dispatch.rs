//! A failed durable return write terminalizes the original saga as an unknown outcome.
use super::*;

#[test]
fn sqlite_restart_terminalizes_an_unrecorded_dispatch_without_moving_funds(
) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let kernel_keypair = Keypair::generate();
    let invocations = Arc::new(AtomicU64::new(0));
    let payment_calls = Arc::new(PaymentCalls::default());

    let (operation_id, capability_id, usage_before) = {
        let authority = SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &lock_root,
            chio_test_support::clock::clock(),
        )?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = authority.tool_outcome_store();
        let budget = Arc::new(authority.budget_store());
        let mut kernel = ChioKernel::new_with_clock(
            kernel_config(kernel_keypair.clone()),
            chio_test_support::clock::clock(),
        );
        kernel.set_durable_admission_store(
            operations.clone(),
            Arc::new(FailOnceOutcomeStore {
                inner: outcomes,
                fail_record: AtomicBool::new(true),
            }),
            fence.clone(),
        )?;
        kernel.set_budget_store_handle(budget.clone());
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(payment_calls.clone()),
        }));
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(&agent.public_key(), paid_scope(), 300)?;
        let request = paid_request(&capability);
        let response = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.output.is_none());
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("injected tool outcome write failure")),
            "{:?}",
            response.reason
        );
        assert_eq!(
            response
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.pointer("/admission_operation/projected_state")),
            Some(&serde_json::json!("outcome_unknown_after_dispatch"))
        );
        assert_eq!(kernel.receipt_log().len(), 1);
        assert!(operations
            .list_recoverable(now_unix_ms()? + 120_000, 10)?
            .is_empty());
        let references = payment_calls
            .authorization_references
            .lock()
            .map_err(|_| "authorization trace lock")?;
        let [reference] = references.as_slice() else {
            return Err("expected one original authorization reference".into());
        };
        let operation = ordinary_operation::from_rail_reference(
            operations.as_ref(),
            &fence,
            &request,
            reference,
        )?;
        assert_eq!(
            operation.state(),
            AdmissionOperationState::OutcomeUnknownAfterDispatch
        );
        let journal = operations
            .load_payment_journal(operation.binding().operation_id().as_str(), &fence)?
            .ok_or_else(|| std::io::Error::other("payment journal is absent"))?;
        assert_eq!(journal.state, PaymentJournalState::Authorized);
        let usage = budget
            .get_usage(&capability.id, 0)?
            .ok_or_else(|| std::io::Error::other("budget usage is absent"))?;
        assert_eq!(usage.total_cost_exposed, 10);
        (
            operation.binding().operation_id().clone(),
            capability.id,
            usage,
        )
    };

    let authority = SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &lock_root,
        chio_test_support::clock::clock(),
    )?;
    let fence = authority.mutation_fence();
    let operations = Arc::new(authority.admission_operation_store());
    let outcomes = Arc::new(authority.tool_outcome_store());
    let budget = Arc::new(authority.budget_store());
    let mut recovered_kernel = ChioKernel::new_with_clock(
        kernel_config(kernel_keypair),
        chio_test_support::clock::clock(),
    );
    recovered_kernel.set_durable_admission_store(operations.clone(), outcomes, fence.clone())?;
    recovered_kernel.set_budget_store_handle(budget.clone());
    recovered_kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(payment_calls.clone()),
    }));
    recovered_kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));

    assert_eq!(recovered_kernel.reconcile_durable_admission_startup()?, 0);
    assert_eq!(recovered_kernel.reconcile_recoverable_admissions()?, 0);
    let retained = operations
        .load_by_operation_id(&operation_id)?
        .ok_or_else(|| std::io::Error::other("recovered operation is absent"))?;
    assert_eq!(
        retained.state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    let replay = retained
        .terminal_replay()
        .ok_or_else(|| std::io::Error::other("incident replay is absent"))?;
    let stored_replay = operations
        .load_terminal_replay(&retained.replay_key())?
        .ok_or_else(|| std::io::Error::other("stored incident replay is absent"))?;
    assert_eq!(&stored_replay, replay);
    let journal = operations
        .load_payment_journal(operation_id.as_str(), &fence)?
        .ok_or_else(|| std::io::Error::other("recovered payment journal is absent"))?;
    assert_eq!(journal.state, PaymentJournalState::Authorized);
    assert_eq!(
        budget
            .get_usage(&capability_id, 0)?
            .ok_or_else(|| std::io::Error::other("recovered budget usage is absent"))?,
        usage_before
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(payment_calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(payment_calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(payment_calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(payment_calls.refunds.load(Ordering::SeqCst), 0);
    Ok(())
}
