//! A failed page must not starve later durable work during startup.
use super::*;

#[test]
fn startup_recovery_passes_a_full_failed_page_and_preserves_effects() -> Result<(), Box<dyn Error>>
{
    const OPERATION_COUNT: usize = 257;
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let locks = temp.path().join("locks");
    create_private_directory(&locks)?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    let kernel_keypair = Keypair::generate();
    let invocations = Arc::new(AtomicU64::new(0));
    let payment_calls = Arc::new(PaymentCalls::default());

    // Each operation reaches a real retained return through public evaluation.
    // The payment adapter interrupts finalization after the one tool effect.
    let operations_by_id = {
        let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
        let operations = Arc::new(authority.admission_operation_store());
        let mut kernel = ChioKernel::new(kernel_config(kernel_keypair.clone()));
        kernel.set_durable_admission_store(
            operations.clone(),
            Arc::new(authority.tool_outcome_store()),
            authority.mutation_fence(),
        )?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(payment_calls.clone()),
        }));
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        for index in 0..OPERATION_COUNT {
            let capability = kernel.issue_capability(&agent.public_key(), paid_scope(), 3600)?;
            let mut request = paid_request(&capability);
            request.request_id = format!("interrupted-return-{index}");
            payment_calls
                .fail_next_capture
                .store(true, Ordering::SeqCst);
            assert!(matches!(kernel.evaluate_tool_call_blocking(&request),
                Err(KernelError::DurableAdmission(ref reason))
                    if reason.contains("injected capture interruption")));
        }
        let now = now_unix_ms()? + 120_000;
        let mut pending = operations.list_recoverable(now, None, 256)?;
        assert_eq!(pending.len(), 256);
        let cursor = pending
            .last()
            .ok_or("missing recovery page")?
            .binding()
            .operation_id()
            .clone();
        pending.extend(operations.list_recoverable(now, Some(&cursor), 256)?);
        assert_eq!(pending.len(), OPERATION_COUNT);
        assert!(pending
            .iter()
            .all(|op| op.state() == AdmissionOperationState::Finalizing));
        assert!(pending
            .windows(2)
            .all(|pair| pair[0].binding().operation_id() < pair[1].binding().operation_id()));
        pending
            .into_iter()
            .map(|op| op.binding().operation_id().clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(invocations.load(Ordering::SeqCst), OPERATION_COUNT as u64);

    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let fence = authority.mutation_fence();
    let operations = Arc::new(authority.admission_operation_store());
    let refused_reads = Arc::new(Mutex::new(
        operations_by_id[..256].iter().cloned().collect(),
    ));
    let outcomes = Arc::new(InterruptibleOutcomeStore {
        inner: authority.tool_outcome_store(),
        fail_record: AtomicBool::new(false),
        refused_reads: refused_reads.clone(),
    });
    let mut kernel = ChioKernel::new(kernel_config(kernel_keypair));
    kernel.set_durable_admission_store(operations.clone(), outcomes, fence.clone())?;
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(payment_calls.clone()),
    }));
    kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));

    assert!(matches!(kernel.reconcile_durable_admission_startup(),
        Err(KernelError::DurableAdmission(ref reason))
            if reason.contains("injected retained outcome read failure")));
    let healthy_id = &operations_by_id[256];
    assert_eq!(
        operations
            .load_by_operation_id(healthy_id)?
            .ok_or("missing healthy operation")?
            .state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(
        operations
            .load_by_operation_id(&operations_by_id[0])?
            .ok_or("missing refused operation")?
            .state(),
        AdmissionOperationState::Finalizing
    );
    let captures_after_progress = payment_calls.captures.load(Ordering::SeqCst);
    // Failure must not set the startup-complete flag. Another sweep still
    // refuses, while the completed operation is neither settled nor run again.
    assert!(kernel.reconcile_durable_admission_startup().is_err());
    assert_eq!(
        payment_calls.captures.load(Ordering::SeqCst),
        captures_after_progress
    );
    assert_eq!(invocations.load(Ordering::SeqCst), OPERATION_COUNT as u64);

    refused_reads
        .lock()
        .map_err(|_| "read fault lock poisoned")?
        .clear();
    assert_eq!(kernel.reconcile_durable_admission_startup()?, 256);
    assert_eq!(kernel.reconcile_durable_admission_startup()?, 0);
    for operation_id in &operations_by_id {
        assert_eq!(
            operations
                .load_by_operation_id(operation_id)?
                .ok_or("missing completed operation")?
                .state(),
            AdmissionOperationState::Completed
        );
        assert_eq!(
            operations
                .load_payment_journal(operation_id.as_str(), &fence)?
                .ok_or("missing payment journal")?
                .state,
            PaymentJournalState::Settled
        );
    }
    assert_eq!(invocations.load(Ordering::SeqCst), OPERATION_COUNT as u64);
    Ok(())
}
