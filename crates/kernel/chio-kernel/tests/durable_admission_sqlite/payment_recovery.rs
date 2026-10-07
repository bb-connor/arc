use super::*;

#[path = "payment_recovery/prepay_restart.rs"]
mod prepay_restart;
#[path = "payment_recovery/pricing_restart.rs"]
mod pricing_restart;

struct RefuseAfterPrepayment(Arc<PaymentCalls>);

impl chio_kernel::post_invocation::PostInvocationHook for RefuseAfterPrepayment {
    fn name(&self) -> &str {
        "sqlite-refuse-after-original-prepayment"
    }

    fn inspect(
        &self,
        _: &chio_kernel::post_invocation::PostInvocationContext<'_>,
        _: &serde_json::Value,
    ) -> chio_kernel::post_invocation::PostInvocationVerdict {
        chio_kernel::post_invocation::PostInvocationVerdict::Allow
    }

    fn durable_identity(
        &self,
    ) -> Result<Option<chio_kernel::post_invocation::PostInvocationHookIdentity>, String> {
        if self.0.authorizations.load(Ordering::SeqCst) != 0 {
            return Err("refused after original prepayment".into());
        }
        chio_kernel::post_invocation::PostInvocationHookIdentity::from_canonical_config(
            self.name(),
            "1",
            "chio.sqlite-tests.payment-refund",
            &(),
        )
        .map(Some)
    }
}

fn provision() -> Result<(tempfile::TempDir, std::path::PathBuf, std::path::PathBuf), Box<dyn Error>>
{
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let locks = temp.path().join("locks");
    create_private_directory(&locks)?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    Ok((temp, database, locks))
}

#[test]
fn sqlite_review_payment_prepaid_refusal_persists_confirmed_refund() -> Result<(), Box<dyn Error>> {
    let (_temp, database, locks) = provision()?;
    let authority = SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &locks,
        chio_test_support::clock::clock(),
    )?;
    let operations = Arc::new(authority.admission_operation_store());
    let budget = Arc::new(authority.budget_store());
    let mut kernel = ChioKernel::new_with_clock(
        kernel_config(Keypair::generate()),
        chio_test_support::clock::clock(),
    );
    kernel.set_durable_admission_store(
        operations,
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.set_budget_store_handle(budget);
    let calls = Arc::new(PaymentCalls::default());
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.set_payment_adapter(Box::new(PrepaidFinalPaymentAdapter {
        calls: calls.clone(),
    }));
    kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));
    kernel.add_post_invocation_hook(Box::new(RefuseAfterPrepayment(calls.clone())));
    let agent = Keypair::generate();
    let capability = kernel.issue_capability(&agent.public_key(), paid_scope(), 300)?;
    let mut request = paid_request(&capability);
    request.request_id = "sqlite-review-prepaid-refusal".into();
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.verify_signature()?);
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(calls.refunds.load(Ordering::SeqCst), 1);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    // A second read has no effect and the physical authority remains valid.
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
    Ok(())
}

#[test]
fn sqlite_review_payment_missing_original_adapter_isolates_other_requests(
) -> Result<(), Box<dyn Error>> {
    let (_temp, database, locks) = provision()?;
    let keypair = Keypair::generate();
    let paid_invocations = Arc::new(AtomicU64::new(0));
    let calls = Arc::new(PaymentCalls::default());
    let operation_id = {
        let authority = SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &locks,
            chio_test_support::clock::clock(),
        )?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let mut kernel = ChioKernel::new_with_clock(
            kernel_config(keypair.clone()),
            chio_test_support::clock::clock(),
        );
        kernel.set_durable_admission_store(
            operations.clone(),
            Arc::new(authority.tool_outcome_store()),
            fence.clone(),
        )?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(calls.clone()),
        }));
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: paid_invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(&agent.public_key(), paid_scope(), 300)?;
        calls.fail_next_capture.store(true, Ordering::SeqCst);
        let request = paid_request(&capability);
        let error = kernel
            .evaluate_tool_call_blocking(&request)
            .err()
            .ok_or("original capture must be interrupted")?;
        ordinary_operation::assert_interrupted_payment(&error, "injected capture interruption")?;
        let references = calls
            .authorization_references
            .lock()
            .map_err(|_| "authorization trace lock")?;
        let [reference] = references.as_slice() else {
            return Err("expected one original authorization reference".into());
        };
        let original = ordinary_operation::from_rail_reference(
            operations.as_ref(),
            &fence,
            &request,
            reference,
        )?;
        assert_eq!(original.state(), AdmissionOperationState::Finalizing);
        original.binding().operation_id().clone()
    };
    let authority = SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &locks,
        chio_test_support::clock::clock(),
    )?;
    let fence = authority.mutation_fence();
    let operations = Arc::new(authority.admission_operation_store());
    let mut recovered =
        ChioKernel::new_with_clock(kernel_config(keypair), chio_test_support::clock::clock());
    recovered.set_durable_admission_store(
        operations.clone(),
        Arc::new(authority.tool_outcome_store()),
        fence.clone(),
    )?;
    recovered.set_budget_store_handle(Arc::new(authority.budget_store()));
    let healthy_invocations = Arc::new(AtomicU64::new(0));
    recovered.register_tool_server(Box::new(MutationServer {
        invocations: healthy_invocations.clone(),
    }));
    assert_eq!(recovered.reconcile_durable_admission_startup()?, 0);
    let status = operations
        .load_recovery_status(
            &operation_id,
            &fence,
            chio_test_support::clock::clock().unix_millis()?.get(),
        )?
        .ok_or("quarantined original operation")?;
    assert!(status.quarantined);
    assert_eq!(
        status.deferral.failure_kind,
        chio_kernel::admission_operation::AdmissionRecoveryFailureKind::ParticipantUnavailable
    );
    let original = operations
        .load_by_operation_id(&operation_id)?
        .ok_or("original operation")?;
    assert_eq!(original.state(), AdmissionOperationState::Finalizing);
    let journal = operations
        .load_payment_journal(operation_id.as_str(), &fence)?
        .ok_or("original pending journal")?;
    assert_eq!(journal.state, PaymentJournalState::Settling);
    assert_eq!(calls.refunds.load(Ordering::SeqCst), 0);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 0);
    let agent = Keypair::generate();
    let capability = recovered.issue_capability(&agent.public_key(), scope(), 300)?;
    let mut healthy = request(&capability);
    healthy.request_id = "healthy-after-quarantined-payment".into();
    assert_eq!(
        recovered.evaluate_tool_call_blocking(&healthy)?.verdict,
        Verdict::Allow
    );
    assert_eq!(healthy_invocations.load(Ordering::SeqCst), 1);
    assert_eq!(paid_invocations.load(Ordering::SeqCst), 1);
    assert_eq!(recovered.reconcile_durable_admission_startup()?, 0);
    Ok(())
}
