//! Current qualified joint-store prepay closure survives a native owner restart.
use super::*;
use chio_kernel::admission_operation::AdmissionIdentifier;
use chio_kernel::payment::PaymentAuthorizationAttempt;
#[path = "prepay_restart/fixture.rs"]
mod fixture;
use fixture::*;

#[test]
fn sqlite_review_prepay_restart_retains_exact_debit_and_original_receipt_without_another_effect(
) -> Result<(), Box<dyn Error>> {
    let at = 1_800_000_300_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let (_temp, database, locks) = provision()?;
    let keypair = Keypair::generate();
    let invocations = Arc::new(AtomicU64::new(0));
    let facts = Arc::new(PrepayFacts::default());
    let (request, operation_id, original_receipt, original_journal) = {
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
        kernel.set_payment_adapter(Box::new(ExactPrepayRail(facts.clone())));
        kernel.set_governed_approval_policy(
            "sqlite-exact-prepay-tenant".into(),
            vec![keypair.public_key()],
        )?;
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability =
            kernel.issue_capability(&agent.public_key(), scope_with_original_quote(), 300)?;
        let mut request = paid_request(&capability);
        request.request_id = "sqlite-exact-prepay-restart".into();
        attach_original_quote(&kernel, &mut request, &keypair, at / 1_000)?;
        let response = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert!(response.receipt.verify_signature()?);
        let original = operations
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
                &fence,
                at,
            )?
            .ok_or("completed original request")?
            .0;
        assert_eq!(original.state(), AdmissionOperationState::Completed);
        let operation_id = original.binding().operation_id().clone();
        let journal = operations
            .load_payment_journal(operation_id.as_str(), &fence)?
            .ok_or("original prepay journal")?;
        assert_eq!(journal.authorized_amount_units, Some(5));
        assert_eq!(journal.amount_units, 10);
        assert_eq!(
            journal.authorization_attempt,
            Some(PaymentAuthorizationAttempt::Started)
        );
        assert_eq!(journal.state, PaymentJournalState::Settled);
        assert_eq!(journal.settle_action, None);
        assert_eq!(journal.settle_amount_units, None);
        assert_eq!(journal.transaction_id, None);
        let financial = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("financial"))
            .ok_or("financial metadata")?;
        assert_eq!(
            financial
                .get("cost_charged")
                .and_then(serde_json::Value::as_u64),
            Some(5)
        );
        assert_eq!(
            facts
                .original_authorizations
                .lock()
                .map_err(|_| "prepay trace lock")?
                .as_slice(),
            &[(operation_id.as_str().to_owned(), 5, "USD".into())]
        );
        assert_eq!(facts.calls.authorizations.load(Ordering::SeqCst), 1);
        assert_eq!(facts.calls.captures.load(Ordering::SeqCst), 0);
        (
            request,
            operation_id,
            canonical_json_bytes(&response.receipt)?,
            journal,
        )
    };
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
    kernel.set_governed_approval_policy(
        "sqlite-exact-prepay-tenant".into(),
        vec![keypair.public_key()],
    )?;
    kernel.set_payment_adapter(Box::new(ExactPrepayRail(facts.clone())));
    kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));
    assert_eq!(kernel.reconcile_durable_admission_startup()?, 0);
    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(canonical_json_bytes(&replay.receipt)?, original_receipt);
    assert_eq!(
        operations.load_payment_journal(operation_id.as_str(), &fence)?,
        Some(original_journal)
    );
    assert_eq!(facts.calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(facts.calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(facts.calls.refunds.load(Ordering::SeqCst), 0);
    assert_eq!(facts.calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(
        facts
            .original_authorizations
            .lock()
            .map_err(|_| "prepay trace lock")?
            .len(),
        1
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
