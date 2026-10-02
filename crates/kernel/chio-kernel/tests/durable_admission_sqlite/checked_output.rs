use super::*;
use chio_kernel::{Guard, GuardContext, GuardDecision, ToolServerOutput};

struct Checker(Arc<AtomicBool>);
impl Guard for Checker {
    fn name(&self) -> &str {
        "sqlite-checked-output"
    }
    fn evaluate(&self, _: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }
    fn output_rejection_is_zero_charge(&self, _: &GuardContext<'_>) -> bool {
        true
    }
    fn validate_output_before_release(
        &self,
        _: &GuardContext<'_>,
        _: &ToolServerOutput,
    ) -> Result<(), KernelError> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(KernelError::GuardDenied("bad delivered result".into()))
        }
    }
}

#[test]
fn checked_output_denial_recovers_before_and_after_release_without_becoming_a_capture(
) -> Result<(), Box<dyn Error>> {
    for interrupt_release in [false, true] {
        let temp = tempfile::tempdir()?;
        secure_directory(temp.path())?;
        let database = temp.path().join("authority.db");
        let locks = temp.path().join("locks");
        create_private_directory(&locks)?;
        SqliteAuthorityStore::provision(&database, &locks)?;
        let key = Keypair::generate();
        let invocations = Arc::new(AtomicU64::new(0));
        let calls = Arc::new(PaymentCalls::default());
        calls
            .fail_next_release
            .store(interrupt_release, Ordering::SeqCst);
        let allow = Arc::new(AtomicBool::new(false));
        let (request, original) = {
            let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
            let operations = Arc::new(authority.admission_operation_store());
            let mut kernel = ChioKernel::new(kernel_config(key.clone()));
            kernel.require_durable_request_retention();
            kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
            kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
                calls: Some(calls.clone()),
            }));
            kernel.register_tool_server(Box::new(PaidMutationServer {
                invocations: invocations.clone(),
            }));
            kernel.add_guard(Box::new(Checker(allow.clone())));
            kernel.set_durable_admission_store(
                operations.clone(),
                Arc::new(authority.tool_outcome_store()),
                authority.mutation_fence(),
            )?;
            let cap =
                kernel.issue_capability(&Keypair::generate().public_key(), paid_scope(), 300)?;
            let request = paid_request(&cap);
            let response = kernel.evaluate_tool_call_blocking(&request);
            let original = if interrupt_release {
                let error = response
                    .err()
                    .ok_or("release interruption was not reached")?;
                assert!(error.to_string().contains("injected release interruption"));
                let pending = operations.list_recoverable(now_unix_ms()? + 120_000, 10)?;
                assert_eq!(pending.len(), 1);
                assert_eq!(pending[0].state(), AdmissionOperationState::Finalizing);
                None
            } else {
                Some(response?)
            };
            let before_calls = (
                calls.captures.load(Ordering::SeqCst),
                calls.releases.load(Ordering::SeqCst),
            );
            let denied = kernel
                .export_durable_execution_evidence(&request)
                .err()
                .ok_or("denied output was exported")?;
            assert!(denied.to_string().contains("execution.verdict"), "{denied}");
            assert_eq!(
                before_calls,
                (
                    calls.captures.load(Ordering::SeqCst),
                    calls.releases.load(Ordering::SeqCst)
                )
            );
            assert_eq!(invocations.load(Ordering::SeqCst), 1);
            let connection = rusqlite::Connection::open(&database)?;
            assert_eq!(
                connection.query_row(
                    "SELECT COUNT(*) FROM tool_outcome_execution_evidence",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                0
            );
            (request, original)
        };
        // A later permissive checker must not change a durably resolved denial.
        allow.store(true, Ordering::SeqCst);
        let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
        let operations = Arc::new(authority.admission_operation_store());
        let mut kernel = ChioKernel::new(kernel_config(key));
        kernel.require_durable_request_retention();
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(calls.clone()),
        }));
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));
        kernel.add_guard(Box::new(Checker(allow)));
        kernel.set_durable_admission_store(
            operations.clone(),
            Arc::new(authority.tool_outcome_store()),
            authority.mutation_fence(),
        )?;
        kernel.reconcile_recoverable_admissions()?;
        let response = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        assert!(response.output.is_none());
        assert!(response.receipt.verify_signature()?);
        assert_eq!(
            response.receipt.content_hash,
            sha256_hex(chio_kernel::admission_operation::OUTPUT_GUARD_REJECTION_REDACTION_DOMAIN)
        );
        if let Some(original) = original {
            assert_eq!(
                canonical_json_bytes(&response.receipt)?,
                canonical_json_bytes(&original.receipt)?
            );
        }
        let replay = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(
            canonical_json_bytes(&response.receipt)?,
            canonical_json_bytes(&replay.receipt)?
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(calls.captures.load(Ordering::SeqCst), 0);
        assert_eq!(
            calls.releases.load(Ordering::SeqCst),
            if interrupt_release { 2 } else { 1 }
        );
    }
    Ok(())
}

#[test]
fn checked_output_contract_rejects_final_payment_before_authorization() -> Result<(), Box<dyn Error>>
{
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let locks = temp.path().join("locks");
    create_private_directory(&locks)?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let invocations = Arc::new(AtomicU64::new(0));
    let calls = Arc::new(PaymentCalls::default());
    let mut kernel = ChioKernel::new(kernel_config(Keypair::generate()));
    kernel.set_payment_adapter(Box::new(PrepaidFinalPaymentAdapter {
        calls: calls.clone(),
    }));
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.add_guard(Box::new(Checker(Arc::new(AtomicBool::new(false)))));
    kernel.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    let cap = kernel.issue_capability(&Keypair::generate().public_key(), paid_scope(), 300)?;
    let response = kernel.evaluate_tool_call_blocking(&paid_request(&cap))?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("reversible-hold")));
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
