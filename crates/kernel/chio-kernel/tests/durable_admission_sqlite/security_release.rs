//! Monetary settlement and security release are distinct, ordered authorities.
use super::*;
use chio_kernel::{
    SecurityDispatchOutcomeHandle, SecurityInvocationContext, SecurityInvocationContextV1,
    SecurityPreDispatchContext, SecurityPreDispatchHook, SecurityPreDispatchPolicy,
    SecurityRequestLifecyclePermit,
};
use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};
use chio_security_types::PrincipalId;

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Clone)]
struct Release {
    allowed: bool,
    zero_charge: bool,
    payments: Arc<PaymentCalls>,
    releases: Arc<AtomicU64>,
}

impl SecurityRequestLifecyclePermit for Release {
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        let settled = if self.zero_charge {
            &self.payments.releases
        } else {
            &self.payments.captures
        };
        if settled.load(Ordering::SeqCst) != 1 {
            return Err(KernelError::Internal(
                "security release preceded settlement".into(),
            ));
        }
        if self.allowed {
            Ok(())
        } else {
            Err(KernelError::GuardDenied("security release refused".into()))
        }
    }
}

impl SecurityPreDispatchHook for Release {
    fn name(&self) -> &str {
        "settled-security-release"
    }
    fn acquire_request_lifecycle(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, KernelError> {
        Ok(Some(Box::new(self.clone())))
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

fn run(zero_charge: bool, allowed: bool) -> TestResult {
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let locks = temp.path().join("locks");
    create_private_directory(&locks)?;
    SqliteAuthorityStore::provision(&database, &locks)?;
    let keypair = Keypair::generate();
    let invocations = Arc::new(AtomicU64::new(0));
    let payments = Arc::new(PaymentCalls::default());
    let releases = Arc::new(AtomicU64::new(0));
    let open = || -> Result<(SqliteAuthorityStore, ChioKernel), Box<dyn Error>> {
        let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
        let mut kernel = ChioKernel::new(kernel_config(keypair.clone()));
        kernel.set_durable_admission_store(
            Arc::new(authority.admission_operation_store()),
            Arc::new(authority.tool_outcome_store()),
            authority.mutation_fence(),
        )?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
            calls: Some(payments.clone()),
        }));
        if zero_charge {
            kernel.register_tool_server(Box::new(ZeroCostMutationServer {
                invocations: invocations.clone(),
            }));
        } else {
            kernel.register_tool_server(Box::new(PaidMutationServer {
                invocations: invocations.clone(),
            }));
        }
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(Arc::new(Release {
            allowed,
            zero_charge,
            payments: payments.clone(),
            releases: releases.clone(),
        }));
        Ok((authority, kernel))
    };
    let (authority, kernel) = open()?;
    kernel.reconcile_durable_admission_startup()?;
    let agent = Keypair::generate();
    let capability = kernel.issue_capability(
        &agent.public_key(),
        if zero_charge {
            zero_charge_scope()
        } else {
            paid_scope()
        },
        300,
    )?;
    let request = if zero_charge {
        zero_charge_request(&capability)
    } else {
        paid_request(&capability)
    };
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("settlement-tenant")?,
        SessionId::new("settlement-session")?,
        PrincipalId::new(request.agent_id.clone())?,
        IsolationEpochId::new("settlement-epoch")?,
        LineageId::new(capability.id.clone())?,
        1,
    ));
    let first = kernel.evaluate_tool_call_blocking_with_security_context(&request, &context);
    let receipt = if allowed {
        let response = first?;
        assert_eq!(response.verdict, Verdict::Allow);
        Some(response.receipt.id)
    } else {
        assert!(
            matches!(
                first,
                Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(_))
            ),
            "{first:?}"
        );
        None
    };
    let retry = kernel.evaluate_tool_call_blocking_with_security_context(&request, &context);
    if let Some(expected) = &receipt {
        assert_eq!(&retry?.receipt.id, expected);
    } else {
        assert!(
            matches!(
                retry,
                Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(_))
            ),
            "{retry:?}"
        );
        let future = now_unix_ms()?.checked_add(120_000).ok_or("recovery time")?;
        let pending = authority
            .admission_operation_store()
            .list_recoverable(future, 10)?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].state(), AdmissionOperationState::Finalizing);
        let journal = authority
            .admission_operation_store()
            .load_payment_journal(
                pending[0].binding().operation_id().as_str(),
                &authority.mutation_fence(),
            )?
            .ok_or("payment journal")?;
        assert_eq!(journal.state, PaymentJournalState::Settled);
    }
    drop(kernel);
    drop(authority);
    let (_authority, kernel) = open()?;
    let recovered = kernel.reconcile_durable_admission_startup();
    if let Some(expected) = receipt {
        recovered?;
        let response =
            kernel.evaluate_tool_call_blocking_with_security_context(&request, &context)?;
        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(response.receipt.id, expected);
    } else {
        assert!(
            matches!(
                recovered,
                Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(_))
            ),
            "{recovered:?}"
        );
    }
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert_eq!(payments.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(
        payments.captures.load(Ordering::SeqCst),
        u64::from(!zero_charge)
    );
    assert_eq!(
        payments.releases.load(Ordering::SeqCst),
        u64::from(zero_charge)
    );
    assert_eq!(payments.refunds.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn payment_capture_precedes_checkpoint_and_is_not_repeated() -> TestResult {
    run(false, true)
}
#[test]
fn zero_charge_release_precedes_checkpoint_and_is_not_repeated() -> TestResult {
    run(true, true)
}
#[test]
fn security_refusal_cannot_repeat_or_reverse_captured_payment() -> TestResult {
    run(false, false)
}
#[test]
fn security_refusal_cannot_repeat_zero_charge_release() -> TestResult {
    run(true, false)
}
