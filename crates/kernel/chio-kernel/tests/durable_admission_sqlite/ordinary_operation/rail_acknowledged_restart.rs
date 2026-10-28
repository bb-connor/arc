//! A clock fault after capture acknowledgement leaves the durable settlement
//! intent incomplete. A reopened owner retries that intent without repeating
//! the tool invocation or its budget reconciliation.
use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading};

struct LostCaptureAcknowledgement;

/// Panics on the first clock read after capture acknowledgement, before the
/// completion compare-and-set can persist that acknowledgement.
struct PanicAfterAcknowledgement {
    source: Arc<dyn Clock>,
    acknowledged: Arc<AtomicBool>,
}

impl Clock for PanicAfterAcknowledgement {
    fn read(&self) -> Result<ClockReading, ClockError> {
        if self.acknowledged.swap(false, Ordering::SeqCst) {
            std::panic::resume_unwind(Box::new(LostCaptureAcknowledgement));
        }
        self.source.read()
    }
}

struct AcknowledgingRail {
    inner: ReversiblePaymentAdapter,
    acknowledged: Arc<AtomicBool>,
}

impl PaymentAdapter for AcknowledgingRail {
    fn rail_id(&self) -> &'static str {
        self.inner.rail_id()
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        self.inner.rail_mode()
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.inner.authorize(request)
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        let acknowledged =
            self.inner
                .capture(authorization_id, amount_units, currency, reference)?;
        self.acknowledged.store(true, Ordering::SeqCst);
        Ok(acknowledged)
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner.release(authorization_id, reference)
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.inner
            .refund(transaction_id, amount_units, currency, reference)
    }

    fn replayed_authorization_metadata(
        &self,
        authorization_id: &str,
    ) -> Result<serde_json::Value, PaymentError> {
        self.inner.replayed_authorization_metadata(authorization_id)
    }
}

#[test]
fn sqlite_restart_after_capture_acknowledgement_fault_redrives_once() -> Result<(), Box<dyn Error>>
{
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let keypair = Keypair::generate();
    let invocations = Arc::new(AtomicU64::new(0));
    let calls = Arc::new(PaymentCalls::default());
    let acknowledged = Arc::new(AtomicBool::new(false));

    let (request, operation_id, capability_id, retained_journal, original_fence) = {
        let authority = SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &lock_root,
            chio_test_support::clock::clock(),
        )?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let mut kernel = ChioKernel::new_with_clock(
            kernel_config(keypair.clone()),
            Arc::new(PanicAfterAcknowledgement {
                source: chio_test_support::clock::clock(),
                acknowledged: acknowledged.clone(),
            }),
        );
        kernel.set_durable_admission_store(
            operations.clone(),
            Arc::new(authority.tool_outcome_store()),
            fence.clone(),
        )?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_payment_adapter(Box::new(AcknowledgingRail {
            inner: ReversiblePaymentAdapter {
                calls: Some(calls.clone()),
            },
            acknowledged: acknowledged.clone(),
        }));
        kernel.register_tool_server(Box::new(PaidMutationServer {
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(&agent.public_key(), paid_scope(), 300)?;
        let request = paid_request(&capability);
        let Err(error) = kernel.evaluate_tool_call_blocking(&request) else {
            return Err("clock fault must retain the original settlement intent".into());
        };
        assert!(
            matches!(error, KernelError::Clock(ClockError::Unavailable)),
            "{error:?}"
        );
        assert!(kernel.receipt_log().is_empty());
        assert!(!acknowledged.load(Ordering::SeqCst));
        assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
        let reference = {
            let references = calls
                .authorization_references
                .lock()
                .map_err(|_| "authorization trace lock")?;
            let [reference] = references.as_slice() else {
                return Err("expected one original authorization reference".into());
            };
            reference.clone()
        };
        let operation = from_rail_reference(operations.as_ref(), &fence, &request, &reference)?;
        assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
        let journal = operations
            .load_payment_journal(operation.binding().operation_id().as_str(), &fence)?
            .ok_or("retained settlement journal")?;
        assert_eq!(
            (
                journal.state,
                journal.settle_action,
                journal.settle_amount_units
            ),
            (
                PaymentJournalState::Settling,
                Some(PaymentSettleAction::Capture),
                Some(5)
            )
        );
        (
            request,
            operation.binding().operation_id().clone(),
            capability.id.clone(),
            journal,
            fence,
        )
    };

    let authority = SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &lock_root,
        chio_test_support::clock::clock(),
    )?;
    let fence = authority.mutation_fence();
    assert_eq!(fence.store_uuid, original_fence.store_uuid);
    assert!(fence.owner_epoch > original_fence.owner_epoch);
    let operations = Arc::new(authority.admission_operation_store());
    let budget = Arc::new(authority.budget_store());
    assert_eq!(
        operations.load_payment_journal(operation_id.as_str(), &fence)?,
        Some(retained_journal)
    );
    let reconciled = budget
        .get_usage(&capability_id, 0)?
        .ok_or("budget usage reconciled with the settlement intent")?;
    assert_eq!(reconciled.total_cost_realized_spend, 5);
    let mut recovered =
        ChioKernel::new_with_clock(kernel_config(keypair), chio_test_support::clock::clock());
    recovered.set_durable_admission_store(
        operations.clone(),
        Arc::new(authority.tool_outcome_store()),
        fence.clone(),
    )?;
    recovered.set_budget_store_handle(budget.clone());
    recovered.set_payment_adapter(Box::new(ReversiblePaymentAdapter {
        calls: Some(calls.clone()),
    }));
    recovered.register_tool_server(Box::new(PaidMutationServer {
        invocations: invocations.clone(),
    }));

    assert_eq!(recovered.reconcile_durable_admission_startup()?, 1);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 2);
    let journal = operations
        .load_payment_journal(operation_id.as_str(), &fence)?
        .ok_or("recovered payment journal")?;
    assert_eq!(
        (
            journal.state,
            journal.settle_action,
            journal.settle_amount_units
        ),
        (
            PaymentJournalState::Settled,
            Some(PaymentSettleAction::Capture),
            Some(5)
        )
    );
    assert_eq!(
        operations
            .load_by_operation_id(&operation_id)?
            .ok_or("recovered operation")?
            .state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(budget.get_usage(&capability_id, 0)?, Some(reconciled));
    let replay = recovered.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(recovered.reconcile_recoverable_admissions()?, 0);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 2);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
