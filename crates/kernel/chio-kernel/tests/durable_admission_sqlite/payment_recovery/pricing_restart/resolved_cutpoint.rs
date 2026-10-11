//! A process stops at the Resolved commit, before any settlement step. The
//! next owner settles from the persisted Resolved disposition and its frozen
//! pricing, never from a fresh conversion, and captures exactly once.
use super::*;
use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionOperationV1};
use chio_kernel::tool_outcome::{
    PostReturnEvaluationStateV1, ResolvedToolOutcomeV1, SettlementDispositionV1,
};
use chio_kernel::{DurableFinalizationCutpoint, PaymentJournalRecord};
use chio_store_sqlite::SqliteAdmissionOperationStore;
use std::sync::Mutex;

const UNITS: u64 = 3_000_000_000_000_000;
const ORIGINAL_CHARGE: u64 = 3;

struct CutpointCrash;

#[derive(Debug)]
struct AtResolved {
    operation: AdmissionOperationV1,
    journal: PaymentJournalRecord,
    outcome: ToolOutcomeRecordV1,
    evaluation: PostReturnEvaluationRecordV1,
    rail_captures: u64,
    traced_captures: usize,
}

#[derive(Clone, Copy, Debug)]
enum Recovery {
    Startup,
    Request,
}

type Trace = Arc<Mutex<Vec<DurableFinalizationCutpoint>>>;

fn observe_resolved(
    operations: &SqliteAdmissionOperationStore,
    outcomes: &SqliteToolOutcomeStore,
    fence: &StoreMutationFence,
    facts: &PricingFacts,
) -> Result<AtResolved, Box<dyn Error>> {
    let reference = {
        let references = facts
            .calls
            .authorization_references
            .lock()
            .map_err(|_| "authorization trace lock")?;
        let [reference] = references.as_slice() else {
            return Err("expected one original authorization reference".into());
        };
        reference.clone()
    };
    let id = AdmissionOperationId::from_persisted(&reference)?;
    Ok(AtResolved {
        operation: operations
            .load_by_operation_id(&id)?
            .ok_or("operation at the Resolved commit")?,
        journal: operations
            .load_payment_journal(id.as_str(), fence)?
            .ok_or("journal at the Resolved commit")?,
        outcome: outcomes
            .lookup_by_operation(&id)?
            .ok_or("tool outcome at the Resolved commit")?,
        evaluation: outcomes
            .lookup_post_return_evaluation(&id)?
            .ok_or("evaluation at the Resolved commit")?,
        rail_captures: facts.calls.captures.load(Ordering::SeqCst),
        traced_captures: facts
            .captures
            .lock()
            .map_err(|_| "capture trace lock")?
            .len(),
    })
}

fn paid_kernel(
    keypair: Keypair,
    authority: &SqliteAuthorityStore,
    facts: &Arc<PricingFacts>,
    invocations: &Arc<AtomicU64>,
) -> Result<ChioKernel, Box<dyn Error>> {
    let mut kernel =
        ChioKernel::new_with_clock(kernel_config(keypair), chio_test_support::clock::clock());
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
    kernel.set_payment_adapter(Box::new(TracedCapture(facts.clone())));
    kernel.set_price_oracle(Box::new(MovingRate(facts.clone())));
    kernel.register_tool_server(Box::new(CostServer {
        invocations: invocations.clone(),
        units: UNITS,
        currency: "ETH",
    }));
    Ok(kernel)
}

fn resolved_capture(disposition: &ResolvedToolOutcomeV1) -> Option<&MonetaryAmount> {
    match disposition {
        ResolvedToolOutcomeV1::Resolved {
            settlement_disposition: SettlementDispositionV1::Capture { amount },
            ..
        } => Some(amount),
        _ => None,
    }
}

fn crash_at_resolved_then_recover(
    request_id: &str,
    recovery: Recovery,
) -> Result<(), Box<dyn Error>> {
    let at = 1_800_000_400_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let (_temp, database, locks) = provision()?;
    let keypair = Keypair::generate();
    let invocations = Arc::new(AtomicU64::new(0));
    let facts = Arc::new(PricingFacts::default());
    facts.rate.store(10, Ordering::SeqCst);
    let trace: Trace = Arc::new(Mutex::new(Vec::new()));
    let at_resolved: Arc<Mutex<Option<Result<AtResolved, String>>>> = Arc::new(Mutex::new(None));

    let (request, original_fence) = {
        let authority = SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &locks,
            chio_test_support::clock::clock(),
        )?;
        let fence = authority.mutation_fence();
        let mut kernel = paid_kernel(keypair.clone(), &authority, &facts, &invocations)?;
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(&agent.public_key(), paid_scope(), 300)?;
        let mut request = paid_request(&capability);
        request.request_id = request_id.into();
        let operations = Arc::new(authority.admission_operation_store());
        let outcomes = authority.tool_outcome_store();
        let hook_fence = fence.clone();
        let hook_facts = facts.clone();
        let hook_trace = trace.clone();
        let hook_slot = at_resolved.clone();
        kernel.install_durable_finalization_cutpoint(Arc::new(move |reached| {
            if let Ok(mut trace) = hook_trace.lock() {
                trace.push(reached);
            }
            if reached == DurableFinalizationCutpoint::PostReturnResolved {
                let observed = observe_resolved(&operations, &outcomes, &hook_fence, &hook_facts)
                    .map_err(|error| error.to_string());
                if let Ok(mut slot) = hook_slot.lock() {
                    *slot = Some(observed);
                }
                std::panic::resume_unwind(Box::new(CutpointCrash));
            }
        }));
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            kernel.evaluate_tool_call_blocking(&request)
        }));
        let payload = match crashed {
            Err(payload) => payload,
            Ok(result) => {
                return Err(format!("evaluation passed the Resolved cutpoint: {result:?}").into())
            }
        };
        assert!(matches!(
            payload.downcast_ref::<CutpointCrash>(),
            Some(CutpointCrash)
        ));
        (request, fence)
    };

    let at_resolved = at_resolved
        .lock()
        .map_err(|_| "cutpoint observation lock")?
        .take()
        .ok_or("the Resolved cutpoint was not reached")??;
    assert_eq!(
        trace.lock().map_err(|_| "cutpoint trace lock")?.as_slice(),
        [
            DurableFinalizationCutpoint::ToolReturnRecorded,
            DurableFinalizationCutpoint::PostReturnEvaluationBegun,
            DurableFinalizationCutpoint::PostReturnResolved,
        ]
    );
    let operation_id = at_resolved.operation.binding().operation_id().clone();
    assert_eq!(
        at_resolved.operation.state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(at_resolved.journal.operation_id, operation_id.as_str());
    assert_eq!(at_resolved.journal.state, PaymentJournalState::Authorized);
    assert_eq!(at_resolved.journal.rail, "sqlite-test-reversible");
    assert_eq!(at_resolved.journal.currency, "USD");
    assert_eq!(at_resolved.journal.authorized_amount_units, Some(10));
    assert!(at_resolved.journal.authorization_id.is_some());
    assert_eq!(at_resolved.journal.settle_action, None);
    assert_eq!(at_resolved.journal.settle_amount_units, None);
    assert!(matches!(
        at_resolved.evaluation.state(),
        PostReturnEvaluationStateV1::Resolved { .. }
    ));
    assert_eq!(
        resolved_capture(at_resolved.outcome.disposition()),
        Some(&MonetaryAmount {
            units: ORIGINAL_CHARGE,
            currency: "USD".into(),
        })
    );
    assert_eq!(
        (at_resolved.rail_captures, at_resolved.traced_captures),
        (0, 0)
    );
    assert_eq!(facts.oracle_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    // A later rate would change the charge if the next owner repriced.
    facts.rate.store(20, Ordering::SeqCst);
    let authority = SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &locks,
        chio_test_support::clock::clock(),
    )?;
    let fence = authority.mutation_fence();
    assert_eq!(fence.store_uuid, original_fence.store_uuid);
    assert!(fence.owner_epoch > original_fence.owner_epoch);
    let operations = authority.admission_operation_store();
    let outcomes = authority.tool_outcome_store();
    let persisted = ordinary_operation::from_rail_reference(
        &operations,
        &fence,
        &request,
        operation_id.as_str(),
    )?;
    assert_eq!(persisted, at_resolved.operation);
    assert_eq!(
        operations.load_payment_journal(operation_id.as_str(), &fence)?,
        Some(at_resolved.journal.clone())
    );
    assert_eq!(
        outcomes.lookup_by_operation(&operation_id)?.as_ref(),
        Some(&at_resolved.outcome)
    );
    assert_eq!(
        outcomes
            .lookup_post_return_evaluation(&operation_id)?
            .as_ref(),
        Some(&at_resolved.evaluation)
    );

    let mut kernel = paid_kernel(keypair.clone(), &authority, &facts, &invocations)?;
    let recovered_trace: Trace = Arc::new(Mutex::new(Vec::new()));
    let hook_trace = recovered_trace.clone();
    kernel.install_durable_finalization_cutpoint(Arc::new(move |reached| {
        if let Ok(mut trace) = hook_trace.lock() {
            trace.push(reached);
        }
    }));
    let response = match recovery {
        Recovery::Startup => {
            assert_eq!(kernel.reconcile_durable_admission_startup()?, 1);
            kernel.evaluate_tool_call_blocking(&request)?
        }
        Recovery::Request => {
            let response = kernel.evaluate_tool_call_blocking(&request)?;
            assert_eq!(kernel.reconcile_durable_admission_startup()?, 0);
            response
        }
    };
    assert_eq!(
        recovered_trace
            .lock()
            .map_err(|_| "cutpoint trace lock")?
            .as_slice(),
        [DurableFinalizationCutpoint::TerminalProjected],
        "{recovery:?}"
    );

    let completed = ordinary_operation::from_rail_reference(
        &operations,
        &fence,
        &request,
        operation_id.as_str(),
    )?;
    assert_eq!(completed.state(), AdmissionOperationState::Completed);
    let journal = operations
        .load_payment_journal(operation_id.as_str(), &fence)?
        .ok_or("settled original journal")?;
    assert_eq!(journal.state, PaymentJournalState::Settled);
    assert_eq!(journal.settle_action, Some(PaymentSettleAction::Capture));
    assert_eq!(journal.settle_amount_units, Some(ORIGINAL_CHARGE));
    assert_eq!(
        journal.authorization_id,
        at_resolved.journal.authorization_id
    );
    assert_eq!(journal.authorized_amount_units, Some(10));
    assert_eq!(
        outcomes
            .lookup_post_return_evaluation(&operation_id)?
            .as_ref(),
        Some(&at_resolved.evaluation)
    );
    assert_eq!(
        resolved_capture(
            outcomes
                .lookup_by_operation(&operation_id)?
                .ok_or("terminal tool outcome")?
                .disposition()
        ),
        Some(&MonetaryAmount {
            units: ORIGINAL_CHARGE,
            currency: "USD".into(),
        })
    );

    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(
        response.output,
        Some(chio_kernel::ToolCallOutput::Value(
            serde_json::json!({"original_paid_output": true}),
        ))
    );
    assert!(response.receipt.verify_signature()?);
    assert_eq!(response.receipt.kernel_key, keypair.public_key());
    assert_eq!(response.receipt.capability_id, request.capability.id);
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
        Some(ORIGINAL_CHARGE)
    );
    assert_eq!(
        financial
            .get("oracle_evidence")
            .and_then(|evidence| evidence.get("converted_cost_units"))
            .and_then(serde_json::Value::as_u64),
        Some(ORIGINAL_CHARGE)
    );

    assert_eq!(
        facts
            .captures
            .lock()
            .map_err(|_| "capture trace lock")?
            .as_slice(),
        &[(
            operation_id.as_str().to_owned(),
            ORIGINAL_CHARGE,
            "USD".into()
        )]
    );
    assert_eq!(facts.oracle_calls.load(Ordering::SeqCst), 1);
    assert_eq!(facts.calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(facts.calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(facts.calls.releases.load(Ordering::SeqCst), 0);
    assert_eq!(facts.calls.refunds.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let bytes = canonical_json_bytes(&response.receipt)?;
    assert_eq!(
        canonical_json_bytes(&kernel.evaluate_tool_call_blocking(&request)?.receipt)?,
        bytes
    );
    assert_eq!(facts.calls.captures.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn sqlite_crash_at_resolved_commit_startup_settles_from_original_disposition(
) -> Result<(), Box<dyn Error>> {
    crash_at_resolved_then_recover("sqlite-resolved-cutpoint-startup", Recovery::Startup)
}

#[test]
fn sqlite_crash_at_resolved_commit_request_replay_settles_from_original_disposition(
) -> Result<(), Box<dyn Error>> {
    crash_at_resolved_then_recover("sqlite-resolved-cutpoint-request", Recovery::Request)
}
