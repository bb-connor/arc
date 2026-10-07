//! A host cancellation that wins the dispatch-start boundary after the rail
//! authorized payment runs the denial's pre-dispatch cleanup and signs a
//! cancelled outcome.

use super::*;
use std::sync::mpsc;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const HOLD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const HOST_CANCELLATION: &str = "session request cancelled before dispatch";
const CONTROL_DENIAL: &str = "post-payment control denial";
const UNCONFIRMED_CLEANUP: &str = "; pre-dispatch cleanup could not be confirmed: ";
const UNCONFIRMED_UNWIND: &str = "internal error: payment unwind acknowledgement was not confirmed";

#[derive(Clone, Copy, Debug)]
enum Entry {
    Session,
    Nested,
}

#[derive(Clone, Copy)]
enum Outcome {
    Denied,
    HostCancelled,
}

enum AfterPayment {
    Deny,
    Park {
        armed: std::sync::atomic::AtomicBool,
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    },
}

/// Allows the call, then acts in the post-payment dispatch revalidation: the
/// last guard call after the rail authorized payment and before the session
/// dispatch-start boundary.
struct AfterPaymentGuard {
    store: Arc<TestAdmissionOperationStore>,
    action: AfterPayment,
}

impl Guard for AfterPaymentGuard {
    fn name(&self) -> &str {
        "after-payment-host-boundary"
    }

    fn evaluate(&self, _: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }

    fn revalidate_before_dispatch(&self, _: &GuardContext<'_>) -> Result<(), KernelError> {
        if self
            .store
            .payment_journal()
            .is_none_or(|journal| journal.authorization_id.is_none())
        {
            return Ok(());
        }
        match &self.action {
            AfterPayment::Deny => Err(KernelError::GuardDenied(CONTROL_DENIAL.into())),
            AfterPayment::Park {
                armed,
                entered,
                release,
            } => {
                if !armed.swap(false, Ordering::SeqCst) {
                    return Ok(());
                }
                let internal = |reason: &str| KernelError::Internal(reason.into());
                entered
                    .send(())
                    .map_err(|_| internal("boundary observer unavailable"))?;
                release
                    .lock()
                    .map_err(|_| internal("boundary release lock poisoned"))?
                    .recv_timeout(HOLD_TIMEOUT)
                    .map_err(|_| internal("boundary release timed out"))
            }
        }
    }
}

struct Run {
    request: ToolCallRequest,
    store: Arc<TestAdmissionOperationStore>,
    calls: Arc<RailCalls>,
    invocations: Arc<AtomicU64>,
    response: ToolCallResponse,
}

/// Evaluates one paid call that the session owns. The control denies in the
/// post-payment revalidation; the host cancellation is requested while the
/// call is parked there, so the dispatch-start boundary observes it next.
fn run(
    name: &str,
    prepaid: bool,
    release_failed: bool,
    entry: Entry,
    outcome: Outcome,
) -> TestResult<Run> {
    let (mut kernel, request, store, invocations, calls) = payment_fixture(name, prepaid);
    calls.release_failed.store(release_failed, Ordering::SeqCst);
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let action = match outcome {
        Outcome::Denied => AfterPayment::Deny,
        Outcome::HostCancelled => AfterPayment::Park {
            armed: std::sync::atomic::AtomicBool::new(true),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        },
    };
    kernel.add_guard(Box::new(AfterPaymentGuard {
        store: store.clone(),
        action,
    }));
    let session_id =
        kernel.open_session(request.agent_id.clone(), vec![request.capability.clone()])?;
    kernel.activate_session(&session_id)?;
    let owner_request_id = match entry {
        Entry::Session => request.request_id.clone(),
        Entry::Nested => format!("{name}-parent"),
    };
    let owner = make_operation_context(&session_id, &owner_request_id, &request.agent_id);
    kernel.begin_session_request(&owner, OperationKind::ToolCall, true)?;

    let authorized = if prepaid {
        PaymentJournalState::Settled
    } else {
        PaymentJournalState::Authorized
    };
    let kernel = &kernel;
    let evaluate = || match entry {
        Entry::Session => kernel.evaluate_tool_call_sync_with_session_context(
            &request,
            Some(&[]),
            None,
            Some(&session_id),
        ),
        Entry::Nested => kernel.evaluate_tool_call_with_nested_flow_client(
            &owner,
            &request,
            &mut NoopNestedFlowClient,
            None,
        ),
    };
    let response = match outcome {
        Outcome::Denied => evaluate()?,
        Outcome::HostCancelled => std::thread::scope(|scope| -> TestResult<ToolCallResponse> {
            let evaluation = scope.spawn(|| evaluate().map_err(|error| error.to_string()));
            entered.recv_timeout(HOLD_TIMEOUT)?;
            let parked = store
                .payment_journal()
                .map(|journal| (journal.state, journal.authorization_id));
            let parked_invocations = invocations.load(Ordering::SeqCst);
            kernel.request_session_cancellation(&session_id, &owner.request_id)?;
            release.send(())?;
            let response = evaluation
                .join()
                .map_err(|_| "evaluation thread panicked")??;
            assert_eq!(
                parked,
                Some((authorized, Some("original-payment-authorization".into())))
            );
            assert_eq!(parked_invocations, 0);
            Ok(response)
        })?,
    };
    Ok(Run {
        request,
        store,
        calls,
        invocations,
        response,
    })
}

/// Everything the shared pre-dispatch cleanup leaves behind. Identifiers that
/// differ between fixtures are replaced by their role, and the per-receipt
/// signing nonce is dropped.
fn cleanup_state(run: &Run) -> TestResult<serde_json::Value> {
    let operation = run.store.operation();
    let operation_id = operation.binding().operation_id().as_str().to_owned();
    let hold_id = operation
        .budget_hold_id()
        .ok_or("hold ID")?
        .as_str()
        .to_owned();
    let journal = run.store.payment_journal().ok_or("payment journal")?;
    let hold = run
        .store
        .budget_store()
        .get_budget_hold(&hold_id)?
        .ok_or("original hold")?;
    let usage = run
        .store
        .budget_store()
        .get_usage(&run.request.capability.id, 0)?
        .ok_or("grant usage")?;
    let refunds = run
        .calls
        .refunds
        .lock()
        .map_err(|_| "test lock")?
        .iter()
        .map(|(transaction, units, currency, reference)| {
            serde_json::json!([transaction, units, currency, reference])
        })
        .collect::<Vec<_>>();
    let mut metadata = run.response.receipt.metadata.clone().ok_or("metadata")?;
    metadata
        .as_object_mut()
        .ok_or("metadata object")?
        .remove("chio_receipt_signing_nonce")
        .ok_or("signing nonce")?;
    let state = serde_json::json!({
        "journal": {
            "state": format!("{:?}", journal.state),
            "version": journal.journal_version,
            "rail_mode": format!("{:?}", journal.rail_mode),
            "authorization_id": journal.authorization_id,
            "transaction_id": journal.transaction_id,
            "amount_units": journal.amount_units,
            "authorized_amount_units": journal.authorized_amount_units,
            "settle_action": journal.settle_action.map(|action| format!("{action:?}")),
            "settle_amount_units": journal.settle_amount_units,
            "release_authority": journal
                .release_authority
                .as_ref()
                .map(|authority| format!("{:?}", authority.kind)),
            "compensated_before_dispatch": journal.is_compensated_before_dispatch(),
        },
        "operation": format!("{:?}", operation.state()),
        "hold": {
            "authorized_exposure_units": hold.authorized_exposure_units,
            "remaining_exposure_units": hold.remaining_exposure_units,
            "disposition": format!("{:?}", hold.disposition),
        },
        "usage": {
            "invocation_count": usage.invocation_count,
            "seq": usage.seq,
            "total_cost_exposed": usage.total_cost_exposed,
            "total_cost_realized_spend": usage.total_cost_realized_spend,
        },
        "rail": {
            "authorizations": run.calls.authorizations.lock().map_err(|_| "test lock")?.clone(),
            "releases": run.calls.releases.lock().map_err(|_| "test lock")?.clone(),
            "refunds": refunds,
            "captures": run.calls.captures.lock().map_err(|_| "test lock")?.len(),
        },
        "invocations": run.invocations.load(Ordering::SeqCst),
        "receipt_metadata": metadata,
    });
    let roles = [
        (hold_id, "<hold>"),
        (operation_id, "<operation>"),
        (run.request.capability.id.clone(), "<capability>"),
        (run.request.request_id.clone(), "<request>"),
        (run.request.capability.issuer.to_hex(), "<issuer>"),
        (run.request.capability.subject.to_hex(), "<subject>"),
    ];
    Ok(replace_roles(state, &roles))
}

fn replace_roles(value: serde_json::Value, roles: &[(String, &str)]) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => {
            serde_json::Value::String(roles.iter().fold(text, |text, (value, role)| {
                text.replace(value.as_str(), role)
            }))
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .into_iter()
                .map(|item| replace_roles(item, roles))
                .collect(),
        ),
        serde_json::Value::Object(fields) => serde_json::Value::Object(
            fields
                .into_iter()
                .map(|(key, item)| (key, replace_roles(item, roles)))
                .collect(),
        ),
        other => other,
    }
}

fn assert_signed(
    response: &ToolCallResponse,
    decision: Decision,
    terminal_state: OperationTerminalState,
    reason: &str,
) -> TestResult {
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.output, None);
    assert_eq!(response.reason.as_deref(), Some(reason));
    assert_eq!(response.terminal_state, terminal_state);
    assert_eq!(response.receipt.decision, Some(decision));
    assert!(response.receipt.verify_signature()?);
    Ok(())
}

/// Runs the existing post-payment denial and the host cancellation on equal
/// fixtures. Both must leave identical cleanup state; only the signed outcome
/// differs.
fn cancel_against_denial(
    name: &str,
    prepaid: bool,
    release_failed: bool,
    entry: Entry,
) -> TestResult<(Run, serde_json::Value)> {
    let denied = run(name, prepaid, release_failed, entry, Outcome::Denied)?;
    let cancelled = run(name, prepaid, release_failed, entry, Outcome::HostCancelled)?;
    let cleanup = if release_failed {
        format!("{UNCONFIRMED_CLEANUP}{UNCONFIRMED_UNWIND}")
    } else {
        String::new()
    };
    let control = KernelError::GuardDenied(format!(
        "guard dispatch revalidation failed: {}",
        KernelError::GuardDenied(CONTROL_DENIAL.into())
    ));
    let control = format!("{control}{cleanup}");
    assert_signed(
        &denied.response,
        Decision::Deny {
            reason: control.clone(),
            guard: "kernel".into(),
        },
        OperationTerminalState::Completed,
        &control,
    )?;
    let cancellation = format!("{HOST_CANCELLATION}{cleanup}");
    assert_signed(
        &cancelled.response,
        Decision::Cancelled {
            reason: cancellation.clone(),
        },
        OperationTerminalState::Cancelled {
            reason: cancellation.clone(),
        },
        &cancellation,
    )?;
    let state = cleanup_state(&cancelled)?;
    assert_eq!(state, cleanup_state(&denied)?, "{entry:?}");
    Ok((cancelled, state))
}

/// The original hold's financial metadata once it is fully reversed before
/// dispatch: ten of a hundred USD attempted at grant zero, nothing charged.
fn reversed_hold_financial() -> serde_json::Value {
    serde_json::json!({
        "attempted_cost": 10,
        "budget_remaining": 100,
        "budget_total": 100,
        "cost_charged": 0,
        "currency": "USD",
        "delegation_depth": 0,
        "grant_index": 0,
        "root_budget_holder": "<issuer>",
        "settlement_status": "not_applicable",
    })
}

fn reversed_budget() -> serde_json::Value {
    serde_json::json!({
        "hold": {
            "authorized_exposure_units": 10,
            "remaining_exposure_units": 0,
            "disposition": "Reversed",
        },
        "usage": {
            "invocation_count": 0,
            "seq": 2,
            "total_cost_exposed": 0,
            "total_cost_realized_spend": 0,
        },
    })
}

fn retained_credentials(unwind: Option<serde_json::Value>) -> serde_json::Value {
    let mut runtime = serde_json::json!({
        "dispatch_credential_disposition": "retained_after_authorization",
        "dispatch_credential_retention_outcome_unknown": false,
        "payment_credential_disposition": "retained_after_authorization",
    });
    if let (Some(fields), Some(unwind)) = (runtime.as_object_mut(), unwind) {
        fields.insert("pre_dispatch_payment_unwind".into(), unwind);
    }
    runtime
}

#[test]
fn host_cancel_after_reversible_hold_signs_cancelled_with_released_payment() -> TestResult {
    for entry in [Entry::Session, Entry::Nested] {
        let (cancelled, state) = cancel_against_denial(
            &format!("session-cancel-reversible-{entry:?}"),
            false,
            false,
            entry,
        )?;
        assert_eq!(
            state["journal"],
            serde_json::json!({
                "state": "Settled",
                "version": 5,
                "rail_mode": "ReversibleHold",
                "authorization_id": "original-payment-authorization",
                "transaction_id": "original-payment-authorization",
                "amount_units": 10,
                "authorized_amount_units": 10,
                "settle_action": "Release",
                "settle_amount_units": null,
                "release_authority": "PreDispatchNoEffect",
                "compensated_before_dispatch": true,
            })
        );
        assert_eq!(state["operation"], "CompensatedBeforeDispatch");
        assert_eq!(state["hold"], reversed_budget()["hold"]);
        assert_eq!(state["usage"], reversed_budget()["usage"]);
        assert_eq!(
            state["rail"],
            serde_json::json!({
                "authorizations": ["<operation>"],
                "releases": ["<operation>"],
                "refunds": [],
                "captures": 0,
            })
        );
        assert_eq!(state["invocations"], 0);
        assert_eq!(
            state["receipt_metadata"]["chio_runtime"],
            retained_credentials(Some(serde_json::json!({
                "authorization_id": "original-payment-authorization",
                "credential_disposition": "retained_after_authorization",
                "settlement_status": "released",
                "transaction_id": "original-payment-authorization",
            })))
        );
        assert_eq!(
            state["receipt_metadata"]["budget_authority"]["terminal"]["disposition"],
            "reversed"
        );
        assert_eq!(
            state["receipt_metadata"]["financial"],
            reversed_hold_financial()
        );
        assert_released_budget(&cancelled.store)?;
    }
    Ok(())
}

#[test]
fn host_cancel_after_prepayment_signs_cancelled_with_refunded_payment() -> TestResult {
    for entry in [Entry::Session, Entry::Nested] {
        let (cancelled, state) = cancel_against_denial(
            &format!("session-cancel-prepaid-{entry:?}"),
            true,
            false,
            entry,
        )?;
        assert_eq!(
            state["journal"],
            serde_json::json!({
                "state": "Closed",
                "version": 5,
                "rail_mode": "PrepaidFinal",
                "authorization_id": "original-payment-authorization",
                "transaction_id": "original-payment-refund",
                "amount_units": 10,
                "authorized_amount_units": 10,
                "settle_action": null,
                "settle_amount_units": null,
                "release_authority": "PreDispatchNoEffect",
                "compensated_before_dispatch": true,
            })
        );
        assert_eq!(state["operation"], "CompensatedBeforeDispatch");
        assert_eq!(state["hold"], reversed_budget()["hold"]);
        assert_eq!(state["usage"], reversed_budget()["usage"]);
        assert_eq!(
            state["rail"],
            serde_json::json!({
                "authorizations": ["<operation>"],
                "releases": [],
                "refunds": [["original-payment-authorization", 10, "USD", "<operation>"]],
                "captures": 0,
            })
        );
        assert_eq!(state["invocations"], 0);
        assert_eq!(
            state["receipt_metadata"]["chio_runtime"],
            retained_credentials(Some(serde_json::json!({
                "authorization_id": "original-payment-authorization",
                "credential_disposition": "retained_after_authorization",
                "settlement_status": "refunded",
                "transaction_id": "original-payment-refund",
            })))
        );
        assert_eq!(
            state["receipt_metadata"]["budget_authority"]["terminal"]["disposition"],
            "reversed"
        );
        assert_eq!(
            state["receipt_metadata"]["financial"],
            reversed_hold_financial()
        );
        assert_released_budget(&cancelled.store)?;
    }
    Ok(())
}

#[test]
fn host_cancel_with_unconfirmed_release_signs_cancelled_and_keeps_denial_state() -> TestResult {
    for entry in [Entry::Session, Entry::Nested] {
        let (_, state) = cancel_against_denial(
            &format!("session-cancel-unconfirmed-{entry:?}"),
            false,
            true,
            entry,
        )?;
        assert_eq!(
            state["journal"],
            serde_json::json!({
                "state": "Authorized",
                "version": 3,
                "rail_mode": "ReversibleHold",
                "authorization_id": "original-payment-authorization",
                "transaction_id": null,
                "amount_units": 10,
                "authorized_amount_units": 10,
                "settle_action": null,
                "settle_amount_units": null,
                "release_authority": null,
                "compensated_before_dispatch": false,
            })
        );
        assert_eq!(state["operation"], "CapturePending");
        assert_eq!(
            state["hold"],
            serde_json::json!({
                "authorized_exposure_units": 10,
                "remaining_exposure_units": 10,
                "disposition": "Open",
            })
        );
        assert_eq!(
            state["usage"],
            serde_json::json!({
                "invocation_count": 1,
                "seq": 1,
                "total_cost_exposed": 10,
                "total_cost_realized_spend": 0,
            })
        );
        assert_eq!(
            state["rail"],
            serde_json::json!({
                "authorizations": ["<operation>"],
                "releases": ["<operation>"],
                "refunds": [],
                "captures": 0,
            })
        );
        assert_eq!(state["invocations"], 0);
        assert_eq!(
            state["receipt_metadata"]["chio_runtime"],
            retained_credentials(None)
        );
        assert_eq!(
            state["receipt_metadata"]["financial"],
            serde_json::json!({
                "payment_authorization_may_be_retained": true,
                "payment_reference": "original-payment-authorization",
                "payment_unwind_attempt_reference": "<operation>",
                "payment_unwind_unconfirmed": true,
            })
        );
        let budget = &state["receipt_metadata"]["budget_authority"];
        assert_eq!(budget["pre_dispatch_cleanup_unconfirmed"], true);
        assert_eq!(budget["admission_release_unconfirmed"], true);
        assert_eq!(budget["admission_may_be_retained"], true);
        assert_eq!(budget["cleanup_mutation_kind"], "charge");
        assert_eq!(budget["cleanup_hold_id"], "<hold>");
    }
    Ok(())
}
