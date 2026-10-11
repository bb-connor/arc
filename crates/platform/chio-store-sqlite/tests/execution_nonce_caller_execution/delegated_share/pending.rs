//! Deterministic interleavings at the real kernel's funded share boundary.

use super::*;
use chio_kernel::admission_operation::AdmissionOperationState;
use chio_kernel::CallerExecutionCheckpoint;
use std::sync::{mpsc, Mutex};

struct FundingGate {
    arrived: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
}

fn pause_funded_request(runtime: &mut Runtime, request_id: &str) -> TestResult<FundingGate> {
    let (arrived_tx, arrived) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let request_id = request_id.to_owned();
    Arc::get_mut(&mut runtime.kernel)
        .ok_or("exclusive test kernel")?
        .install_caller_execution_checkpoint_hook(Arc::new(move |checkpoint, operation| {
            if checkpoint != CallerExecutionCheckpoint::BeforeShareAdmission
                || operation.binding().request_id().as_str() != request_id
                || operation.state() != AdmissionOperationState::BudgetAuthorized
            {
                return;
            }
            assert!(arrived_tx.send(()).is_ok(), "funding observer disconnected");
            let receiver = release_rx.lock().unwrap_or_else(|error| panic!("{error}"));
            assert!(
                receiver.recv_timeout(Duration::from_secs(30)).is_ok(),
                "funding gate was not released"
            );
        }));
    Ok(FundingGate { arrived, release })
}

#[test]
fn a_later_funded_sibling_cannot_displace_an_existing_caller_owner() -> TestResult {
    let fixture = Fixture::with_nonce_ttl(300)?;
    let mut runtime = fixture.open()?;
    let siblings = Siblings::new(&fixture, &mut runtime)?;
    let gate = pause_funded_request(&mut runtime, "pending-share-second")?;
    // Preflight before the competing owner exists, then pause the execution
    // after its executable hold commits but before its sibling-share check.
    let second = request(&siblings.second, "pending-share-second")?;
    let second = with_nonce(&second, &preflight(&runtime, &second)?);
    let first = reserve_child(&runtime, &request(&siblings.first, "pending-share-first")?)?;
    let (settled, newcomer, pending_response) = std::thread::scope(|scope| -> TestResult<_> {
        let pending = scope.spawn(|| runtime.kernel.reserve_caller_execution_blocking(&second));
        let arrived = gate.arrived.recv_timeout(Duration::from_secs(30));
        let checked = match arrived {
            Ok(()) => (|| -> TestResult<_> {
                let settled = reconcile(&runtime, &first)?;
                let newcomer = runtime.kernel.reserve_caller_execution_blocking(&request(
                    &siblings.first,
                    "newcomer-during-pending-share",
                )?)?;
                Ok((settled, newcomer))
            })(),
            Err(error) => Err(error.into()),
        };
        // Always unpark before reporting any failure, including reconciliation
        // errors, so scope cleanup never waits on a stranded worker.
        let released = gate.release.send(());
        let pending_response = pending.join().map_err(|_| "pending reservation panicked")?;
        released?;
        let (settled, newcomer) = checked?;
        Ok((settled, newcomer, pending_response?))
    })?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_state(&fixture, &first, "completed")?;
    assert_eq!(grant_quota(&runtime, &first)?, (0, 1));
    assert_eq!(newcomer.verdict, Verdict::Deny, "{:?}", newcomer.reason);
    assert!(newcomer
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("sibling-sum")));
    // Once the earlier owner settles, the later funded reservation can proceed.
    assert_eq!(
        pending_response.verdict,
        Verdict::Allow,
        "{:?}",
        pending_response.reason
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn an_interrupted_funded_caller_is_compensated_without_displacing_a_reserved_owner() -> TestResult {
    let fixture = Fixture::with_nonce_ttl(300)?;
    let (siblings, first, second) = {
        let mut runtime = fixture.open()?;
        let siblings = Siblings::new(&fixture, &mut runtime)?;
        Arc::get_mut(&mut runtime.kernel)
            .ok_or("exclusive test kernel")?
            .install_caller_execution_checkpoint_hook(Arc::new(|checkpoint, operation| {
                assert!(
                    checkpoint != CallerExecutionCheckpoint::BeforeShareAdmission
                        || operation.binding().request_id().as_str() != "interrupted-funded-caller"
                        || operation.state() != AdmissionOperationState::BudgetAuthorized,
                    "injected interruption after funding"
                );
            }));
        let second = request(&siblings.second, "interrupted-funded-caller")?;
        let second = with_nonce(&second, &preflight(&runtime, &second)?);
        let first = reserve_child(&runtime, &request(&siblings.first, "uninterrupted-owner")?)?;
        let interrupted = std::thread::scope(|scope| {
            scope
                .spawn(|| runtime.kernel.reserve_caller_execution_blocking(&second))
                .join()
        });
        assert!(
            interrupted.is_err(),
            "the harness must reach the funded checkpoint"
        );
        assert_state(&fixture, &second, "budget_authorized")?;
        assert_state(&fixture, &first, "ready_to_dispatch")?;
        assert_eq!(grant_quota(&runtime, &second)?, (1, 0));
        (siblings, first, second)
    };
    let mut runtime = fixture.open_with_reconcile(false)?;
    siblings.configure(&fixture, &mut runtime)?;
    runtime.kernel.reconcile_durable_admission_startup()?;
    assert_state(&fixture, &second, "compensated_before_dispatch")?;
    assert_eq!(grant_quota(&runtime, &second)?, (0, 0));
    assert_state(&fixture, &first, "ready_to_dispatch")?;
    assert_eq!(grant_quota(&runtime, &first)?, (1, 0));
    assert_eq!(reconcile(&runtime, &first)?.verdict, Verdict::Allow);
    let _next = reserve_child(
        &runtime,
        &request(&siblings.second, "after-funded-recovery")?,
    )?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
