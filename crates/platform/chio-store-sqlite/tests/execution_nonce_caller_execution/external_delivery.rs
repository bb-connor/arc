//! External effects require a committed kernel authorization and durable executor claim.

use super::*;
use chio_kernel::admission_operation::{AdmissionIdentifier, AdmissionOperationStore};
use chio_kernel::caller_delivery::CallerDeliveryError;
use chio_kernel::KernelError;
use chio_store_sqlite::caller_execution_ledger::CallerExecutionLedgerError;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn an_external_effect_with_a_lost_report_cannot_be_refunded_at_nonce_expiry() -> TestResult {
    let (fixture, executor_key) = super::authenticated::fixture()?;
    let effect = fixture.directory.path().join("external-effect");
    let ledger = crate::authenticated::ledger(&fixture)?;
    let execution = {
        let runtime = fixture.open()?;
        let execution = reserve(&fixture, &runtime, "external-effect-report-lost")?;
        let observed_at_ms =
            u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        let selector = AdmissionIdentifier::try_new("request_id", execution.request_id.clone())?;
        let (operation, _) = runtime
            .authority
            .admission_operation_store()
            .load_unambiguous_retained_tool_request(
                &selector,
                &runtime.authority.mutation_fence(),
                observed_at_ms,
            )?
            .ok_or("retained caller operation")?;
        let reservation = runtime
            .authority
            .admission_operation_store()
            .load_execution_nonce_reservation(
                operation.binding().operation_id(),
                &runtime.authority.mutation_fence(),
                observed_at_ms,
            )?
            .ok_or("physical nonce reservation")?;
        assert_eq!(
            canonical(reservation.signed_nonce())?,
            canonical(execution.execution_nonce.as_ref().ok_or("reserved nonce")?)?,
            "the effect follows the actual authority-issued reservation"
        );

        let authorization = super::authenticated::start(&runtime, &execution)?;
        assert_eq!(
            grant_quota(&runtime, &execution)?,
            (0, 1),
            "capture precedes effect"
        );
        let _lost_report = ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &executor_key,
            || {
                let write_effect = || -> std::io::Result<()> {
                    let mut external = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&effect)?;
                    external.write_all(b"external effect committed\n")?;
                    external.sync_all()
                };
                write_effect().map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                Ok(report())
            },
        )?;
        assert!(effect.metadata()?.len() > 0);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        execution
    };
    let expiry = u64::try_from(
        execution
            .execution_nonce
            .as_ref()
            .ok_or("reserved nonce")?
            .expires_at(),
    )?;
    let _clock =
        chio_test_support::clock::scope_unix_secs(expiry.checked_add(1).ok_or("expiry overflow")?);
    let runtime = fixture.open()?;
    assert!(
        effect.metadata()?.len() > 0,
        "the external effect survives restart"
    );
    let retained_usage = grant_quota(&runtime, &execution)?;
    let mut repeated = execution.clone();
    repeated.request_id = "external-effect-second-operation".into();
    repeated.execution_nonce = None;
    let second = runtime
        .kernel
        .reserve_caller_execution_blocking(&repeated)?;
    assert_eq!(
        (retained_usage, second.verdict),
        ((0, 1), Verdict::Deny),
        "report loss and expiry must retain capture and deny another call under the same quota"
    );
    assert_state(&fixture, &execution, "awaiting_caller_report")?;
    Ok(())
}

#[test]
fn altered_start_authorization_cannot_claim_or_execute() -> TestResult {
    let (fixture, executor_key) = super::authenticated::fixture()?;
    let ledger_path = fixture.directory.path().join("executor.db");
    let ledger = crate::authenticated::ledger(&fixture)?;
    let runtime = fixture.open()?;
    let execution = reserve(&fixture, &runtime, "altered-caller-start")?;
    let authorization = super::authenticated::start(&runtime, &execution)?;
    let mut altered = authorization.clone();
    altered.authorization.committed.execution_nonce_id =
        AdmissionIdentifier::try_new("execution_nonce_id", "substituted-nonce")?;
    let effects = std::sync::atomic::AtomicUsize::new(0);
    let result = ledger.execute_once(
        &altered,
        &fixture.signer.public_key(),
        &authorization.authorization.invocation,
        &executor_key,
        || {
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(report())
        },
    );
    assert!(matches!(
        result,
        Err(CallerExecutionLedgerError::Authentication(
            CallerDeliveryError::Signature
        ))
    ));
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    let connection = rusqlite::Connection::open(&ledger_path)?;
    let claims: i64 =
        connection.query_row("SELECT count(*) FROM caller_executor_claims", [], |row| {
            row.get(0)
        })?;
    assert_eq!(claims, 0);
    let delivery = ledger.execute_once(
        &authorization,
        &fixture.signer.public_key(),
        &authorization.authorization.invocation,
        &executor_key,
        || {
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(report())
        },
    )?;
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let settled = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &delivery)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_state(&fixture, &execution, "completed")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
