//! Executable contract gap for a trusted caller's effect before reconciliation.
//!
//! This harness exercises the documented reserve, execute, report ordering. It
//! is not a qualified external transport: the fixture reads nonce provenance
//! from the authority directly. The future dispatch-start handshake must replace
//! the reservation-only execution step before this can be a passing gate.

use super::*;
use chio_kernel::admission_operation::{AdmissionIdentifier, AdmissionOperationStore};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
#[ignore = "requires durable caller dispatch-start handshake before external effect"]
fn an_external_effect_with_a_lost_report_cannot_be_refunded_at_nonce_expiry() -> TestResult {
    let fixture = Fixture::with_nonce_ttl(300)?;
    let effect = fixture.directory.path().join("external-effect");
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

        // A real local effect outside the kernel's registered server. The
        // trusted caller loses its report before calling reconciliation.
        let mut external = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&effect)?;
        external.write_all(b"external effect committed\n")?;
        external.sync_all()?;
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
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(
        expiry.checked_add(1).ok_or("expiry overflow")?,
        [],
    );
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
    assert_state(&fixture, &execution, "outcome_unknown_after_dispatch")?;
    Ok(())
}
