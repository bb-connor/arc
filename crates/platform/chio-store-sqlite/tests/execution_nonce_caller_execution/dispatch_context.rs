//! Live typed return-context capture, separate from the unfinished external
//! start handshake. These tests never treat a reservation as an effect permit.

use super::*;
use chio_kernel::admission_operation::{
    AdmissionCallerDispatchContextV1, AdmissionIdentifier, AdmissionOperationStore,
};
use chio_kernel::{CallerExecutionCheckpoint, CallerExecutionReport};
use std::sync::Arc;

fn now_ms() -> TestResult<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

fn load(
    runtime: &Runtime,
    request: &ToolCallRequest,
) -> TestResult<AdmissionCallerDispatchContextV1> {
    let now = now_ms()?;
    let store = runtime.authority.admission_operation_store();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &runtime.authority.mutation_fence(),
            now,
        )?
        .ok_or("caller operation")?;
    assert!(operation.dispatch_commit().is_some());
    let frame = store
        .load_caller_dispatch_context(
            operation.binding().operation_id(),
            &runtime.authority.mutation_fence(),
            now,
        )?
        .ok_or("physical kernel-produced caller context")?;
    assert_eq!(
        Some(frame.digest()),
        operation.caller_dispatch_context_digest()
    );
    Ok(frame)
}

#[test]
fn caller_report_retains_typed_private_context_with_capture_and_exact_restart_replay() -> TestResult
{
    let fixture = Fixture::new()?;
    let (execution, bytes, receipt, old_fence) = {
        let runtime = fixture.open()?;
        let execution = reserve(&fixture, &runtime, "caller-context-restart")?;
        let raw = rusqlite::Connection::open(fixture.database())?;
        assert_eq!(
            raw.query_row(
                "SELECT count(*) FROM admission_operation_caller_contexts",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        let completed = reconcile(&runtime, &execution)?;
        assert_eq!(completed.verdict, Verdict::Allow, "{completed:#?}");
        assert!(completed.receipt.verify_signature()?);
        let frame = load(&runtime, &execution)?;
        let payload: serde_json::Value = serde_json::from_slice(frame.kernel_context_json())?;
        assert_eq!(payload["schema"], "chio.kernel-caller-return-context.v3");
        let participants = payload["participants"]
            .as_object()
            .ok_or("frozen participants")?;
        assert_eq!(participants.len(), 18);
        let framed: serde_json::Value = serde_json::from_slice(frame.canonical_bytes())?;
        for field in ["provider_attempt", "budget_hold_id", "execution_nonce_id"] {
            assert_eq!(participants[field], framed[field]);
        }
        assert!(participants["execution_nonce_issuance_digest"].is_string());
        assert!(participants["execution_nonce_preflight_digest"].is_string());
        assert_eq!(
            payload["receipt_signing_identity"]["public_key"],
            serde_json::to_value(&completed.receipt.kernel_key)?
        );
        assert_eq!(
            payload["receipt_signing_identity"]["crypto_floor"],
            "allow_classical"
        );
        assert_eq!(payload["request_id"], execution.request_id);
        assert_eq!(payload["matched_grant_index"], 0);
        assert!(payload["pre_invocation_guard_evidence"].is_array());
        let private = std::str::from_utf8(frame.kernel_context_json())?;
        assert!(
            !private.contains("caller_reported"),
            "return observations cannot become admission facts"
        );
        assert!(!private.contains(&serde_json::to_string(
            &execution.execution_nonce.as_ref().ok_or("nonce")?.signature
        )?));
        assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(
            raw.query_row(
                "SELECT count(*) FROM admission_operation_caller_contexts",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            1
        );
        (
            execution,
            frame.canonical_bytes().to_vec(),
            completed.receipt,
            runtime.authority.mutation_fence(),
        )
    };
    let runtime = fixture.open()?;
    let frame = load(&runtime, &execution)?;
    assert_eq!(frame.canonical_bytes(), bytes);
    let replay = reconcile(&runtime, &execution)?;
    assert_eq!(canonical(&replay.receipt)?, canonical(&receipt)?);
    assert_eq!(load(&runtime, &execution)?.canonical_bytes(), bytes);
    let wire: serde_json::Value = serde_json::from_slice(&bytes)?;
    let operation_id = chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
        wire["operation_id"].as_str().ok_or("framed operation id")?,
    )?;
    assert!(runtime
        .authority
        .admission_operation_store()
        .load_caller_dispatch_context(&operation_id, &old_fence, now_ms()?)
        .is_err());
    assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn caller_context_capture_rejects_out_of_band_schema_changes() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let execution = reserve(&fixture, &runtime, "caller-context-insert-failure")?;
    let raw = rusqlite::Connection::open(fixture.database())?;
    raw.execute_batch("CREATE TRIGGER fail_caller_context_insert BEFORE INSERT ON admission_operation_caller_contexts
        BEGIN SELECT RAISE(ABORT, 'injected caller context insertion failure'); END;")?;
    // A second connection is not a valid fault-injection port. The live owner
    // must reject its write before reaching the caller-context capture path.
    let refused = reconcile(&runtime, &execution);
    assert!(
        refused.as_ref().is_err_and(|error| error
            .to_string()
            .contains("authority database changed outside its serving-owner connection")),
        "wrong rejection: {refused:#?}"
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM admission_operation_caller_contexts",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_state(&fixture, &execution, "ready_to_dispatch")?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    drop(runtime);
    // Reopening must not legitimize the changed schema either.
    let startup = fixture.open_with_reconcile(false);
    assert!(startup.as_ref().is_err_and(|error| error
        .to_string()
        .contains("admission operation schema differs from the canonical definition")));
    drop(startup);
    raw.execute_batch("DROP TRIGGER fail_caller_context_insert")?;
    drop(raw);
    let runtime = fixture.open_with_reconcile(false)?;
    assert_eq!(runtime.kernel.reconcile_recoverable_admissions()?, 0);
    assert_state(&fixture, &execution, "ready_to_dispatch")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (1, 0));
    let completed = reconcile(&runtime, &execution)?;
    assert_eq!(completed.verdict, Verdict::Allow, "{completed:#?}");
    load(&runtime, &execution)?;
    assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn caller_context_survives_interruption_after_capture_before_report_recording() -> TestResult {
    let fixture = Fixture::new()?;
    let (execution, frame_bytes) = {
        let mut runtime = fixture.open()?;
        let execution = reserve(&fixture, &runtime, "caller-context-interrupted")?;
        Arc::get_mut(&mut runtime.kernel)
            .ok_or("unshared kernel")?
            .install_caller_execution_checkpoint_hook(Arc::new(|point, _| {
                if point == CallerExecutionCheckpoint::DispatchCommitted {
                    panic!("injected interruption after caller context capture");
                }
            }));
        let kernel = runtime.kernel.clone();
        let nonce = execution.execution_nonce.clone().ok_or("nonce")?;
        let arguments = execution.arguments.clone();
        assert!(
            std::thread::spawn(move || kernel.reconcile_caller_execution_blocking(
                &nonce,
                &arguments,
                CallerExecutionReport {
                    output: serde_json::json!({"not_recorded": true}),
                    realized_cost: None
                },
            ))
            .join()
            .is_err()
        );
        let bytes = load(&runtime, &execution)?.canonical_bytes().to_vec();
        assert!(!std::str::from_utf8(&bytes)?.contains("not_recorded"));
        assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
        (execution, bytes)
    };
    let runtime = fixture.open()?;
    assert_state(&fixture, &execution, "outcome_unknown_after_dispatch")?;
    assert_eq!(load(&runtime, &execution)?.canonical_bytes(), frame_bytes);
    assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
