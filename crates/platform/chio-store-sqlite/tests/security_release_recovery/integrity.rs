//! Physical checkpoint integrity and configuration-independent recovery.
use super::*;
use chio_kernel::tool_outcome::{SecurityReleaseRecordV1, ToolOutcomeStore};

fn completed_fixture() -> TestResult<(Fixture, Runtime, ToolCallRequest)> {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let hook = Arc::new(ReleaseHook {
        allowed: true,
        releases: Arc::new(AtomicUsize::new(0)),
    });
    let runtime = open(&fixture, hook, true)?;
    let request = fixture.request(&runtime, "release-integrity")?;
    let response = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request)?)?;
    assert_eq!(response.verdict, chio_kernel::Verdict::Allow);
    Ok((fixture, runtime, request))
}

#[test]
fn checkpoint_sql_guards_reject_replace_update_and_delete() -> TestResult {
    let (fixture, runtime, request) = completed_fixture()?;
    let connection = rusqlite::Connection::open(fixture.database())?;
    connection.execute_batch("PRAGMA recursive_triggers = OFF")?;
    for sql in [
        "INSERT OR REPLACE INTO tool_outcome_security_releases SELECT * FROM tool_outcome_security_releases",
        "UPDATE tool_outcome_security_releases SET acknowledged_at_unix_ms = acknowledged_at_unix_ms + 1",
        "DELETE FROM tool_outcome_security_releases",
    ] { assert!(connection.execute(sql, []).is_err(), "{sql}"); }
    drop(connection);
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request)?)?;
    assert_eq!(replay.verdict, chio_kernel::Verdict::Allow);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn checkpoint_omission_and_rewritten_bindings_fail_on_reopen() -> TestResult {
    for mutation in ["delete", "commitment", "digest", "recommit"] {
        let (fixture, runtime, _) = completed_fixture()?;
        drop(runtime);
        let connection = rusqlite::Connection::open(fixture.database())?;
        let trigger = if mutation == "delete" {
            "tool_outcome_security_releases_no_delete"
        } else {
            "tool_outcome_security_releases_no_update"
        };
        let ddl: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name = ?1",
            [trigger],
            |row| row.get(0),
        )?;
        connection.execute_batch(&format!("DROP TRIGGER {trigger}"))?;
        if mutation == "delete" {
            connection.execute("DELETE FROM tool_outcome_security_releases", [])?;
        } else {
            let bytes: Vec<u8> = connection.query_row(
                "SELECT canonical_record FROM tool_outcome_security_releases",
                [],
                |row| row.get(0),
            )?;
            let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
            if mutation == "commitment" {
                value["dispatch_commitment_id"] = serde_json::json!("dispatch-commitment:foreign");
            } else {
                let time = value["acknowledged_at_unix_ms"]
                    .as_u64()
                    .ok_or("checkpoint time")?;
                value["acknowledged_at_unix_ms"] =
                    serde_json::json!(time.checked_add(1).ok_or("time overflow")?);
            }
            let canonical = chio_core::canonical_json_bytes(&value)?;
            if mutation == "recommit" {
                // Match every local field and its digest. The immutable global
                // admission commitment must still reject the replacement.
                let digest =
                    chio_core::sha256_hex(&chio_core::canonical_json_bytes(&serde_json::json!({
                        "schema": "chio.security-release-participant.v1", "record": value
                    }))?);
                connection.execute("UPDATE tool_outcome_security_releases SET canonical_record = ?1, participant_digest = ?2, acknowledged_at_unix_ms = acknowledged_at_unix_ms + 1", rusqlite::params![canonical, digest])?;
            } else {
                connection.execute(
                    "UPDATE tool_outcome_security_releases SET canonical_record = ?1",
                    [canonical],
                )?;
            }
        }
        connection.execute_batch(&ddl)?;
        drop(connection);
        assert!(
            fixture.open_with_reconcile(false).is_err(),
            "tampered checkpoint accepted: {mutation}"
        );
    }
    Ok(())
}

#[test]
fn decoded_checkpoint_is_exact_data_not_a_live_owner() -> TestResult {
    let (fixture, runtime, request) = completed_fixture()?;
    let operation = chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
        operation_state(&fixture, &request.request_id)?
            .ok_or("operation")?
            .0,
    )?;
    let checkpoint = runtime
        .authority
        .tool_outcome_store()
        .lookup_security_release(&operation)?
        .ok_or("checkpoint")?;
    let canonical = checkpoint.canonical_bytes()?;
    assert_eq!(
        SecurityReleaseRecordV1::from_canonical_bytes(&canonical)?,
        checkpoint
    );
    let mut value: serde_json::Value = serde_json::from_slice(&canonical)?;
    value["unexpected_authority"] = serde_json::json!(true);
    assert!(
        SecurityReleaseRecordV1::from_canonical_bytes(&chio_core::canonical_json_bytes(&value)?)
            .is_err()
    );
    assert!(SecurityReleaseRecordV1::from_canonical_bytes(&vec![b' '; 8193]).is_err());
    assert!(
        SecurityReleaseRecordV1::from_canonical_bytes(&serde_json::to_vec_pretty(&checkpoint)?)
            .is_err()
    );
    Ok(())
}

#[test]
fn checkpoint_survives_authorized_payload_compaction_and_owner_rotation() -> TestResult {
    let (fixture, runtime, request) = completed_fixture()?;
    let operation = chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
        operation_state(&fixture, &request.request_id)?
            .ok_or("operation")?
            .0,
    )?;
    let outcomes = runtime.authority.tool_outcome_store();
    let checkpoint = outcomes
        .lookup_security_release(&operation)?
        .ok_or("checkpoint")?;
    let cutoff = checkpoint
        .acknowledged_at_unix_ms()
        .checked_add(1)
        .ok_or("cutoff")?;
    let summary = outcomes.compact_retained_invocation_blobs(
        cutoff,
        &runtime.authority.mutation_fence(),
        cutoff,
    )?;
    assert_eq!(summary.compacted, 1);
    assert_eq!(summary.retained_live, 0);
    assert_eq!(
        outcomes.lookup_security_release(&operation)?,
        Some(checkpoint.clone())
    );
    assert!(outcomes
        .load_raw_invocation_by_operation(&operation)
        .is_err());
    drop(outcomes);
    drop(runtime);
    // Preserve the admitted security profile so the retry reaches the
    // compacted-payload boundary, not the earlier configuration-drift denial.
    let releases = Arc::new(AtomicUsize::new(0));
    let runtime = open(
        &fixture,
        Arc::new(ReleaseHook {
            allowed: true,
            releases: releases.clone(),
        }),
        false,
    )?;
    assert_eq!(
        runtime
            .authority
            .tool_outcome_store()
            .lookup_security_release(&operation)?,
        Some(checkpoint)
    );
    // Retained release evidence is not a replacement for a compacted payload.
    runtime.kernel.reconcile_durable_admission_startup()?;
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request)?);
    assert!(
        replay.is_err(),
        "compacted payload replay returned {replay:?}"
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn removing_hook_configuration_cannot_erase_a_pending_release() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let runtime = open(
        &fixture,
        Arc::new(ReleaseHook {
            allowed: false,
            releases: Arc::new(AtomicUsize::new(0)),
        }),
        true,
    )?;
    let request = fixture.request(&runtime, "release-with-removed-hook")?;
    assert_withheld(
        runtime
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&request, &context(&request)?),
    );
    let original = operation_state(&fixture, &request.request_id)?.ok_or("pending operation")?;
    assert_eq!(original.1, "finalizing");
    let operation =
        chio_kernel::admission_operation::AdmissionOperationId::from_persisted(original.0.clone())?;
    drop(runtime);
    let runtime = fixture.open_with_reconcile(false)?;
    let recovery = runtime.kernel.reconcile_durable_admission_startup();
    assert!(
        matches!(
            &recovery,
            Err(KernelError::DurableAdmission(reason))
                if reason == "recovered post-return plan does not match durable admission"
        ),
        "changed security profile startup returned {recovery:?}"
    );
    assert!(runtime
        .kernel
        .evaluate_tool_call_blocking(&request)
        .is_err());
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        operation_state(&fixture, &request.request_id)?,
        Some(original.clone())
    );
    assert!(runtime
        .authority
        .tool_outcome_store()
        .lookup_security_release(&operation)?
        .is_none());
    drop(runtime);
    // Restoring the profile must expose the same unresolved obligation, not
    // consume a fresh, now-permissive owner to manufacture its checkpoint.
    let fresh_releases = Arc::new(AtomicUsize::new(0));
    let runtime = open(
        &fixture,
        Arc::new(ReleaseHook {
            allowed: true,
            releases: fresh_releases.clone(),
        }),
        false,
    )?;
    assert!(matches!(
        runtime.kernel.reconcile_durable_admission_startup(),
        Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(_))
    ));
    assert!(runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request)?,)
        .is_err());
    assert_eq!(
        operation_state(&fixture, &request.request_id)?,
        Some(original)
    );
    assert!(runtime
        .authority
        .tool_outcome_store()
        .lookup_security_release(&operation)?
        .is_none());
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(fresh_releases.load(Ordering::SeqCst), 0);
    Ok(())
}

struct NoLifecycle;
impl SecurityPreDispatchHook for NoLifecycle {
    fn name(&self) -> &str {
        "no-lifecycle"
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

#[test]
fn acknowledgement_time_follows_the_native_release_callback() -> TestResult {
    use std::sync::atomic::AtomicU64;
    struct TimedRelease(Arc<AtomicU64>);
    impl SecurityRequestLifecyclePermit for TimedRelease {
        fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError> {
            std::thread::sleep(std::time::Duration::from_millis(20));
            let elapsed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| KernelError::Internal(error.to_string()))?;
            let at = u64::try_from(elapsed.as_millis())
                .map_err(|error| KernelError::Internal(error.to_string()))?;
            self.0.store(at, Ordering::SeqCst);
            Ok(())
        }
    }
    impl SecurityPreDispatchHook for TimedRelease {
        fn name(&self) -> &str {
            "timed-release"
        }
        fn acquire_request_lifecycle(
            &self,
            _: &SecurityPreDispatchContext<'_>,
        ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, KernelError> {
            Ok(Some(Box::new(Self(self.0.clone()))))
        }
        fn commit(
            &self,
            _: &SecurityPreDispatchContext<'_>,
        ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
            Ok(None)
        }
    }
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let mut runtime = fixture.open_with_reconcile(false)?;
    let completed_at = Arc::new(AtomicU64::new(0));
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique kernel")?;
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(TimedRelease(completed_at.clone())));
    kernel.reconcile_durable_admission_startup()?;
    let request = fixture.request(&runtime, "timed-security-release")?;
    let response = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request)?)?;
    assert_eq!(response.verdict, chio_kernel::Verdict::Allow);
    let operation = chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
        operation_state(&fixture, &request.request_id)?
            .ok_or("operation")?
            .0,
    )?;
    let checkpoint = runtime
        .authority
        .tool_outcome_store()
        .lookup_security_release(&operation)?
        .ok_or("checkpoint")?;
    let finished = completed_at.load(Ordering::SeqCst);
    assert!(finished > 0);
    assert!(checkpoint.acknowledged_at_unix_ms() >= finished);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn a_frozen_no_owner_requirement_does_not_create_release_authority() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let mut runtime = fixture.open_with_reconcile(false)?;
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique kernel")?;
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(NoLifecycle));
    kernel.reconcile_durable_admission_startup()?;
    let request = fixture.request(&runtime, "security-without-lifecycle")?;
    let response = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request)?)?;
    assert_eq!(response.verdict, chio_kernel::Verdict::Allow);
    let operation = chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
        operation_state(&fixture, &request.request_id)?
            .ok_or("operation")?
            .0,
    )?;
    assert!(runtime
        .authority
        .tool_outcome_store()
        .lookup_security_release(&operation)?
        .is_none());
    assert!(!runtime
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(&operation)?
        .ok_or("raw outcome")?
        .requires_security_release()?);
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request)?)?;
    assert_eq!(replay.receipt.id, response.receipt.id);
    Ok(())
}
