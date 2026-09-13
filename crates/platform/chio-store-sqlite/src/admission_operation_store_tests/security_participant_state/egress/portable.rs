//! Exercise the portable trait against actual SQLite custody and snapshot reads.
use super::*;
use chio_kernel::admission_operation::{
    NativeSecurityAuthorityBindingV1, NativeSecurityEgressContext, NativeSecurityEgressHistoryV1,
};

fn context<'a>(
    pending: &'a Pending,
    binding: &'a NativeSecurityAuthorityBindingV1,
) -> NativeSecurityEgressContext<'a> {
    NativeSecurityEgressContext {
        operation: &pending.operation,
        lease: &pending.lease,
        binding,
        security_context: &pending.context,
        request: &pending.request,
        trusted_now_unix_ms: now_ms(),
    }
}

fn read(fixture: &Fixture, pending: &Pending) -> AnchoredTestResult<NativeSecurityEgressHistoryV1> {
    let port: &dyn AdmissionOperationStore = &fixture.store;
    let (operation, history) = port
        .load_native_security_egress(
            pending.operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("operation absent")?;
    assert_eq!(operation, pending.operation);
    Ok(history.ok_or("egress history absent")?)
}

#[test]
fn portable_history_distinguishes_missing_operation_from_missing_custody() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let pending = pending(&fixture, "portable-no-history", None)?;
    let before = counts(&fixture)?;
    let port: &dyn AdmissionOperationStore = &fixture.store;
    assert!(port
        .load_native_security_egress(
            &AdmissionOperationId::from_persisted(sha256_hex(b"absent-operation"))?,
            &fixture.fence,
            now_ms(),
        )?
        .is_none());
    let (operation, history) = port
        .load_native_security_egress(
            pending.operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("current operation absent")?;
    assert_eq!(operation, pending.operation);
    assert!(history.is_none());
    assert_eq!(counts(&fixture)?, before);
    Ok(())
}

#[test]
fn portable_commands_preserve_both_phases_and_read_current_operation() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let mut pending = pending(&fixture, "portable-egress", None)?;
    let binding = pending.initialized.admission_binding()?;
    let before = counts(&fixture)?;
    let original_joins = joins(&fixture)?;
    let port: &dyn AdmissionOperationStore = &fixture.store;
    let input = context(&pending, &binding);
    assert_eq!(format!("{input:?}"), "NativeSecurityEgressContext { .. }");
    let fence = port.acquire_native_security_egress(&input, &pending.plan)?;
    let acquired = read(&fixture, &pending)?;
    assert_eq!(acquired.binding, binding);
    assert_eq!(
        acquired.operation_id,
        *pending.operation.binding().operation_id()
    );
    assert_eq!(acquired.acquisition.fence, fence);
    assert_eq!(
        acquired.live_request_hash.as_str(),
        sha256_hex(&canonical_json_bytes(&pending.request)?)
    );
    assert!(acquired.commitment.is_none());
    assert_eq!(
        format!("{:?}", acquired.acquisition),
        "NativeSecurityEgressAcquisitionV1 { .. }"
    );
    let command = commitment(&fence)?;
    let committed = port.commit_native_security_egress(&context(&pending, &binding), &command)?;
    let history = read(&fixture, &pending)?;
    assert_eq!(history.acquisition, acquired.acquisition);
    assert_eq!(history.live_request_hash, acquired.live_request_hash);
    let second = history.commitment.as_ref().ok_or("commitment absent")?;
    assert_eq!(second.commitment, committed);
    assert_eq!(second.acquisition_digest, acquired.acquisition.event_digest);
    assert_ne!(second.event_digest, second.acquisition_digest);
    assert_eq!(
        format!("{second:?}"),
        "NativeSecurityEgressCommitmentV1 { .. }"
    );
    assert_eq!(
        format!("{history:?}"),
        "NativeSecurityEgressHistoryV1 { .. }"
    );
    assert_eq!(
        port.acquire_native_security_egress(&context(&pending, &binding), &pending.plan)?,
        fence
    );
    assert_eq!(
        port.commit_native_security_egress(&context(&pending, &binding), &command)?,
        committed
    );
    assert_eq!(
        counts(&fixture)?,
        (before.0 + 2, before.1 + 2, before.2 + 1)
    );
    assert_eq!(joins(&fixture)?, original_joins);

    // Committed egress is still not dispatch authority. Readback must report a
    // real compensated operation alongside its unchanged historical phases.
    let error = fixture
        .store
        .compare_and_swap(
            &super::command(
                &pending.operation,
                pending.lease.clone(),
                vec![],
                AdmissionOperationState::DispatchCommitted,
                None,
            ),
            now_ms(),
        )
        .err()
        .ok_or("native generic dispatch succeeded")?;
    assert!(error
        .to_string()
        .contains("native security dispatch custody is unsupported"));
    pending.operation = compensation::compensate(&fixture, &pending)?;
    assert_eq!(read(&fixture, &pending)?, history);
    let fixture = reopen(fixture)?;
    assert_eq!(read(&fixture, &pending)?, history);
    Ok(())
}

#[test]
fn portable_commands_recheck_selected_binding_live_material_and_actual_lease() -> AnchoredTestResult
{
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let other = hydrate(&fixture, &imported(&fixture, "other")?)?;
    let pending = pending(&fixture, "portable-substitution", None)?;
    let binding = pending.initialized.admission_binding()?;
    let other_binding = other.admission_binding()?;
    let (_, other_lease) = mutations::setup(&fixture, "portable-other-lease", &pending.context)?;
    let mut changed_request = pending.request.clone();
    changed_request.arguments = serde_json::json!({"substituted": true});
    let changed_context = SecurityInvocationContext::v1(
        pending
            .context
            .as_v1()
            .clone()
            .with_flow_state_generation(pending.plan.expected_context_generation + 1),
    );
    let port: &dyn AdmissionOperationStore = &fixture.store;
    let before = counts(&fixture)?;
    for variant in 0..4 {
        let mut input = context(&pending, &binding);
        match variant {
            0 => input.binding = &other_binding,
            1 => input.request = &changed_request,
            2 => input.lease = &other_lease,
            3 => input.security_context = &changed_context,
            _ => return Err("unexpected substitution variant".into()),
        }
        assert!(
            port.acquire_native_security_egress(&input, &pending.plan)
                .is_err(),
            "variant {variant}"
        );
        assert_eq!(counts(&fixture)?, before);
    }
    let acquired =
        port.acquire_native_security_egress(&context(&pending, &binding), &pending.plan)?;
    let command = commitment(&acquired)?;
    let before = counts(&fixture)?;
    for variant in 0..4 {
        let mut input = context(&pending, &binding);
        match variant {
            0 => input.binding = &other_binding,
            1 => input.request = &changed_request,
            2 => input.lease = &other_lease,
            3 => input.security_context = &changed_context,
            _ => return Err("unexpected substitution variant".into()),
        }
        assert!(
            port.commit_native_security_egress(&input, &command)
                .is_err(),
            "variant {variant}"
        );
        assert_eq!(counts(&fixture)?, before);
    }
    port.commit_native_security_egress(&context(&pending, &binding), &command)?;
    assert!(read(&fixture, &pending)?.commitment.is_some());
    Ok(())
}

#[test]
fn portable_owner_rotation_preserves_history_without_reviving_old_custody() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let mut pending = pending(&fixture, "portable-takeover", None)?;
    let binding = pending.initialized.admission_binding()?;
    let port: &dyn AdmissionOperationStore = &fixture.store;
    let acquired =
        port.acquire_native_security_egress(&context(&pending, &binding), &pending.plan)?;
    let history = read(&fixture, &pending)?;
    let old_fence = fixture.fence.clone();
    let fixture = reopen(fixture)?;
    assert!(fixture.fence.owner_epoch > old_fence.owner_epoch);
    let port: &dyn AdmissionOperationStore = &fixture.store;
    assert!(port
        .load_native_security_egress(
            pending.operation.binding().operation_id(),
            &old_fence,
            now_ms()
        )
        .is_err());
    assert_eq!(read(&fixture, &pending)?, history);
    let before = counts(&fixture)?;
    assert!(port
        .acquire_native_security_egress(&context(&pending, &binding), &pending.plan)
        .is_err());
    assert!(port
        .commit_native_security_egress(&context(&pending, &binding), &commitment(&acquired)?)
        .is_err());
    assert_eq!(counts(&fixture)?, before);
    pending.lease = renew(&fixture, &pending.operation, &pending.lease)?;
    port.commit_native_security_egress(&context(&pending, &binding), &commitment(&acquired)?)?;
    let committed = read(&fixture, &pending)?;
    assert_eq!(committed.acquisition, history.acquisition);
    assert!(committed.commitment.is_some());
    Ok(())
}

#[test]
fn portable_history_survives_expiry_without_renewing_fence_or_lease() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let pending = pending(&fixture, "portable-expiry", None)?;
    let binding = pending.initialized.admission_binding()?;
    let port: &dyn AdmissionOperationStore = &fixture.store;
    let acquired =
        port.acquire_native_security_egress(&context(&pending, &binding), &pending.plan)?;
    let history = read(&fixture, &pending)?;
    let before = counts(&fixture)?;
    let expired = pending.lease.expires_at_unix_ms().div_ceil(1000) * 1000;
    assert!(expired > acquired.expires_at_unix_ms);
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(expired / 1000, std::iter::empty());
    assert_eq!(read(&fixture, &pending)?, history);
    assert!(port
        .acquire_native_security_egress(&context(&pending, &binding), &pending.plan)
        .is_err());
    assert!(port
        .commit_native_security_egress(&context(&pending, &binding), &commitment(&acquired)?)
        .is_err());
    assert_eq!(counts(&fixture)?, before);
    Ok(())
}

#[test]
fn portable_history_rejects_missing_current_catalog_even_without_events() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let pending = pending(&fixture, "portable-catalog", None)?;
    assert_eq!(counts(&fixture)?.0, 0);
    // Corrupt only this disposable test database. A read must not repair it or
    // report missing custody as though current catalog integrity had passed.
    fixture
        .store
        .connection()?
        .execute_batch("DROP TABLE security_participant_egress_events")?;
    let port: &dyn AdmissionOperationStore = &fixture.store;
    assert!(port
        .load_native_security_egress(
            pending.operation.binding().operation_id(),
            &fixture.fence,
            now_ms()
        )
        .is_err());
    assert!(port
        .load_native_security_egress(
            &AdmissionOperationId::from_persisted(sha256_hex(b"absent-operation"))?,
            &fixture.fence,
            now_ms()
        )
        .is_err());
    Ok(())
}
