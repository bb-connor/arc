//! Hostile rows do not acquire invocation custody by sharing an original ID.
//! These tests measure the private read stage, not captured or financed replay.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationV1, NativeOutputEnvelopeBoundsV1, NativeOutputRetentionProfileV1,
};

async fn genuine_selected_original() -> TestResult<(RecoveryFixture, AdmissionOperationV1)> {
    let profile = NativeOutputRetentionProfileV1::new(NativeOutputEnvelopeBoundsV1::new(
        1024 * 1024,
        1024 * 1024,
        1024 * 1024,
        1024 * 1024,
        1,
    )?);
    let fixture =
        semantic::empty_import::native_fixture_from_empty_import_with_retention("write", &profile)
            .await?;
    let request_id = fixture.process.request_id("root", "native-input-genesis")?;
    let (operation, original) = fixture
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("genuine selected genesis original is absent")?;
    original.validate_binding(operation.binding())?;
    assert_eq!(original.native_output_retention(), Some(&profile));
    assert!(original.native_security_authority_binding().is_some());
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
    assert_eq!(captured_invocations(&fixture)?, 0);
    Ok((fixture, operation))
}

#[tokio::test]
async fn selected_original_bounds_raw_read_before_allocation_and_decode() -> TestResult {
    let (fixture, operation) = genuine_selected_original().await?;
    let store = fixture.authority.admission_operation_store();
    let baseline = store.profiled_outcome_read_allocations_for_test(
        operation.binding().operation_id(),
        b"{",
        None,
    )?;
    assert_eq!(baseline, (1024 * 1024, 1024 * 1024, 1, 0));
    let oversized = vec![
        b' ';
        usize::try_from(
            baseline
                .0
                .checked_add(1)
                .ok_or("hostile Raw length overflowed")?
        )?
    ];
    let observed = store.profiled_outcome_read_allocations_for_test(
        operation.binding().operation_id(),
        &oversized,
        None,
    )?;
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
    assert_eq!(captured_invocations(&fixture)?, 0);
    assert_eq!(
        store.load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    assert_eq!(observed.2, 0,
        "private Raw reader allocated hostile bytes beyond the authentic original envelope before decode");
    Ok(())
}

#[tokio::test]
async fn selected_original_bounds_evaluation_read_before_allocation_and_decode() -> TestResult {
    let (fixture, operation) = genuine_selected_original().await?;
    let store = fixture.authority.admission_operation_store();
    let baseline = store.profiled_outcome_read_allocations_for_test(
        operation.binding().operation_id(),
        b"{",
        Some(b"{"),
    )?;
    assert_eq!(baseline, (1024 * 1024, 1024 * 1024, 1, 1));
    let oversized = vec![
        b' ';
        usize::try_from(
            baseline
                .1
                .checked_add(1)
                .ok_or("hostile evaluation length overflowed")?
        )?
    ];
    let observed = store.profiled_outcome_read_allocations_for_test(
        operation.binding().operation_id(),
        b"{",
        Some(&oversized),
    )?;
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
    assert_eq!(captured_invocations(&fixture)?, 0);
    assert_eq!(
        store.load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    assert_eq!(observed.3, 0,
        "private evaluation reader allocated hostile bytes beyond the authentic original envelope before decode");
    Ok(())
}
