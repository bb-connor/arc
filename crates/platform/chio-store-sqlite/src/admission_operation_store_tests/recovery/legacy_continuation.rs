//! A skipped physical prefix must not hide a usable legacy result.
use super::deferred_status::defer;
use super::*;

#[test]
fn legacy_selection_advances_past_a_deterministic_dormant_prefix() -> AnchoredTestResult {
    let at = 1_800_001_300_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let fixture = fixture();
    let mut operations = [
        prepared_operation(
            &fixture.fence,
            AdmissionOperationKind::ToolDispatch,
            "legacy-continuation-a",
            "legacy-continuation-capability-a",
        ),
        prepared_operation(
            &fixture.fence,
            AdmissionOperationKind::ToolDispatch,
            "legacy-continuation-b",
            "legacy-continuation-capability-b",
        ),
    ];
    operations.sort_by(|left, right| {
        left.binding()
            .operation_id()
            .cmp(right.binding().operation_id())
    });
    let [dormant, usable] = operations;
    fixture.store.begin(&dormant, &fixture.fence, at)?;
    fixture.store.begin(&usable, &fixture.fence, at)?;
    let (_, status) = defer(&fixture, &dormant, at)?;
    let query_at = at + 2_000;
    assert!(status.quarantined);
    assert!(status.deferral.retry_not_before_unix_ms > query_at);
    assert!(dormant.binding().operation_id() < usable.binding().operation_id());
    let connection = fixture.store.connection()?;
    let before = admission_commit_rows(&connection)?;
    drop(connection);
    let anchor = fixture.authority.anchor_generation()?;

    assert_eq!(fixture.store.list_recoverable(query_at, 1)?, vec![usable]);
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(dormant.binding().operation_id())?,
        Some(dormant)
    );
    let connection = fixture.store.connection()?;
    assert_eq!(admission_commit_rows(&connection)?, before);
    drop(connection);
    assert_eq!(fixture.authority.anchor_generation()?, anchor);
    Ok(())
}
