use super::*;

#[test]
fn live_issuance_does_not_occupy_a_recovery_page() -> TestResult {
    let mut fixture = prepared_nonce_fixture(None)?;
    issue(&mut fixture)?;
    // Reopening makes the old coordinator's claim eligible for recovery.
    let fixture = lifecycle::reopen(fixture)?;
    let store = &fixture.fixture.store;
    let later = prepared_operation(
        &fixture.fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "later-recovery-work",
        "later-capability",
    );
    store.begin(&later, &fixture.fixture.fence, now_ms())?;
    assert_eq!(store.list_recoverable(now_ms(), 1)?, vec![later.clone()]);
    let expires = u64::try_from(fixture.reservation.signed_nonce().expires_at())? * 1_000;
    let mut expected = vec![later, fixture.operation];
    expected.sort_by(|left, right| {
        left.binding()
            .operation_id()
            .cmp(right.binding().operation_id())
    });
    assert_eq!(store.list_recoverable(expires, 2)?, expected);
    Ok(())
}
