//! Legacy usable results retain physical bounds and exact custody validation.
use super::deferred_status::defer;
use super::*;
use chio_kernel::admission_operation::{
    AdmissionRecoveryDeferralClear, AdmissionRecoveryPageQuery,
};

const CAPACITY_MESSAGE: &str =
    "legacy recovery selection exceeds the bounded scan; use cursor recovery";

fn read_state(fixture: &Fixture) -> AnchoredTestResult<(Vec<Vec<Vec<Value>>>, u64)> {
    let connection = fixture.store.connection()?;
    let mut data = Vec::new();
    for sql in [
        "SELECT * FROM admission_operations ORDER BY operation_id",
        "SELECT * FROM admission_operation_recovery_deferrals ORDER BY operation_id",
        "SELECT * FROM admission_operation_commits ORDER BY commit_sequence",
        "SELECT * FROM authority_global_commits ORDER BY commit_sequence",
        "SELECT * FROM admission_operation_commit_meta ORDER BY singleton",
        "SELECT * FROM authority_global_commit_meta ORDER BY singleton",
    ] {
        let mut statement = connection.prepare(sql)?;
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|index| row.get(index))
                    .collect::<rusqlite::Result<Vec<Value>>>()
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        data.push(rows);
    }
    Ok((data, fixture.authority.anchor_generation()?))
}

#[test]
fn legacy_recovery_exact256_end_and_unresolved_tail_are_distinct_without_effects(
) -> AnchoredTestResult {
    let at = 1_800_001_000_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let fixture = fixture();
    let mut operations = (0..257)
        .map(|index| {
            prepared_operation(
                &fixture.fence,
                AdmissionOperationKind::ToolDispatch,
                &format!("legacy-bound-request-{index:03}"),
                &format!("legacy-bound-capability-{index:03}"),
            )
        })
        .collect::<Vec<_>>();
    operations.sort_by(|left, right| {
        left.binding()
            .operation_id()
            .cmp(right.binding().operation_id())
    });
    let (tail, earlier) = operations.split_last().ok_or("operations")?;
    let mut first_status = None;
    for operation in earlier {
        fixture.store.begin(operation, &fixture.fence, at)?;
        let deferred = defer(&fixture, operation, at)?;
        if first_status.is_none() {
            first_status = Some(deferred);
        }
    }
    let before = read_state(&fixture)?;
    assert!(fixture.store.list_recoverable(at + 2_000, 1)?.is_empty());
    assert_eq!(
        read_state(&fixture)?,
        before,
        "exact end is a read only result"
    );

    fixture.store.begin(tail, &fixture.fence, at)?;
    let before = read_state(&fixture)?;
    assert!(matches!(fixture.store.list_recoverable(at + 2_000, 1),
        Err(AdmissionOperationStoreError::Unavailable(reason)) if reason == CAPACITY_MESSAGE));
    assert_eq!(
        read_state(&fixture)?,
        before,
        "unresolved tail creates no claims or history"
    );
    let page = fixture.store.recovery_page(AdmissionRecoveryPageQuery {
        not_after_unix_ms: at + 2_000,
        candidate_limit: 256,
        after_operation_id: None,
        fence: &fixture.fence,
    })?;
    assert_eq!(page.scanned_candidates, 256);
    assert!(page.operations.is_empty());
    let cursor = page.next_cursor.ok_or("physical page cursor")?;
    let final_page = fixture.store.recovery_page(AdmissionRecoveryPageQuery {
        not_after_unix_ms: at + 2_000,
        candidate_limit: 256,
        after_operation_id: Some(&cursor),
        fence: &fixture.fence,
    })?;
    assert_eq!(final_page.scanned_candidates, 1);
    assert_eq!(final_page.operations, vec![tail.clone()]);
    assert!(final_page.next_cursor.is_none());
    assert_eq!(
        read_state(&fixture)?,
        before,
        "cursor behavior and read effects are unchanged"
    );

    let first = earlier.first().ok_or("first operation")?;
    let (lease, status) = first_status.ok_or("first status")?;
    fixture
        .store
        .clear_recovery_deferral(AdmissionRecoveryDeferralClear {
            operation: first,
            lease: Some(&lease),
            expected: &status,
            fence: &fixture.fence,
            trusted_now_unix_ms: at,
        })?;
    let before = read_state(&fixture)?;
    assert_eq!(
        fixture.store.list_recoverable(at + 2_000, 1)?,
        vec![first.clone()]
    );
    assert!(matches!(fixture.store.list_recoverable(at + 2_000, 2),
        Err(AdmissionOperationStoreError::Unavailable(reason)) if reason == CAPACITY_MESSAGE));
    assert_eq!(
        read_state(&fixture)?,
        before,
        "capacity refusal returns no partial result or write"
    );
    Ok(())
}

#[test]
fn legacy_recovery_corrupt_dormant_candidate_refuses_before_skipping() -> AnchoredTestResult {
    let at = 1_800_001_100_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let fixture = fixture();
    let mut operations = (0..2)
        .map(|index| {
            prepared_operation(
                &fixture.fence,
                AdmissionOperationKind::ToolDispatch,
                &format!("legacy-corrupt-request-{index}"),
                &format!("legacy-corrupt-capability-{index}"),
            )
        })
        .collect::<Vec<_>>();
    operations.sort_by(|left, right| {
        left.binding()
            .operation_id()
            .cmp(right.binding().operation_id())
    });
    for operation in &operations {
        fixture.store.begin(operation, &fixture.fence, at)?;
    }
    let first = operations.first().ok_or("first operation")?;
    defer(&fixture, first, at)?;
    // The owned connection reaches the exact status/global-history gate rather
    // than the earlier, separately covered external-write owner fence.
    fixture.store.connection()?.execute(
        "UPDATE admission_operation_recovery_deferrals SET status_digest=?1 WHERE operation_id=?2",
        params!["b".repeat(64), first.binding().operation_id().as_str()],
    )?;
    let before = read_state(&fixture)?;
    assert!(matches!(fixture.store.list_recoverable(at + 2_000, 1),
        Err(AdmissionOperationStoreError::Invariant(reason)) if reason == "recovery status does not match its anchored canonical record"));
    assert_eq!(read_state(&fixture)?, before);
    Ok(())
}

#[test]
fn legacy_recovery_external_write_remains_fatal_and_mints_no_result() -> AnchoredTestResult {
    let at = 1_800_001_200_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "legacy-external-request",
        "legacy-external-capability",
    );
    fixture.store.begin(&operation, &fixture.fence, at)?;
    defer(&fixture, &operation, at)?;
    let external = Connection::open(&fixture.database)?;
    external.execute(
        "UPDATE admission_operation_recovery_deferrals SET status_digest=?1 WHERE operation_id=?2",
        params!["b".repeat(64), operation.binding().operation_id().as_str()],
    )?;
    let committed = admission_commit_rows(&external)?;
    assert!(matches!(fixture.store.list_recoverable(at + 2_000, 1),
        Err(AdmissionOperationStoreError::OutcomeUnknown(reason))
            if reason == "authority database changed outside its serving-owner connection"));
    assert_eq!(admission_commit_rows(&external)?, committed);
    Ok(())
}

#[test]
fn legacy_recovery_terminal_tail_does_not_exhaust_candidate_capacity() -> AnchoredTestResult {
    let at = 1_800_001_400_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let fixture = fixture();
    let mut operations = (0..257)
        .map(|index| {
            prepared_operation(
                &fixture.fence,
                AdmissionOperationKind::ToolDispatch,
                &format!("legacy-terminal-tail-request-{index:03}"),
                &format!("legacy-terminal-tail-capability-{index:03}"),
            )
        })
        .collect::<Vec<_>>();
    operations.sort_by(|left, right| {
        left.binding()
            .operation_id()
            .cmp(right.binding().operation_id())
    });
    let (tail, dormant) = operations.split_last().ok_or("terminal tail fixture")?;
    for operation in dormant {
        fixture.store.begin(operation, &fixture.fence, at)?;
        defer(&fixture, operation, at)?;
    }
    let terminal = finalizing_tool_operation(
        &fixture,
        tail.binding().request_id().as_str(),
        tail.binding().capability_id().as_str(),
        at,
    );
    assert_eq!(terminal.binding(), tail.binding());
    fixture
        .store
        .commit_terminal_projection(&unknown_projection(
            &fixture,
            &terminal,
            "legacy-excluded-terminal-tail-incident",
            'd',
            at + 20,
        ))?;
    let terminal = fixture
        .store
        .load_by_operation_id(tail.binding().operation_id())?
        .ok_or("retained terminal tail")?;
    assert_eq!(
        terminal.state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert!(fixture
        .store
        .load_recovery_status(tail.binding().operation_id(), &fixture.fence, at + 2_000)?
        .is_none());
    let before = read_state(&fixture)?;
    assert!(fixture.store.list_recoverable(at + 2_000, 1)?.is_empty());
    assert_eq!(read_state(&fixture)?, before);
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(tail.binding().operation_id())?,
        Some(terminal)
    );
    Ok(())
}
