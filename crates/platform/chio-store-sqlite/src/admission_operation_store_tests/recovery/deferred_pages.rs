//! Physical LIMIT/keyset bounds must hold even when every candidate is not due.
use super::deferred_status::defer;
use super::*;
use chio_kernel::admission_operation::{AdmissionRecoveryPageQuery, AdmissionRecoveryPortError};

#[test]
fn recovery_cursor_passes_256_not_due_operations_without_hiding_the_later_item(
) -> AnchoredTestResult {
    let at = 1_800_000_200_000;
    let _clock = chio_test_support::clock::scope_unix_secs(at / 1_000);
    let fixture = fixture();
    let mut operations = (0..257)
        .map(|index| {
            prepared_operation(
                &fixture.fence,
                AdmissionOperationKind::ToolDispatch,
                &format!("deferred-page-request-{index:03}"),
                &format!("deferred-page-capability-{index:03}"),
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
    let (last, earlier) = operations.split_last().ok_or("operations")?;
    for operation in earlier {
        defer(&fixture, operation, at)?;
    }
    let connection = Connection::open(&fixture.database)?;
    let commits = admission_commit_rows(&connection)?;
    let anchor = fixture.authority.anchor_generation()?;
    let page = fixture.store.recovery_page(AdmissionRecoveryPageQuery {
        not_after_unix_ms: at + 2_000,
        candidate_limit: 256,
        after_operation_id: None,
        fence: &fixture.fence,
    })?;
    assert!(page.operations.is_empty());
    assert_eq!(page.scanned_candidates, 256);
    let cursor = page.next_cursor.ok_or("full skipped page cursor")?;
    assert_eq!(
        &cursor,
        earlier
            .last()
            .ok_or("earlier operation")?
            .binding()
            .operation_id()
    );
    let tail = fixture.store.recovery_page(AdmissionRecoveryPageQuery {
        not_after_unix_ms: at + 2_000,
        candidate_limit: 256,
        after_operation_id: Some(&cursor),
        fence: &fixture.fence,
    })?;
    assert_eq!(tail.scanned_candidates, 1);
    assert_eq!(tail.operations, vec![last.clone()]);
    assert_eq!(tail.next_cursor, None);
    assert_eq!(
        admission_commit_rows(&connection)?,
        commits,
        "read pages mint no claims or authority"
    );
    assert_eq!(fixture.authority.anchor_generation()?, anchor);
    Ok(())
}

#[test]
fn recovery_physical_page_refuses_stale_fence_and_invalid_bounds() -> AnchoredTestResult {
    let fixture = fixture();
    let mut stale = fixture.fence.clone();
    stale.owner_epoch = stale.owner_epoch.checked_add(1).ok_or("fence epoch")?;
    let query = |candidate_limit| AdmissionRecoveryPageQuery {
        not_after_unix_ms: now_ms(),
        candidate_limit,
        after_operation_id: None,
        fence: &stale,
    };
    assert!(matches!(
        fixture.store.recovery_page(query(1)),
        Err(AdmissionRecoveryPortError::Local(
            AdmissionOperationStoreError::Fenced
        ))
    ));
    for invalid in [0, 257, usize::MAX] {
        assert!(matches!(
            fixture.store.recovery_page(query(invalid)),
            Err(AdmissionRecoveryPortError::Local(
                AdmissionOperationStoreError::Invariant(_)
            ))
        ));
    }
    Ok(())
}
