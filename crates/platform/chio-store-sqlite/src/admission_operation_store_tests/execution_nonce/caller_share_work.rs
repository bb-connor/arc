//! A caller sibling-share snapshot reads only the operations that can fund a
//! share under the requested parent, however many unrelated operations live.

use super::*;

const UNRELATED: usize = 8;

fn begin_unrelated(fixture: &Fixture, label: &str) -> TestResult {
    for index in 0..UNRELATED {
        let operation = prepared_operation(
            &fixture.fence,
            AdmissionOperationKind::ToolDispatch,
            &format!("{label}-{index}"),
            "caller-share-unrelated-capability",
        );
        fixture.store.begin(&operation, &fixture.fence, now_ms())?;
    }
    Ok(())
}

/// Take one snapshot and count the operation rows it decoded.
fn snapshot_decodes(fixture: &Fixture, parent: &AdmissionIdentifier) -> TestResult<usize> {
    let before = decoded_operations();
    let shares = fixture
        .store
        .load_caller_budget_shares(parent, 16, &fixture.fence, now_ms())?;
    assert!(shares.is_empty());
    Ok(decoded_operations() - before)
}

#[test]
fn caller_share_snapshot_decodes_no_unrelated_live_operation() -> TestResult {
    let fixture = fixture();
    let parent = identifier("parent_id", "caller-share-work-parent");
    let mut work = Vec::new();
    for round in 0..2 {
        begin_unrelated(&fixture, &format!("caller-share-work-{round}"))?;
        work.push(snapshot_decodes(&fixture, &parent)?);
    }
    assert_eq!(work, [0, 0]);
    Ok(())
}
