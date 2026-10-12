//! External projection edits must close serving-owner custody before a read.

use super::*;
use chio_kernel::admission_operation::AdmissionOperationStoreError;

const DROP_TRIGGERS: &str = "DROP TRIGGER admission_operation_caller_shares_immutable;
     DROP TRIGGER admission_operation_caller_shares_no_delete;";

fn assert_external_edit_refused(label: &str, edit: &str) -> TestResult {
    let fixture = Fixture::new()?;
    let mut runtime = fixture.open()?;
    let siblings = Siblings::new(&fixture, &mut runtime)?;
    let _first = reserve_child(
        &runtime,
        &request(&siblings.first, &format!("{label}-first"))?,
    )?;
    let parent = AdmissionIdentifier::try_new("parent_id", siblings.parent.id.clone())?;
    let store = runtime.authority.admission_operation_store();
    let fence = runtime.authority.mutation_fence();
    let now = store.observed_authority_time()?.get();
    let before = store.load_caller_budget_shares(&parent, 16, &fence, now)?;
    assert_eq!(
        before.len(),
        1,
        "the live share must be present before the edit"
    );
    assert_eq!(before[0].child_id().as_str(), siblings.first.id);

    execute_sql(&fixture, edit)?;
    // Keep the already-observed time: a fresh clock query would itself check
    // custody, hiding which boundary refused the modified projection.
    let after = store.load_caller_budget_shares(&parent, 16, &fence, now);
    assert!(
        matches!(
            &after,
            Err(AdmissionOperationStoreError::OutcomeUnknown(reason))
                if reason == "authority database changed outside its serving-owner connection"
        ),
        "{label}: expected the external-write custody refusal, got {after:?}"
    );
    let sibling = runtime
        .kernel
        .reserve_caller_execution_blocking(&request(&siblings.second, &format!("{label}-second"))?);
    if let Ok(response) = sibling {
        assert_eq!(
            response.verdict,
            Verdict::Deny,
            "{label}: {:?}",
            response.reason
        );
    }
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn external_trigger_drop_and_row_delete_is_refused() -> TestResult {
    assert_external_edit_refused(
        "projection-delete",
        &format!("{DROP_TRIGGERS} DELETE FROM admission_operation_caller_shares;"),
    )
}

#[test]
fn external_trigger_drop_and_reparent_is_refused() -> TestResult {
    assert_external_edit_refused(
        "projection-reparent",
        &format!(
            "{DROP_TRIGGERS} UPDATE admission_operation_caller_shares
             SET parent_capability_id = 'tamper-other-parent'
             WHERE parent_kind = 'delegated';"
        ),
    )
}

#[test]
fn external_foreign_projection_insert_is_refused() -> TestResult {
    assert_external_edit_refused(
        "projection-insert",
        "PRAGMA foreign_keys = OFF;
         INSERT INTO admission_operation_caller_shares
             (operation_id, parent_kind, parent_capability_id)
         VALUES ('tamper-foreign-operation', 'unresolved', NULL);",
    )
}

#[test]
fn external_trigger_drop_alone_is_refused() -> TestResult {
    assert_external_edit_refused("projection-drop-only", DROP_TRIGGERS)
}
