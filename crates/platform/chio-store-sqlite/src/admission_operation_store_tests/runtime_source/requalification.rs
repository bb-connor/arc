use super::*;
use crate::admission_operation_store::RuntimeSourceRequalificationInput;

fn replace(
    fixture: &Fixture,
    prior: &RuntimeSourceRecordV1,
    source: &Source,
    fence: &StoreMutationFence,
) -> Result<RuntimeSourceRecordV1, AdmissionOperationStoreError> {
    fixture.store.requalify_runtime_source(
        RuntimeSourceRequalificationInput {
            prior,
            source_id: &identifier("source", "replacement-source"),
            runtime_authority_id: &identifier("runtime", "replacement-runtime"),
            source,
        },
        fence,
        now_ms(),
    )
}

#[test]
fn requalification_retains_history_and_refuses_superseded_authority() -> Result<(), Box<dyn Error>>
{
    let fixture = fixture();
    let original = Source::new(&fixture, Behavior::Normal);
    let prior = install(&fixture, &original)?;
    let before = global_count(&fixture.store);
    let replacement = Source::new(&fixture, Behavior::Normal);
    let current = replace(&fixture, &prior, &replacement, &fixture.fence)?;
    assert_eq!(source_count(&fixture.store), 2);
    assert_eq!(global_count(&fixture.store), before + 2);
    assert_eq!(
        fixture.store.load_runtime_source(
            &identifier("runtime", "replacement-runtime"),
            &fixture.fence,
            now_ms(),
        )?,
        Some(current.clone()),
    );
    assert_eq!(
        load(&fixture),
        Err(AdmissionOperationStoreError::Invariant(
            "runtime source qualification has been superseded".into(),
        )),
    );
    assert_eq!(
        install(&fixture, &original),
        Err(AdmissionOperationStoreError::Invariant(
            "runtime source qualification has been superseded".into(),
        )),
    );
    {
        let connection = fixture.store.connection()?;
        let retained: Vec<u8> = connection.query_row(
            "SELECT canonical_source FROM runtime_source_qualifications WHERE runtime_authority_id = ?1",
            [RUNTIME_ID],
            |row| row.get(0),
        )?;
        assert_eq!(retained, prior.qualification().canonical_bytes());
        crate::admission_operation_store::verify_runtime_source_projection_coverage(&connection)?;
        verify_admission_operation_invariants(&connection)?;
    }
    assert_eq!(
        replace(&fixture, &prior, &replacement, &fixture.fence)?,
        current
    );
    assert_eq!(source_count(&fixture.store), 2);
    assert_eq!(global_count(&fixture.store), before + 2);
    Ok(())
}

#[test]
fn requalification_callback_refusal_preserves_prior_authority() -> Result<(), Box<dyn Error>> {
    let fixture = fixture();
    let original = Source::new(&fixture, Behavior::Normal);
    let prior = install(&fixture, &original)?;
    let before = global_count(&fixture.store);
    let replacement = Source::new(&fixture, Behavior::Refuse);
    assert_eq!(
        replace(&fixture, &prior, &replacement, &fixture.fence),
        Err(AdmissionOperationStoreError::Invariant(
            "injected source qualification refusal".into(),
        )),
    );
    assert_eq!(load(&fixture)?, Some(prior));
    assert_eq!(source_count(&fixture.store), 1);
    assert_eq!(global_count(&fixture.store), before);
    Ok(())
}

#[test]
fn requalification_stale_fence_refuses_before_source_callback() -> Result<(), Box<dyn Error>> {
    let fixture = fixture();
    let original = Source::new(&fixture, Behavior::Normal);
    let prior = install(&fixture, &original)?;
    let before = global_count(&fixture.store);
    let replacement = Source::new(&fixture, Behavior::Normal);
    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    assert_eq!(
        replace(&fixture, &prior, &replacement, &stale),
        Err(AdmissionOperationStoreError::Fenced),
    );
    assert_eq!(replacement.calls.load(Ordering::SeqCst), 0);
    assert_eq!(load(&fixture)?, Some(prior));
    assert_eq!(source_count(&fixture.store), 1);
    assert_eq!(global_count(&fixture.store), before);
    Ok(())
}

#[test]
fn requalification_reclaims_active_capacity_without_deleting_history() -> Result<(), Box<dyn Error>>
{
    let fixture = fixture();
    let prior = install(&fixture, &Source::new(&fixture, Behavior::Normal))?;
    for index in 1..128 {
        fixture.store.install_runtime_source(
            &identifier("source", &format!("capacity-source-{index}")),
            &identifier("runtime", &format!("capacity-runtime-{index}")),
            &Source::new(&fixture, Behavior::Normal),
            &fixture.fence,
            now_ms(),
        )?;
    }
    let replacement = Source::new(&fixture, Behavior::Normal);
    replace(&fixture, &prior, &replacement, &fixture.fence)?;
    assert_eq!(source_count(&fixture.store), 129);
    let before = global_count(&fixture.store);
    assert_eq!(
        fixture.store.install_runtime_source(
            &identifier("source", "over-capacity-source"),
            &identifier("runtime", "over-capacity-runtime"),
            &Source::new(&fixture, Behavior::Normal),
            &fixture.fence,
            now_ms(),
        ),
        Err(AdmissionOperationStoreError::Invariant(
            "runtime source capacity or source identity conflict".into(),
        )),
    );
    assert_eq!(source_count(&fixture.store), 129);
    assert_eq!(global_count(&fixture.store), before);
    let connection = fixture.store.connection()?;
    crate::admission_operation_store::verify_runtime_source_projection_coverage(&connection)?;
    verify_admission_operation_invariants(&connection)?;
    Ok(())
}

#[test]
fn missing_supersession_refuses_global_projection_coverage() -> Result<(), Box<dyn Error>> {
    let fixture = fixture();
    let prior = install(&fixture, &Source::new(&fixture, Behavior::Normal))?;
    replace(
        &fixture,
        &prior,
        &Source::new(&fixture, Behavior::Normal),
        &fixture.fence,
    )?;
    let connection = fixture.store.connection()?;
    crate::admission_operation_store::verify_runtime_source_projection_coverage(&connection)?;
    connection.execute_batch(
        "DROP TRIGGER runtime_source_supersessions_no_delete;
         DELETE FROM runtime_source_supersessions;",
    )?;
    let result =
        crate::admission_operation_store::verify_runtime_source_projection_coverage(&connection);
    assert!(matches!(result,
        Err(crate::serving_owner::SqliteServingOwnerError::Invalid(detail))
        if detail == "runtime source qualification integrity: runtime sources and global references have different counts"
    ));
    Ok(())
}
