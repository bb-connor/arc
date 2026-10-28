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
