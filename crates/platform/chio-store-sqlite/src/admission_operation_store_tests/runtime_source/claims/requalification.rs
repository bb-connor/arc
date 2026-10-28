use super::*;
use crate::admission_operation_store::{runtime_participant, RuntimeSourceRequalificationInput};

#[test]
fn superseded_source_keeps_history_but_refuses_new_claim_and_dispatch() -> TestResult {
    let fixture = fixture();
    let source = installed(&fixture)?;
    let (initial, lease) = setup(&fixture, "requalified-claim-history")?;
    let first = intent(&initial, &source, "first", &[])?;
    let (operation, reference) =
        fixture
            .store
            .claim_runtime_participants(&initial, &lease, &first, now_ms())?;
    let snapshot = {
        let connection = fixture.store.connection()?;
        runtime_participant::dispatch_snapshot(&connection, &operation, 0)?
            .ok_or("missing valid dispatch snapshot")?
    };
    let replacement = Source::new(&fixture, Behavior::Normal);
    fixture.store.requalify_runtime_source(
        RuntimeSourceRequalificationInput {
            prior: &source,
            source_id: &identifier("source", "claim-replacement-source"),
            runtime_authority_id: &identifier("runtime", "claim-replacement-runtime"),
            source: &replacement,
        },
        &fixture.fence,
        now_ms(),
    )?;
    {
        let connection = fixture.store.connection()?;
        runtime_participant::verify_dispatch_snapshot(&connection, &operation, &Some(snapshot))?;
        assert_eq!(
            runtime_participant::dispatch_snapshot(&connection, &operation, 0),
            Err(AdmissionOperationStoreError::Invariant(
                "runtime source qualification has been superseded".into(),
            )),
        );
    }
    let history = fixture
        .store
        .load_runtime_participant_history(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("missing retained history")?;
    assert_eq!(history.1.len(), 1);
    assert_eq!(history.1[0].reference, reference);
    let lease = renew(&fixture, &operation, &lease)?;
    fixture
        .store
        .release_runtime_participants(&operation, &lease, &reference, now_ms())?;
    let next = intent(&operation, &source, "after-supersession", &[])?;
    let before = global_count(&fixture.store);
    assert_eq!(
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &next, now_ms()),
        Err(AdmissionOperationStoreError::Invariant(
            "runtime source qualification has been superseded".into(),
        )),
    );
    assert_eq!(global_count(&fixture.store), before);
    let history = fixture
        .store
        .load_runtime_participant_history(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("missing released history")?;
    assert_eq!(history.1.len(), 1);
    assert_eq!(history.1[0].reference, reference);
    Ok(())
}
