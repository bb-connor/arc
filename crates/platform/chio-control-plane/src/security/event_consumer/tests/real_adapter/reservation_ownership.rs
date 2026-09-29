use super::*;
use chio_security_types::ports::{
    AttestedFindingResponseAdmissionState, AttestedFindingResponseOutboxRecord,
    AttestedFindingResponsePlanningState,
};

#[test]
fn reserved_plan_reconstruction_rejects_rebound_or_corrupt_publication() {
    let fixture = real_adapter_fixture();
    let publication =
        crate::security::event_consumer::build_attested_finding_response_plan_publication(
            &fixture.plan,
        )
        .unwrap_or_else(|error| panic!("publication: {error}"));
    let record = AttestedFindingResponseOutboxRecord {
        batch_id: fixture.plan.batch_id().clone(),
        ordinal: fixture.plan.ordinal(),
        binding: fixture.plan.binding().clone(),
        publication: Some(publication),
        planning_state: AttestedFindingResponsePlanningState::Planned,
        admission_state: AttestedFindingResponseAdmissionState::Pending,
        completion_state: AttestedFindingResponseCompletionState::NotStarted,
        execution_dispatch_id: None,
        prepared_dispatch_binding: None,
        admission_artifact_digest: fixture.plan.admission_artifact_digest().copied(),
        completion_outcome: None,
        completion_evidence_id: None,
        completion_evidence_body_hash: None,
        attempts: 0,
        next_attempt_at_unix_ms: 0,
        last_error_code: None,
    };
    let restored =
        ReservedAttestedFindingResponsePlan::reconstruct(fixture.finding.clone(), &record)
            .unwrap_or_else(|error| panic!("reconstruct: {error}"));
    assert_eq!(restored, fixture.plan);

    for mutation in 0..5 {
        let mut changed = record.clone();
        match mutation {
            0 => {
                changed.batch_id =
                    RecordId::new("foreign-batch").unwrap_or_else(|error| panic!("batch: {error}"))
            }
            1 => changed.ordinal += 1,
            2 => changed.publication = None,
            _ => {
                let publication = changed
                    .publication
                    .as_mut()
                    .unwrap_or_else(|| panic!("fixture publication"));
                if mutation == 3 {
                    publication.body_hash = Digest32::new([0x42; 32]);
                } else {
                    // Even a self-consistent rehash cannot change the finding owner.
                    publication.body.response_plan.trigger_finding_hash = Digest32::new([0x43; 32]);
                    let canonical = chio_core::canonical_json_bytes(&publication.body)
                        .unwrap_or_else(|error| panic!("canonical publication: {error}"));
                    publication.body_hash =
                        Digest32::new(*chio_core::sha256(&canonical).as_bytes());
                    publication.canonical_body = CanonicalBody::new(canonical)
                        .unwrap_or_else(|error| panic!("canonical body: {error}"));
                }
            }
        }
        assert!(
            matches!(
                ReservedAttestedFindingResponsePlan::reconstruct(fixture.finding.clone(), &changed),
                Err(error) if error.kind() == PortErrorKind::IntegrityFailure
            ),
            "mutation {mutation} admitted rebound recovery evidence"
        );
    }
}
