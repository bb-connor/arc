//! Current audience refusal precedes any retained Proposal conflict response.
use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use rusqlite::types::Value;
use tower::ServiceExt;

fn retained_rows(fixture: &KnowledgeFixture) -> TestResult<Vec<Vec<Vec<Value>>>> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture.f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    [
        "SELECT * FROM main.admission_operation_recovery_records ORDER BY record_key",
        "SELECT * FROM main.admission_operation_recovery_events ORDER BY sequence",
        "SELECT * FROM main.authority_global_commits ORDER BY commit_sequence",
    ]
    .into_iter()
    .map(|sql| {
        let mut statement = connection.prepare(sql)?;
        let columns = statement.column_count();
        let rows = statement.query_map([], |row| {
            (0..columns)
                .map(|column| row.get(column))
                .collect::<Result<Vec<Value>, _>>()
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    })
    .collect()
}

#[tokio::test]
async fn current_proposal_audience_refusal_precedes_retained_collision_disclosure() -> TestResult {
    eprintln!("proposal audience phase=current native producer");
    let mut fixture =
        KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    maintain(&mut fixture)?;
    let workflow = Box::pin(fixture.f.ready()).await?;
    let artifact = fixture.publish("private-proposal-audience", b"private original trajectory")?;
    let input = DecisionReportV1 {
        attachments: BoundedList::new(vec![])?,
        ..report(&fixture, &workflow, artifact.clone())?
    };
    let service = Arc::new(maintenance(&fixture)?);
    let report = service.submit_report(
        &fixture.f.control,
        &CommandId::new("private-proposal-audience-report")?,
        &input,
    )?;
    let proposal = lifecycle::proposal(&fixture, &service, &report, &artifact)?;
    let stored = service.propose(&fixture.f.control, &proposal)?;
    assert!(!matches!(stored.label, InformationLabel::Top));
    assert!(!stored.label.flows_to(&InformationLabel::bottom()));
    let changed = PolicyMaintenanceProposalV1 {
        rationale: ProtectedText::new("valid alternate private proposal body")?,
        ..proposal.clone()
    };
    changed.validate()?;
    let absent = PolicyMaintenanceProposalV1 {
        proposal_id: ReviewId::new("absent-private-proposal-audience")?,
        ..changed.clone()
    };
    absent.validate()?;
    let router = crate::recovery::recovery_maintenance_router(service.clone());
    let request = |input: &PolicyMaintenanceProposalV1| -> TestResult<Request<Body>> {
        Ok(Request::builder()
            .method("POST")
            .uri("/v1/recovery/policy/propose")
            .header("content-type", "application/json")
            .body(Body::from(chio_core_types::canonical_json_bytes(
                &serde_json::json!({
                    "capability":text::<32768, _>(&fixture.f.control)?.as_str(),
                    "proposal":text::<32768, _>(input)?.as_str(),
                }),
            )?))?)
    };
    eprintln!("proposal audience phase=authorized exact replay and collision controls");
    let before = retained_rows(&fixture)?;
    assert_eq!(service.propose(&fixture.f.control, &proposal)?, stored);
    let collision = router.clone().oneshot(request(&changed)?).await?;
    assert_eq!(collision.status(), StatusCode::CONFLICT);
    let collision = to_bytes(collision.into_body(), 1_024).await?;
    assert_eq!(collision.as_ref(), b"recovery.conflict");
    assert!(retained_rows(&fixture)? == before);
    let store = fixture.f.authority.admission_operation_store();
    let mut profile = fixture
        .f
        .kernel
        .recovery_deployment(fixture.f.runtime.scope())?;
    let mut actors = profile.actors.as_slice().to_vec();
    assert!(stored.label.flows_to(&actors[0].preview_clearance));
    actors[0].preview_clearance = InformationLabel::bottom();
    profile.actors = NonEmptyBoundedList::new(actors)?;
    profile.authority_scope = recovery_authority_scope_digest(&profile)?;
    store.configure_recovery_deployment(&profile)?;
    eprintln!("proposal audience phase=genuine current downgraded actors");
    for permission in [
        RecoveryPermission::Maintain,
        RecoveryPermission::KnowledgeRead,
    ] {
        let actor = fixture.f.kernel.authenticate_recovery_actor(
            fixture.f.runtime.scope(),
            &fixture.f.control,
            permission,
        )?;
        assert_eq!(actor.permission(), permission);
        assert_eq!(actor.scope(), fixture.f.runtime.scope());
    }
    let selected = fixture
        .f
        .kernel
        .recovery_deployment(fixture.f.runtime.scope())?;
    assert_eq!(
        selected.actors.as_slice()[0].preview_clearance,
        InformationLabel::bottom()
    );
    let before = retained_rows(&fixture)?;
    let calls = fixture.f.process.process("root")?.tree_calls;
    let effects = external_count(&fixture.f.path)?;
    eprintln!("proposal audience phase=public exact collision and absent refusal");
    let mut outcomes = Vec::new();
    for input in [&proposal, &changed, &absent] {
        let response = router.clone().oneshot(request(input)?).await?;
        let status = response.status();
        let body = to_bytes(response.into_body(), 1_024).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body.as_ref(), b"recovery.authority_denied");
        outcomes.push((status, body));
    }
    assert_eq!(outcomes[0], outcomes[1]);
    assert_eq!(outcomes[1], outcomes[2]);
    assert!(retained_rows(&fixture)? == before);
    assert_eq!(fixture.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&fixture.f.path)?, effects);
    assert_eq!(active_product_quota(&fixture, "proposals")?, 1);
    assert_eq!(active_product_quota(&fixture, "reports")?, 1);
    eprintln!("proposal audience phase=all source history and debits preserved");
    Ok(())
}
