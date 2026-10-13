//! Authenticated historical audiences remain data and cannot authorize fresh publication.
use super::*;

fn retained_records(f: &KnowledgeFixture) -> TestResult<Vec<(String, i64, Vec<u8>)>> {
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let mut statement = connection.prepare(
        "SELECT record_key,version,payload
         FROM admission_operation_recovery_records ORDER BY record_key",
    )?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn retain_historical_audience(f: &KnowledgeFixture) -> TestResult {
    let store = f.f.authority.admission_operation_store();
    let scope = f.f.runtime.scope();
    let actor = f.actor(RecoveryPermission::Report)?;
    let finite = f.f.kernel.recovery_deployment(scope)?;
    let capability = chio_core::canonical_json_bytes(&f.f.control)?;
    let historical = retain_recovery_fixture_legacy_top_actor(
        &store,
        &f.f.authority.mutation_fence(),
        scope,
        actor.principal(),
    )?;
    assert_eq!(
        historical.actors.as_slice()[0].preview_clearance,
        InformationLabel::Top,
    );
    assert_eq!(historical.native_authority, finite.native_authority);
    assert_eq!(historical.security_context, finite.security_context);
    assert_eq!(historical.policy_digest, finite.policy_digest);
    assert_eq!(historical.contract_digest, finite.contract_digest);
    assert_eq!(
        historical.actors.as_slice()[0].permissions,
        finite.actors.as_slice()[0].permissions,
    );
    assert_eq!(
        chio_core::canonical_json_bytes(&f.f.kernel.recovery_deployment(scope)?)?,
        chio_core::canonical_json_bytes(&historical)?,
        "the modeled predecessor profile remains authenticated historical data",
    );
    assert_eq!(chio_core::canonical_json_bytes(&f.f.control)?, capability);
    for permission in [RecoveryPermission::Report, RecoveryPermission::Maintain] {
        let current =
            f.f.kernel
                .authenticate_recovery_actor(scope, &f.f.control, permission)?;
        assert_eq!(current.principal(), actor.principal());
        assert_eq!(current.permission(), permission);
    }
    Ok(())
}

#[tokio::test]
async fn policy_report_modeled_historical_top_audience_cannot_publish_without_attachments(
) -> TestResult {
    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    maintain(&mut f)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let input = DecisionReportV1 {
        domain_version: VersionV1,
        scope: f.f.runtime.scope().clone(),
        workflow_id: workflow.clone(),
        expected_revision: f.f.record(&workflow)?.revision,
        decision: RecoveryReportedDecision::NeedsReview,
        reporter_text: ProtectedText::new("historical report publication canary")?,
        desired_outcome: ProtectedText::new("bounded current review")?,
        attachments: BoundedList::new(vec![])?,
    };
    input.validate()?;
    let service = maintenance(&f)?;
    let finite = service.submit_report(
        &f.f.control,
        &CommandId::new("finite-attachment-free-report")?,
        &input,
    )?;
    assert_eq!(finite.report, input);
    assert_eq!(active_product_quota(&f, "reports")?, 1);
    assert_eq!(external_count(&f.f.path)?, 0);
    retain_historical_audience(&f)?;
    let before = retained_records(&f)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let publication = service.submit_report(
        &f.f.control,
        &CommandId::new("historical-top-attachment-free-report")?,
        &input,
    );
    assert_eq!(
        publication.err(),
        Some(crate::recovery::RecoveryRuntimeError::AuthorityDenied),
        "fresh public report intake must require finite clearance even with no artifact or reference-index dependency",
    );
    assert_eq!(retained_records(&f)?, before);
    assert_eq!(active_product_quota(&f, "reports")?, 1);
    assert_eq!(report_count(&f)?, 1);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn policy_proposal_modeled_historical_top_audience_cannot_acquire_fresh_evidence(
) -> TestResult {
    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    maintain(&mut f)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let artifact = f.publish("finite-policy-evidence", b"finite native policy evidence")?;
    let input = DecisionReportV1 {
        attachments: BoundedList::new(vec![])?,
        ..report(&f, &workflow, artifact.clone())?
    };
    let service = maintenance(&f)?;
    let report = service.submit_report(
        &f.f.control,
        &CommandId::new("finite-policy-evidence-report")?,
        &input,
    )?;
    let finite_input = super::lifecycle::proposal(&f, &service, &report, &artifact)?;
    let finite = service.propose(&f.f.control, &finite_input)?;
    assert_eq!(finite.proposal, finite_input);
    assert_eq!(active_product_quota(&f, "proposals")?, 1);
    assert!(f.runtime.collect(&f.f.control, &artifact).is_err());
    let fresh = PolicyMaintenanceProposalV1 {
        proposal_id: ReviewId::new("historical-top-new-policy-proposal")?,
        ..finite_input
    };
    fresh.validate()?;
    retain_historical_audience(&f)?;
    let before = retained_records(&f)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let publication = service.propose(&f.f.control, &fresh);
    assert_eq!(
        publication.err(),
        Some(crate::recovery::RecoveryRuntimeError::AuthorityDenied),
        "fresh public policy evidence intake must refuse a genuinely authenticated historical Top assignment",
    );
    assert_eq!(retained_records(&f)?, before);
    assert_eq!(active_product_quota(&f, "proposals")?, 1);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}

// An old assignment is retained data and cannot become a live response audience.
#[tokio::test]
async fn policy_report_modeled_historical_top_audience_cannot_read_a_classified_view() -> TestResult
{
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    maintain(&mut f)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let input = DecisionReportV1 {
        domain_version: VersionV1,
        scope: f.f.runtime.scope().clone(),
        workflow_id: workflow.clone(),
        expected_revision: f.f.record(&workflow)?.revision,
        decision: RecoveryReportedDecision::NeedsReview,
        reporter_text: ProtectedText::new("historical unknown audience read canary")?,
        desired_outcome: ProtectedText::new("finite native report reader")?,
        attachments: BoundedList::new(vec![])?,
    };
    input.validate()?;
    let service = Arc::new(maintenance(&f)?);
    let stored = service.submit_report(
        &f.f.control,
        &CommandId::new("finite-report-before-historical-audience")?,
        &input,
    )?;
    assert_eq!(service.read_report(&f.f.control, &stored.id)?, stored);
    let envelope = chio_core_types::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&f.f.control)?.as_str(),
        "report_id": stored.id,
    }))?;
    let router = crate::recovery::recovery_maintenance_router(service);
    let positive = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/recovery/reports/read")
                .header("content-type", "application/json")
                .body(Body::from(envelope.clone()))?,
        )
        .await?;
    assert_eq!(positive.status(), StatusCode::OK);
    let positive = to_bytes(positive.into_body(), 262_144).await?;
    let positive: DecisionReportViewV1 = chio_core_types::recovery::decode_contract(&positive)?;
    assert_eq!(positive.id, stored.id);
    assert_eq!(positive.report, stored.report);
    assert_eq!(positive.label, stored.label);
    assert_eq!(active_product_quota(&f, "reports")?, 1);
    assert_eq!(external_count(&f.f.path)?, 0);

    retain_historical_audience(&f)?;
    // Native authentication is a positive prerequisite. Neither missing Inspect
    // permission nor a stale capability can stand in for the audience boundary.
    let inspected = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    assert_eq!(inspected.scope(), f.f.runtime.scope());
    assert_eq!(inspected.permission(), RecoveryPermission::Inspect);
    let before = retained_records(&f)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let refused = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/recovery/reports/read")
                .header("content-type", "application/json")
                .body(Body::from(envelope))?,
        )
        .await?;
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "a genuinely authenticated old Top assignment is not a finite current response audience",
    );
    let refused = to_bytes(refused.into_body(), 262_144).await?;
    assert!(!String::from_utf8_lossy(&refused).contains("historical unknown audience read canary"));
    assert_eq!(retained_records(&f)?, before);
    assert_eq!(active_product_quota(&f, "reports")?, 1);
    assert_eq!(report_count(&f)?, 1);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}
