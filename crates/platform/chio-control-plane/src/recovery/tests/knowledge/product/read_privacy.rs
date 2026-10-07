//! Missing private reports have the same public response as audience refusal.
use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[derive(PartialEq, Eq)]
struct RetainedRecord {
    key: String,
    scope_key: String,
    kind: String,
    version: i64,
    payload: Vec<u8>,
    native_namespace: Option<String>,
    native_request: Option<String>,
}

impl std::fmt::Debug for RetainedRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RetainedRecord([redacted])")
    }
}

fn retained_records(f: &KnowledgeFixture) -> TestResult<Vec<RetainedRecord>> {
    let connection = rusqlite::Connection::open_with_flags(
        f.f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = connection.prepare(
        "SELECT record_key,scope_key,kind,version,payload,native_namespace,native_request
         FROM admission_operation_recovery_records ORDER BY record_key",
    )?;
    let records = statement.query_map([], |row| {
        Ok(RetainedRecord {
            key: row.get(0)?,
            scope_key: row.get(1)?,
            kind: row.get(2)?,
            version: row.get(3)?,
            payload: row.get(4)?,
            native_namespace: row.get(5)?,
            native_request: row.get(6)?,
        })
    })?;
    Ok(records.collect::<Result<_, _>>()?)
}

#[tokio::test]
async fn a_finite_native_reader_cannot_distinguish_a_private_report_from_an_absent_id() -> TestResult
{
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let input = DecisionReportV1 {
        domain_version: VersionV1,
        scope: f.f.runtime.scope().clone(),
        workflow_id: workflow.clone(),
        expected_revision: f.f.record(&workflow)?.revision,
        decision: RecoveryReportedDecision::NeedsReview,
        reporter_text: ProtectedText::new("private report audience canary")?,
        desired_outcome: ProtectedText::new("current finite authorized inspection")?,
        attachments: BoundedList::new(vec![])?,
    };
    let service = Arc::new(maintenance(&f)?);
    let stored = service.submit_report(
        &f.f.control,
        &CommandId::new("private-report-positive-control")?,
        &input,
    )?;
    assert!(!matches!(stored.label, InformationLabel::Top));
    assert!(!stored.label.flows_to(&InformationLabel::bottom()));
    let router = crate::recovery::recovery_maintenance_router(service);
    let request = |id: &EvidenceRef| -> TestResult<Request<Body>> {
        Ok(Request::builder()
            .method("POST")
            .uri("/v1/recovery/reports/read")
            .header("content-type", "application/json")
            .body(Body::from(chio_core_types::canonical_json_bytes(
                &serde_json::json!({
                    "capability":text::<32768, _>(&f.f.control)?.as_str(),
                    "report_id":id,
                }),
            )?))?)
    };
    let positive = router.clone().oneshot(request(&stored.id)?).await?;
    assert_eq!(positive.status(), StatusCode::OK);
    let positive = to_bytes(positive.into_body(), 262_144).await?;
    let positive: DecisionReportViewV1 = chio_core_types::recovery::decode_contract(&positive)?;
    assert_eq!(positive.report, stored.report);
    let scope = f.f.runtime.scope();
    let store = f.f.authority.admission_operation_store();
    let mut deployment = f.f.kernel.recovery_deployment(scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    let prior = actors[0].preview_clearance.clone();
    assert!(stored.label.flows_to(&prior));
    actors[0].preview_clearance = InformationLabel::bottom();
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    let inspector =
        f.f.kernel
            .authenticate_recovery_actor(scope, &f.f.control, RecoveryPermission::Inspect)?;
    assert_eq!(inspector.scope(), scope);
    assert_eq!(inspector.permission(), RecoveryPermission::Inspect);
    let selected = f.f.kernel.recovery_deployment(scope)?;
    assert_eq!(
        selected.actors.as_slice()[0].preview_clearance,
        InformationLabel::bottom()
    );
    let before = retained_records(&f)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let effects = external_count(&f.f.path)?;
    let missing = EvidenceRef::new("pristine-absent-private-report")?;
    assert_ne!(missing, stored.id);
    let mut responses = Vec::new();
    for id in [&stored.id, &missing] {
        let response = router.clone().oneshot(request(id)?).await?;
        let status = response.status();
        let body = to_bytes(response.into_body(), 1_024).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body.as_ref(), b"recovery.authority_denied");
        assert!(!String::from_utf8_lossy(&body).contains("private report audience canary"));
        responses.push((status, body));
    }
    assert_eq!(responses[0], responses[1]);
    assert_eq!(retained_records(&f)?, before);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&f.f.path)?, effects);
    Ok(())
}
