//! Individually supported artifact labels cannot commit oversized product intake.
use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chio_core_types::recovery::artifact_version_reference;
use rusqlite::types::Value;
use std::collections::{BTreeMap, BTreeSet};
use tower::ServiceExt;

const RECORD_CEILING: usize = 262_144;
const PUBLICATION_LABEL_CEILING: usize = 100_000;

fn owner(index: usize) -> TestResult<chio_security_types::flow::PrincipalId> {
    Ok(chio_security_types::flow::PrincipalId::new(format!(
        "bounded-projection-owner-{index:02}-{}",
        "o".repeat(144),
    ))?)
}

fn publication_label(part: usize) -> TestResult<InformationLabel> {
    use chio_security_types::flow::PrincipalId as FlowPrincipalId;
    let mut policies = BTreeMap::new();
    for index in (part * 2)..(part * 2 + 2) {
        let owner = owner(index)?;
        let mut readers = BTreeSet::from([owner.clone()]);
        for reader in 0..255 {
            readers.insert(FlowPrincipalId::new(format!(
                "bounded-projection-reader-{index:02}-{reader:03}-{}",
                "r".repeat(144),
            ))?);
        }
        policies.insert(owner, readers);
    }
    Ok(InformationLabel::try_known(policies, BTreeSet::new())?)
}

fn configure_compact_clearance(fixture: &RecoveryFixture) -> TestResult<Vec<InformationLabel>> {
    let labels = (0..4)
        .map(publication_label)
        .collect::<TestResult<Vec<_>>>()?;
    let compact = (0..8)
        .map(|index| {
            let owner = owner(index)?;
            Ok((owner.clone(), BTreeSet::from([owner])))
        })
        .collect::<TestResult<BTreeMap<_, _>>>()?;
    let compact = InformationLabel::try_known(compact, BTreeSet::new())?;
    let mut deployment = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    let mut actors = deployment.actors.as_slice().to_vec();
    let clearance = actors[0].preview_clearance.join_restrictions(&compact)?;
    assert!(!matches!(clearance, InformationLabel::Top));
    let mut joined = InformationLabel::bottom();
    for label in &labels {
        assert!(label.flows_to(&clearance));
        assert!(chio_core_types::canonical_json_bytes(label)?.len() < PUBLICATION_LABEL_CEILING);
        joined = joined.join_restrictions(label)?;
    }
    assert!(chio_core_types::canonical_json_bytes(&joined)?.len() > RECORD_CEILING);
    actors[0].preview_clearance = clearance;
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    assert!(chio_core_types::canonical_json_bytes(&deployment)?.len() <= RECORD_CEILING);
    fixture
        .authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    Ok(labels)
}

async fn published_parts(
    require_maintenance: bool,
) -> TestResult<(KnowledgeFixture, WorkflowId, Vec<ArtifactVersionRefV1>)> {
    let base = super::super::super::semantic::native_fixture("read")?;
    let labels = configure_compact_clearance(&base)?;
    let mut fixture = KnowledgeFixture::from(base)?;
    if require_maintenance {
        maintain(&mut fixture)?;
    }
    let workflow = Box::pin(fixture.f.ready()).await?;
    let actor = fixture.actor(RecoveryPermission::KnowledgeAdopt)?;
    let store = fixture.f.authority.admission_operation_store();
    let fence = fixture.f.authority.mutation_fence();
    let mut references = Vec::new();
    let mut actual_join = InformationLabel::bottom();
    for (part, label) in labels.into_iter().enumerate() {
        let key = format!("bounded-projection-artifact-{part}");
        let bytes = b"individually supported classified trajectory";
        let mut input = fixture.input(&key, bytes)?;
        input.producer = ArtifactProducerV1::Adoption {
            evidence: EvidenceRef::new(&key)?,
        };
        let reservation = fixture.runtime.reserve(&fixture.f.control, &input)?;
        let certificate = super::super::certificate(&fixture, &reservation, label.clone())?;
        assert!(chio_core_types::canonical_json_bytes(&certificate)?.len() <= RECORD_CEILING);
        let reference =
            fixture
                .runtime
                .publish(&fixture.f.control, &input, bytes, Some(&certificate))?;
        // The ordinary idempotent native entry returns the genuinely stored
        // complete metadata and certificate, without a fixture-authored row.
        let retained = store.reserve_artifact(&actor, &input, &fence, now_ms()?)?;
        assert_eq!(retained.state, ArtifactPublicationStateV1::Available);
        assert_eq!(retained.metadata.label, label);
        assert!(retained.certificate.as_ref() == Some(&certificate));
        assert_eq!(artifact_version_reference(&retained.metadata)?, reference);
        assert!(chio_core_types::canonical_json_bytes(&retained)?.len() <= RECORD_CEILING);
        actual_join = actual_join.join_restrictions(&retained.metadata.label)?;
        references.push(reference);
    }
    assert!(chio_core_types::canonical_json_bytes(&actual_join)?.len() > RECORD_CEILING);
    eprintln!("bounded intake phase=four actual individually supported publications");
    Ok((fixture, workflow, references))
}

fn request(
    fixture: &KnowledgeFixture,
    route: &str,
    fields: serde_json::Value,
) -> TestResult<Request<Body>> {
    let mut object = fields
        .as_object()
        .ok_or("maintenance request object")?
        .clone();
    object.insert(
        "capability".into(),
        serde_json::Value::String(text::<32768, _>(&fixture.f.control)?.as_str().into()),
    );
    let bytes = chio_core_types::canonical_json_bytes(&object)?;
    assert!(bytes.len() <= 65_536);
    Ok(Request::builder()
        .method("POST")
        .uri(route)
        .header("content-type", "application/json")
        .body(Body::from(bytes))?)
}

type Rows = Vec<Vec<Value>>;

fn rows(connection: &rusqlite::Connection, sql: &str) -> TestResult<Rows> {
    let mut statement = connection.prepare(sql)?;
    let columns = statement.column_count();
    let values = statement.query_map([], |row| {
        (0..columns)
            .map(|column| row.get(column))
            .collect::<Result<Vec<Value>, _>>()
    })?;
    Ok(values.collect::<Result<_, _>>()?)
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    records: Rows,
    events: Rows,
    global: Rows,
    processes: Rows,
    calls: Rows,
}

fn snapshot(fixture: &KnowledgeFixture) -> TestResult<Snapshot> {
    let admission = rusqlite::Connection::open_with_flags(
        fixture.f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let process = rusqlite::Connection::open_with_flags(
        fixture.f.path.join("process.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(Snapshot {
        records: rows(&admission, "SELECT * FROM main.admission_operation_recovery_records ORDER BY record_key")?,
        events: rows(&admission, "SELECT * FROM main.admission_operation_recovery_events ORDER BY sequence")?,
        global: rows(&admission, "SELECT * FROM main.authority_global_commits ORDER BY commit_sequence")?,
        processes: rows(&process, "SELECT id,parent_id,root_id,depth,state,revision,tree_calls FROM main.processes ORDER BY id")?,
        calls: rows(&process, "SELECT process_id,operation_key,attempts FROM main.process_calls ORDER BY process_id,operation_key")?,
    })
}

fn product_counts(fixture: &KnowledgeFixture) -> TestResult<(i64, i64)> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture.f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(connection.query_row(
        "SELECT
         (SELECT count(*) FROM main.admission_operation_recovery_records WHERE record_key GLOB 'product-report:*'),
         (SELECT count(*) FROM main.admission_operation_recovery_records WHERE record_key GLOB 'product-proposal:*')",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?)
}

fn evidence_owners(
    fixture: &KnowledgeFixture,
    references: &[ArtifactVersionRefV1],
) -> TestResult<Vec<usize>> {
    let store = fixture.f.authority.admission_operation_store();
    let fence = fixture.f.authority.mutation_fence();
    references
        .iter()
        .map(|reference| {
            Ok(store.inspect_product_evidence_owner_count(reference, &fence, now_ms()?)?)
        })
        .collect()
}

async fn require_refused_body(response: axum::response::Response) -> TestResult {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        to_bytes(response.into_body(), 1_024).await?.as_ref(),
        b"recovery.unavailable",
    );
    Ok(())
}

#[tokio::test]
async fn report_intake_refuses_an_oversized_join_without_committing_or_repinning() -> TestResult {
    let (fixture, workflow, references) = published_parts(false).await?;
    let service = Arc::new(maintenance(&fixture)?);
    let router = crate::recovery::recovery_maintenance_router(service.clone());
    let calls = fixture.f.process.process("root")?.tree_calls;
    // Each real attachment first succeeds through the same public native route.
    for (part, reference) in references.iter().enumerate() {
        let input = report(&fixture, &workflow, reference.clone())?;
        let fields = serde_json::json!({
            "command_id":CommandId::new(&format!("bounded-part-report-{part}"))?,
            "report":text::<32768,_>(&input)?.as_str(),
        });
        let response = router
            .clone()
            .oneshot(request(&fixture, "/v1/recovery/reports/submit", fields)?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), RECORD_CEILING).await?;
        let view: DecisionReportViewV1 = serde_json::from_slice(&bytes)?;
        assert!(view.report == input);
        let stored = service.read_report(&fixture.f.control, &view.id)?;
        assert_eq!(stored.digest, view.digest);
        assert_eq!(stored.label, view.label);
    }
    assert_eq!(product_counts(&fixture)?, (4, 0));
    assert_eq!(active_product_quota(&fixture, "reports")?, 4);
    assert_eq!(evidence_owners(&fixture, &references)?, vec![1; 4]);
    assert_eq!(fixture.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&fixture.f.path)?, 0);

    let input = DecisionReportV1 {
        attachments: BoundedList::new(references.clone())?,
        ..report(&fixture, &workflow, references[0].clone())?
    };
    input.validate()?;
    let command = CommandId::new("bounded-joined-report")?;
    let fields = serde_json::json!({
        "command_id":command,
        "report":text::<32768,_>(&input)?.as_str(),
    });
    for permission in [
        RecoveryPermission::Report,
        RecoveryPermission::KnowledgeRead,
    ] {
        assert_eq!(fixture.actor(permission)?.permission(), permission);
    }
    let before = snapshot(&fixture)?;
    eprintln!("bounded intake phase=authorized four-artifact report join");
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(request(
                &fixture,
                "/v1/recovery/reports/submit",
                fields.clone(),
            )?)
            .await?;
        require_refused_body(response).await?;
        assert_eq!(snapshot(&fixture)?, before);
        assert_eq!(product_counts(&fixture)?, (4, 0));
        assert_eq!(active_product_quota(&fixture, "reports")?, 4);
        assert_eq!(evidence_owners(&fixture, &references)?, vec![1; 4]);
    }
    assert_eq!(
        service
            .submit_report(&fixture.f.control, &command, &input)
            .err(),
        Some(crate::recovery::RecoveryRuntimeError::Unavailable),
    );
    assert_eq!(snapshot(&fixture)?, before);
    assert_eq!(fixture.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&fixture.f.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn proposal_intake_refuses_an_oversized_join_without_committing_or_repinning() -> TestResult {
    let (fixture, workflow, references) = published_parts(true).await?;
    let service = Arc::new(maintenance(&fixture)?);
    let input = DecisionReportV1 {
        attachments: BoundedList::new(vec![])?,
        ..report(&fixture, &workflow, references[0].clone())?
    };
    let stored_report = service.submit_report(
        &fixture.f.control,
        &CommandId::new("bounded-proposal-source-report")?,
        &input,
    )?;
    let router = crate::recovery::recovery_maintenance_router(service.clone());
    let calls = fixture.f.process.process("root")?.tree_calls;
    for (part, reference) in references.iter().enumerate() {
        let mut input = lifecycle::proposal(&fixture, &service, &stored_report, reference)?;
        input.proposal_id = ReviewId::new(&format!("bounded-part-proposal-{part}"))?;
        let fields = serde_json::json!({"proposal":text::<32768,_>(&input)?.as_str()});
        let response = router
            .clone()
            .oneshot(request(&fixture, "/v1/recovery/policy/propose", fields)?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), RECORD_CEILING).await?;
        let view: PolicyMaintenanceViewV1 = serde_json::from_slice(&bytes)?;
        assert!(view.proposal == input);
        let stored = service.propose(&fixture.f.control, &input)?;
        assert_eq!(stored.digest, view.digest);
        assert_eq!(stored.label, view.label);
    }
    assert_eq!(product_counts(&fixture)?, (1, 4));
    assert_eq!(active_product_quota(&fixture, "reports")?, 1);
    assert_eq!(active_product_quota(&fixture, "proposals")?, 4);
    assert_eq!(evidence_owners(&fixture, &references)?, vec![1; 4]);
    assert_eq!(fixture.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&fixture.f.path)?, 0);

    let mut input = lifecycle::proposal(&fixture, &service, &stored_report, &references[0])?;
    input.proposal_id = ReviewId::new("bounded-joined-proposal")?;
    let cases = |prefix: &str| {
        references
            .iter()
            .enumerate()
            .map(|(part, artifact)| {
                Ok(PolicyTrajectoryRefV1 {
                    artifact: artifact.clone(),
                    case_id: EvidenceRef::new(&format!("{prefix}-{part}"))?,
                })
            })
            .collect::<TestResult<Vec<_>>>()
    };
    input.benign_trajectories = NonEmptyBoundedList::new(cases("bounded-benign")?)?;
    input.adversarial_trajectories = NonEmptyBoundedList::new(cases("bounded-adversarial")?)?;
    input.validate()?;
    let fields = serde_json::json!({"proposal":text::<32768,_>(&input)?.as_str()});
    for permission in [
        RecoveryPermission::Maintain,
        RecoveryPermission::KnowledgeRead,
    ] {
        assert_eq!(fixture.actor(permission)?.permission(), permission);
    }
    let before = snapshot(&fixture)?;
    eprintln!("bounded intake phase=authorized four-artifact proposal join");
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(request(
                &fixture,
                "/v1/recovery/policy/propose",
                fields.clone(),
            )?)
            .await?;
        require_refused_body(response).await?;
        assert_eq!(snapshot(&fixture)?, before);
        assert_eq!(product_counts(&fixture)?, (1, 4));
        assert_eq!(active_product_quota(&fixture, "reports")?, 1);
        assert_eq!(active_product_quota(&fixture, "proposals")?, 4);
        assert_eq!(evidence_owners(&fixture, &references)?, vec![1; 4]);
    }
    assert_eq!(
        service.propose(&fixture.f.control, &input).err(),
        Some(crate::recovery::RecoveryRuntimeError::Unavailable),
    );
    assert_eq!(snapshot(&fixture)?, before);
    assert_eq!(fixture.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&fixture.f.path)?, 0);
    Ok(())
}
