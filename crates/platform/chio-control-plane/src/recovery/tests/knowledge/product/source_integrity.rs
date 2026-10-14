//! External retained-source loss fences public reads without leaking their content.
use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chio_kernel::{KernelError, RevocationStoreError};
use rusqlite::types::Value;
use tower::ServiceExt;

type PhysicalRow = (
    String,
    String,
    String,
    i64,
    Vec<u8>,
    Option<String>,
    Option<String>,
);

fn physical_records(connection: &rusqlite::Connection) -> TestResult<Vec<PhysicalRow>> {
    let mut query = connection.prepare(
        "SELECT record_key,scope_key,kind,version,payload,native_namespace,native_request
         FROM admission_operation_recovery_records ORDER BY record_key",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        ))
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn retained_history(connection: &rusqlite::Connection) -> TestResult<Vec<Vec<Vec<Value>>>> {
    let mut history = Vec::new();
    for sql in [
        "SELECT * FROM admission_operation_recovery_events ORDER BY sequence",
        "SELECT * FROM authority_global_commits ORDER BY commit_sequence",
    ] {
        let mut query = connection.prepare(sql)?;
        let count = query.column_count();
        let rows = query.query_map([], |row| {
            (0..count)
                .map(|column| row.get::<_, Value>(column))
                .collect::<Result<Vec<_>, _>>()
        })?;
        history.push(rows.collect::<Result<Vec<_>, _>>()?);
    }
    Ok(history)
}

type PhysicalProcessCounters = (
    Vec<(String, Option<String>, String, i64, String, i64, i64)>,
    Vec<(String, String, i64)>,
);

fn physical_process_counters(
    connection: &rusqlite::Connection,
) -> TestResult<PhysicalProcessCounters> {
    let mut processes = connection.prepare(
        "SELECT id,parent_id,root_id,depth,state,revision,tree_calls
         FROM processes ORDER BY id",
    )?;
    let process_rows = processes.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        ))
    })?;
    let process_rows = process_rows.collect::<Result<Vec<_>, _>>()?;
    let mut calls = connection.prepare(
        "SELECT process_id,operation_key,attempts
         FROM process_calls ORDER BY process_id,operation_key",
    )?;
    let call_rows = calls.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    Ok((process_rows, call_rows.collect::<Result<Vec<_>, _>>()?))
}

#[tokio::test]
async fn a_current_native_reader_gets_unavailable_when_retained_report_projection_disappears(
) -> TestResult {
    eprintln!("retained source phase=current native fixture");
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    eprintln!("retained source phase=current native workflow");
    let workflow = Box::pin(f.f.ready()).await?;
    let input = DecisionReportV1 {
        domain_version: VersionV1,
        scope: f.f.runtime.scope().clone(),
        workflow_id: workflow.clone(),
        expected_revision: f.f.record(&workflow)?.revision,
        decision: RecoveryReportedDecision::NeedsReview,
        reporter_text: ProtectedText::new("retained source operational canary")?,
        desired_outcome: ProtectedText::new("read the authentic retained source")?,
        attachments: BoundedList::new(vec![])?,
    };
    eprintln!("retained source phase=current maintenance service");
    let service = Arc::new(maintenance(&f)?);
    eprintln!("retained source phase=first native report submission");
    let first = service.submit_report(
        &f.f.control,
        &CommandId::new("retained-source-positive-first")?,
        &input,
    )?;
    // Keep a later authentic native head. Only the first current projection is
    // removed; the immutable event and global chain remain intact.
    eprintln!("retained source phase=later native report submission");
    let second = service.submit_report(
        &f.f.control,
        &CommandId::new("retained-source-positive-head")?,
        &input,
    )?;
    assert_ne!(first.id, second.id);
    assert!(!matches!(first.label, InformationLabel::Top));
    eprintln!("retained source phase=healthy current native reader");
    let inspector = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    let profile = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    let assignment = profile
        .actors
        .as_slice()
        .iter()
        .find(|value| {
            value.principal == *inspector.principal()
                && value.subject == inspector.capability().subject
        })
        .ok_or("current assigned native reader")?;
    assert!(!matches!(
        assignment.preview_clearance,
        InformationLabel::Top
    ));
    assert!(first.label.flows_to(&assignment.preview_clearance));
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
    eprintln!("retained source phase=healthy native report routes");
    for actual in [&first, &second] {
        let response = router.clone().oneshot(request(&actual.id)?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 262_144).await?;
        let view: DecisionReportViewV1 = chio_core_types::recovery::decode_contract(&body)?;
        assert_eq!(view.report, actual.report);
    }
    eprintln!("retained source phase=before-fault native process counters");
    let calls = f.f.process.process("root")?.tree_calls;
    let effects = external_count(&f.f.path)?;
    eprintln!("retained source phase=before-fault canonical private root");
    let original_process_path = f.f.path.join("process.db");
    let original_process_file = std::fs::symlink_metadata(&original_process_path)?;
    assert!(original_process_file.is_file());
    // Resolve the trusted fixture's directory alias before NOFOLLOW opens the
    // same regular leaf. The native journal also binds its canonical path.
    let canonical_root = std::fs::canonicalize(&f.f.path)?;
    let original_directory = std::fs::metadata(&f.f.path)?;
    let canonical_directory = std::fs::symlink_metadata(&canonical_root)?;
    assert!(original_directory.is_dir() && canonical_directory.is_dir());
    let process_path = canonical_root.join("process.db");
    let process_file = std::fs::symlink_metadata(&process_path)?;
    assert!(process_file.is_file());
    assert_eq!(std::fs::canonicalize(&original_process_path)?, process_path);
    #[cfg(unix)]
    let (directory_identity, process_identity) = {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        assert_eq!(
            (original_directory.dev(), original_directory.ino()),
            (canonical_directory.dev(), canonical_directory.ino())
        );
        assert_eq!(
            (original_process_file.dev(), original_process_file.ino()),
            (process_file.dev(), process_file.ino())
        );
        assert_eq!(canonical_directory.permissions().mode() & 0o077, 0);
        assert_eq!(process_file.permissions().mode() & 0o077, 0);
        assert_eq!(process_file.nlink(), 1);
        (
            (canonical_directory.dev(), canonical_directory.ino()),
            (process_file.dev(), process_file.ino()),
        )
    };
    // This owned read-only connection observes counters, never native authority,
    // capability material, object bytes or readiness after the external fault.
    eprintln!("retained source phase=before-fault nofollow physical counter open");
    let process_connection = rusqlite::Connection::open_with_flags(
        &process_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let (version, namespace): (u32, String) = process_connection.query_row(
        "SELECT version,namespace FROM process_runtime WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(version, 5);
    assert_eq!(namespace, f.f.process.runtime_id());
    let physical_calls: u32 = process_connection.query_row(
        "SELECT root.tree_calls FROM processes p
         JOIN processes root ON p.root_id=root.id WHERE p.id='root'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(physical_calls, calls);
    let process_before = physical_process_counters(&process_connection)?;
    eprintln!("retained source phase=healthy native and physical counters agree");
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let records_before = physical_records(&connection)?;
    let history_before = retained_history(&connection)?;
    let scope =
        chio_core_types::sha256_hex(&chio_core_types::canonical_json_bytes(f.f.runtime.scope())?);
    let key = format!("product-report:{scope}:{}", first.id.as_str());
    let selected_rows = records_before
        .iter()
        .filter(|row| row.0 == key)
        .collect::<Vec<_>>();
    let [physical] = selected_rows.as_slice() else {
        return Err("actual retained first report row identity".into());
    };
    assert_eq!(physical.1, scope);
    assert_eq!(physical.2, "command");
    assert_eq!(physical.3, 1);
    assert!(physical.5.is_none() && physical.6.is_none());
    assert_eq!(physical.4, chio_core_types::canonical_json_bytes(&first)?);
    let trigger: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='admission_operation_recovery_no_delete'",
        [], |row| row.get(0),
    )?;
    connection.pragma_update(None, "foreign_keys", false)?;
    let foreign_keys: bool = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    assert!(
        !foreign_keys,
        "this isolated corruption writer must not mutate the native event history"
    );
    // Simulate one lost projection in this owned fixture. This grants no native
    // mutation or recovery role, and neither reseals nor erases retained history.
    eprintln!("retained source phase=isolated current projection loss");
    connection.execute_batch("DROP TRIGGER admission_operation_recovery_no_delete")?;
    assert_eq!(
        connection.execute(
            "DELETE FROM admission_operation_recovery_records WHERE record_key=?1",
            [&key],
        )?,
        1
    );
    connection.execute_batch(&trigger)?;
    assert_eq!(retained_history(&connection)?, history_before);
    let after_loss = physical_records(&connection)?;
    assert_eq!(after_loss.len() + 1, records_before.len());
    assert_eq!(
        after_loss,
        records_before
            .into_iter()
            .filter(|row| row.0 != key)
            .collect::<Vec<_>>()
    );
    // The exact current caller remains unchanged. Native reauthentication must
    // observe the real external-writer fence, before any retained-row loader.
    // No native connection is refreshed, resealed or replaced after the fault.
    eprintln!("retained source phase=after-fault current native authentication");
    let rejected = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    );
    assert!(matches!(
        rejected,
        Err(KernelError::RevocationStore(
            RevocationStoreError::OutcomeUnknown(_)
        )),
    ));
    eprintln!("retained source phase=actual external authority fence confirmed");
    for actual in [&first, &second] {
        eprintln!("retained source phase=after-fault report route");
        let response = router.clone().oneshot(request(&actual.id)?).await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 1_024).await?;
        assert_eq!(body.as_ref(), b"recovery.unavailable");
        assert!(!String::from_utf8_lossy(&body).contains("retained source operational canary"));
    }
    eprintln!("retained source phase=after-fault physical accounting");
    assert_eq!(physical_records(&connection)?, after_loss);
    assert_eq!(retained_history(&connection)?, history_before);
    assert_eq!(
        physical_process_counters(&process_connection)?,
        process_before
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let retained_directory = std::fs::symlink_metadata(&canonical_root)?;
        let retained_process_file = std::fs::symlink_metadata(&process_path)?;
        assert!(retained_directory.is_dir() && retained_process_file.is_file());
        assert_eq!(
            (retained_directory.dev(), retained_directory.ino()),
            directory_identity
        );
        assert_eq!(
            (retained_process_file.dev(), retained_process_file.ino()),
            process_identity
        );
        assert_eq!(retained_directory.permissions().mode() & 0o077, 0);
        assert_eq!(retained_process_file.permissions().mode() & 0o077, 0);
        assert_eq!(retained_process_file.nlink(), 1);
    }
    assert_eq!(external_count(&f.f.path)?, effects);
    eprintln!("retained source phase=unchanged physical accounting confirmed");
    Ok(())
}
