//! A lost or corrupt real reclamation terminal cannot authorize retained replay.
use super::*;
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use chio_store_sqlite::SqliteServingOwnerError;
use rusqlite::types::Value;

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

fn records(connection: &rusqlite::Connection) -> TestResult<Rows> {
    rows(
        connection,
        "SELECT record_key,scope_key,kind,version,payload,native_namespace,native_request
         FROM main.admission_operation_recovery_records ORDER BY record_key",
    )
}

fn history(connection: &rusqlite::Connection) -> TestResult<Vec<Rows>> {
    [
        "SELECT * FROM main.admission_operation_recovery_events ORDER BY sequence",
        "SELECT * FROM main.authority_global_commits ORDER BY commit_sequence",
    ]
    .into_iter()
    .map(|sql| rows(connection, sql))
    .collect()
}

fn catalog(connection: &rusqlite::Connection) -> TestResult<Rows> {
    rows(
        connection,
        "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name",
    )
}

fn process_accounting(connection: &rusqlite::Connection) -> TestResult<Vec<Rows>> {
    [
        "SELECT id,parent_id,root_id,depth,state,revision,tree_calls
         FROM main.processes ORDER BY id",
        "SELECT process_id,operation_key,attempts FROM main.process_calls
         ORDER BY process_id,operation_key",
    ]
    .into_iter()
    .map(|sql| rows(connection, sql))
    .collect()
}

#[derive(Clone, Copy)]
enum TerminalFault {
    ProjectionLoss,
    NoncanonicalPayload,
}

async fn refuses_corrupt_retained_terminal(fault: TerminalFault) -> TestResult {
    eprintln!("reclamation integrity phase=genuine current native producer");
    let mut fixture =
        KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    maintain(&mut fixture)?;
    let workflow = Box::pin(fixture.f.ready()).await?;
    let artifact = fixture.publish("reclamation-integrity-evidence", b"native policy evidence")?;
    let input = DecisionReportV1 {
        attachments: BoundedList::new(vec![])?,
        ..report(&fixture, &workflow, artifact.clone())?
    };
    let service = maintenance(&fixture)?;
    let report = service.submit_report(
        &fixture.f.control,
        &CommandId::new("reclamation-integrity-report")?,
        &input,
    )?;
    let proposal = lifecycle::proposal(&fixture, &service, &report, &artifact)?;
    let stored = service.propose(&fixture.f.control, &proposal)?;
    let store = fixture.f.authority.admission_operation_store();
    let fence = fixture.f.authority.mutation_fence();
    let actor = fixture.actor(RecoveryPermission::Maintain)?;
    let reader = fixture.actor(RecoveryPermission::KnowledgeRead)?;
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        1,
    );
    store.archive_policy_maintenance(&actor, &reader, &proposal.proposal_id, &fence, now_ms()?)?;
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        1,
        "the actual archive must retain its complete original evidence owner",
    );
    eprintln!("reclamation integrity phase=actual separate native terminal");
    store.reclaim_archived_policy_evidence(
        &actor,
        &reader,
        &proposal.proposal_id,
        &fence,
        now_ms()?,
    )?;
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        0,
    );
    fixture.runtime.collect(&fixture.f.control, &artifact)?;
    let path = std::fs::canonicalize(&fixture.f.path)?;
    let connection = rusqlite::Connection::open(path.join("admission.db"))?;
    let healthy_records = records(&connection)?;
    assert_eq!(service.propose(&fixture.f.control, &proposal)?, stored);
    assert!(
        records(&connection)? == healthy_records,
        "healthy exact replay must append no pin or source after actual collection",
    );
    assert_eq!(active_product_quota(&fixture, "proposals")?, 0);
    assert_eq!(active_product_quota(&fixture, "reports")?, 1);
    let scope = chio_core_types::sha256_hex(&chio_core_types::canonical_json_bytes(
        fixture.f.runtime.scope(),
    )?);
    let key = format!(
        "product-disposition:reclaimed-proposal-evidence:{scope}:{}",
        proposal.proposal_id.as_str(),
    );
    let (version, payload, local): (i64, Vec<u8>, bool) = connection.query_row(
        "SELECT version,payload,native_namespace IS NULL AND native_request IS NULL
         FROM main.admission_operation_recovery_records WHERE record_key=?1
           AND scope_key=?2 AND kind='command'",
        rusqlite::params![&key, &scope],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(version, 1);
    assert!(local);
    let value: serde_json::Value = serde_json::from_slice(&payload)?;
    assert_eq!(chio_core_types::canonical_json_bytes(&value)?, payload);
    let calls = fixture.f.process.process("root")?.tree_calls;
    let effects = external_count(&path)?;
    assert_eq!(effects, 0);
    let process_path = path.join("process.db");
    let process_file = std::fs::symlink_metadata(&process_path)?;
    let directory_metadata = std::fs::symlink_metadata(&path)?;
    assert!(process_file.is_file() && directory_metadata.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        assert_eq!(directory_metadata.permissions().mode() & 0o077, 0);
        assert_eq!(process_file.permissions().mode() & 0o077, 0);
        assert_eq!(process_file.nlink(), 1);
    }
    let process = rusqlite::Connection::open_with_flags(
        process_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let (process_version, namespace, physical_calls): (u32, String, u32) = process.query_row(
        "SELECT version,namespace,(SELECT tree_calls FROM main.processes WHERE id='root')
         FROM main.process_runtime WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(process_version, 5);
    assert_eq!(namespace, fixture.f.process.runtime_id());
    assert_eq!(physical_calls, calls);
    let process_before = process_accounting(&process)?;
    let history_before = history(&connection)?;
    let catalog_before = catalog(&connection)?;
    eprintln!("reclamation integrity phase=isolated retained terminal corruption");
    match fault {
        TerminalFault::ProjectionLoss => {
            let trigger: String = connection.query_row(
                "SELECT sql FROM main.sqlite_schema WHERE type='trigger'
                 AND name='admission_operation_recovery_no_delete'",
                [],
                |row| row.get(0),
            )?;
            connection.pragma_update(None, "foreign_keys", false)?;
            connection.execute_batch("DROP TRIGGER main.admission_operation_recovery_no_delete")?;
            assert_eq!(
                connection.execute(
                    "DELETE FROM main.admission_operation_recovery_records WHERE record_key=?1",
                    [&key],
                )?,
                1,
            );
            connection.execute_batch(&trigger)?;
        }
        TerminalFault::NoncanonicalPayload => {
            let trigger: String = connection.query_row(
                "SELECT sql FROM main.sqlite_schema WHERE type='trigger'
                 AND name='admission_operation_recovery_identity'",
                [],
                |row| row.get(0),
            )?;
            let mut corrupted = vec![b' '];
            corrupted.extend_from_slice(&payload);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&corrupted)?,
                value
            );
            assert_ne!(corrupted, payload);
            connection.execute_batch("DROP TRIGGER main.admission_operation_recovery_identity")?;
            assert_eq!(
                connection.execute(
                    "UPDATE main.admission_operation_recovery_records SET payload=?1
                     WHERE record_key=?2 AND version=1",
                    rusqlite::params![corrupted, &key],
                )?,
                1,
            );
            connection.execute_batch(&trigger)?;
        }
    }
    assert!(history(&connection)? == history_before);
    assert!(catalog(&connection)? == catalog_before);
    let corrupted_records = records(&connection)?;
    match fault {
        TerminalFault::ProjectionLoss => {
            assert_eq!(corrupted_records.len() + 1, healthy_records.len());
        }
        TerminalFault::NoncanonicalPayload => {
            assert_eq!(corrupted_records.len(), healthy_records.len());
        }
    }
    let changed: Vec<_> = healthy_records
        .iter()
        .filter(|row| {
            corrupted_records
                .iter()
                .find(|candidate| candidate[0] == row[0])
                != Some(*row)
        })
        .collect();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0][0], Value::Text(key));
    eprintln!("reclamation integrity phase=actual warm external-writer refusal");
    assert!(matches!(
        service.propose(&fixture.f.control, &proposal),
        Err(crate::recovery::RecoveryRuntimeError::Unavailable),
    ));
    assert!(matches!(
        store.reclaim_archived_policy_evidence(
            &actor,
            &reader,
            &proposal.proposal_id,
            &fence,
            now_ms()?,
        ),
        Err(AdmissionOperationStoreError::OutcomeUnknown(_)),
    ));
    assert!(records(&connection)? == corrupted_records);
    assert!(history(&connection)? == history_before);
    assert!(catalog(&connection)? == catalog_before);
    assert!(process_accounting(&process)? == process_before);
    let _directory = fixture.f._directory.take();
    drop(service);
    drop(store);
    drop(fixture);
    eprintln!("reclamation integrity phase=actual cold integrity refusal");
    match SqliteAuthorityStore::open_serving(path.join("admission.db"), path.join("locks")) {
        Err(SqliteServingOwnerError::Invalid(_)) => {}
        Err(error) => {
            return Err(format!(
                "cold terminal integrity refused at the wrong prerequisite: {error}"
            )
            .into())
        }
        Ok(_) => {
            return Err("cold serving accepted its corrupt retained reclamation terminal".into())
        }
    }
    assert!(records(&connection)? == corrupted_records);
    assert!(history(&connection)? == history_before);
    assert!(catalog(&connection)? == catalog_before);
    assert!(process_accounting(&process)? == process_before);
    assert_eq!(external_count(&path)?, effects);
    eprintln!("reclamation integrity phase=all original history and debits preserved");
    Ok(())
}

#[tokio::test]
async fn lost_reclamation_terminal_refuses_retained_replay_without_repairing_custody() -> TestResult
{
    refuses_corrupt_retained_terminal(TerminalFault::ProjectionLoss).await
}

#[tokio::test]
async fn noncanonical_reclamation_terminal_refuses_retained_replay_without_resigning_history(
) -> TestResult {
    refuses_corrupt_retained_terminal(TerminalFault::NoncanonicalPayload).await
}
