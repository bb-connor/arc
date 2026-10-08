//! A genuine foreign terminal cannot replace a Proposal's exact retired custody.
use super::*;
use chio_kernel::admission_operation::AdmissionOperationStoreError;
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

fn retained_custody(connection: &rusqlite::Connection) -> TestResult<Vec<Rows>> {
    [
        "SELECT record_key,scope_key,kind,version,payload,native_namespace,native_request
         FROM main.admission_operation_recovery_records ORDER BY record_key",
        "SELECT * FROM main.admission_operation_recovery_events ORDER BY sequence",
        "SELECT * FROM main.authority_global_commits ORDER BY commit_sequence",
        "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name",
    ]
    .into_iter()
    .map(|sql| rows(connection, sql))
    .collect()
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

#[tokio::test]
async fn retired_proposal_custody_rejects_another_genuine_proposal_terminal_without_mutation(
) -> TestResult {
    let mut fixture =
        KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    maintain(&mut fixture)?;
    let workflow = Box::pin(fixture.f.ready()).await?;
    let artifact = fixture.publish("proposal-terminal-custody", b"native policy trajectory")?;
    let service = maintenance(&fixture)?;
    let report = service.submit_report(
        &fixture.f.control,
        &CommandId::new("proposal-terminal-custody-report")?,
        &DecisionReportV1 {
            attachments: BoundedList::new(vec![])?,
            ..report(&fixture, &workflow, artifact.clone())?
        },
    )?;
    let first = lifecycle::proposal(&fixture, &service, &report, &artifact)?;
    let second = PolicyMaintenanceProposalV1 {
        proposal_id: ReviewId::new("other-genuine-proposal-terminal")?,
        ..first.clone()
    };
    let first_stored = service.propose(&fixture.f.control, &first)?;
    let second_stored = service.propose(&fixture.f.control, &second)?;
    assert_ne!(first_stored.digest, second_stored.digest);
    let store = fixture.f.authority.admission_operation_store();
    let fence = fixture.f.authority.mutation_fence();
    let actor = fixture.actor(RecoveryPermission::Maintain)?;
    let reader = fixture.actor(RecoveryPermission::KnowledgeRead)?;
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        2,
        "both genuine immutable sources must own the same complete trajectory",
    );
    for proposal in [&first, &second] {
        store.archive_policy_maintenance(
            &actor,
            &reader,
            &proposal.proposal_id,
            &fence,
            now_ms()?,
        )?;
        assert_eq!(
            store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
            2,
            "archive alone cannot retire either source owner",
        );
    }
    store.reclaim_archived_policy_evidence(
        &actor,
        &reader,
        &first.proposal_id,
        &fence,
        now_ms()?,
    )?;
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        1,
    );
    assert!(fixture
        .runtime
        .collect(&fixture.f.control, &artifact)
        .is_err());
    store.reclaim_archived_policy_evidence(
        &actor,
        &reader,
        &second.proposal_id,
        &fence,
        now_ms()?,
    )?;
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        0,
    );
    fixture.runtime.collect(&fixture.f.control, &artifact)?;
    let scope = fixture.f.runtime.scope();
    let path = std::fs::canonicalize(&fixture.f.path)?;
    let connection = rusqlite::Connection::open(path.join("admission.db"))?;
    let process_path = path.join("process.db");
    let process_file = std::fs::symlink_metadata(&process_path)?;
    let directory = std::fs::symlink_metadata(&path)?;
    assert!(process_file.is_file() && directory.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        assert_eq!(directory.permissions().mode() & 0o077, 0);
        assert_eq!(process_file.permissions().mode() & 0o077, 0);
        assert_eq!(process_file.nlink(), 1);
    }
    let process = rusqlite::Connection::open_with_flags(
        process_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let custody_before = retained_custody(&connection)?;
    let process_before = process_accounting(&process)?;
    let calls = fixture.f.process.process("root")?.tree_calls;
    let (version, namespace, physical_calls): (u32, String, u32) = process.query_row(
        "SELECT version,namespace,(SELECT tree_calls FROM main.processes WHERE id='root')
         FROM main.process_runtime WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(version, 5);
    assert_eq!(namespace, fixture.f.process.runtime_id());
    assert_eq!(physical_calls, calls);
    assert_eq!(external_count(&fixture.f.path)?, 0);

    for proposal in [&first, &second] {
        store.inspect_retired_proposal_terminal_custody(
            scope,
            &proposal.proposal_id,
            &proposal.proposal_id,
            &fence,
            now_ms()?,
        )?;
    }
    for (original, foreign) in [(&first, &second), (&second, &first)] {
        assert!(matches!(
            store.inspect_retired_proposal_terminal_custody(
                scope,
                &original.proposal_id,
                &foreign.proposal_id,
                &fence,
                now_ms()?,
            ),
            Err(AdmissionOperationStoreError::Invariant(_)),
        ));
    }
    // The same exact owning observer remains healthy after both refusals.
    for proposal in [&first, &second] {
        store.inspect_retired_proposal_terminal_custody(
            scope,
            &proposal.proposal_id,
            &proposal.proposal_id,
            &fence,
            now_ms()?,
        )?;
    }
    assert_eq!(service.propose(&fixture.f.control, &first)?, first_stored);
    assert_eq!(service.propose(&fixture.f.control, &second)?, second_stored);
    assert_eq!(active_product_quota(&fixture, "proposals")?, 0);
    assert_eq!(active_product_quota(&fixture, "reports")?, 1);
    assert_eq!(retained_custody(&connection)?, custody_before);
    assert_eq!(process_accounting(&process)?, process_before);
    assert_eq!(fixture.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&fixture.f.path)?, 0);
    Ok(())
}
