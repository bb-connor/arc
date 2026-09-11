use super::*;
use rusqlite::types::Value;

#[test]
fn missing_native_schema_does_not_fall_back_to_legacy_evidence() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteSecurityStateStore::open(directory.path().join("legacy.db"))?;
    let connection = store.connection()?;
    let query = evidence_query(
        &consumption("tenant", "grant")?,
        DeclassificationEvidencePhase::Consumption,
    );
    assert!(records::load_evidence(ScopedReader::native(&connection, A), &query).is_err());
    assert!(records::load_evidence(ScopedReader::legacy(&connection), &query)?.is_none());
    assert!(verify_native_declassification_state(&connection, A).is_err());
    Ok(())
}

pub(super) fn all_rows(
    connection: &Connection,
    authority: Option<&str>,
) -> TestResult<Vec<Vec<Vec<Value>>>> {
    [
        "declassification_lifecycle",
        "declassification_uses",
        "declassification_receipt_outbox",
        "declassification_evidence_identity",
        "declassification_tombstones",
    ]
    .into_iter()
    .map(|suffix| {
        let source = format!("security_{suffix}");
        let fields = retained_security_columns(&source)?;
        let columns = fields.join(",");
        let (table, predicate) = match authority {
            Some(_) => (
                format!("security_participant_state_{suffix}"),
                " WHERE security_authority_id = ?1",
            ),
            None => (source, ""),
        };
        let mut statement = connection.prepare(&format!(
            "SELECT {columns} FROM {table}{predicate} ORDER BY {columns}"
        ))?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(authority), |row| {
                (0..fields.len())
                    .map(|index| row.get(index))
                    .collect::<rusqlite::Result<Vec<Value>>>()
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    })
    .collect()
}

#[test]
fn native_and_legacy_declassification_mutations_preserve_identical_retained_cells() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        let directory = tempfile::tempdir()?;
        let legacy = SqliteSecurityStateStore::open(directory.path().join("legacy.db"))?;
        let mut legacy_connection = legacy.connection()?;
        let owner = SecurityStateWriteTransaction::new(
            legacy_connection.transaction_with_behavior(TransactionBehavior::Immediate)?,
        )?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        seed_lifecycle(&tx, A)?;
        let native = ScopedMutation::native_for_test(&tx, A);
        let legacy = ScopedMutation::legacy(owner.transaction());
        for state in [&native, &legacy] {
            state.begin_declassification_reconciliation()?;
            state.end_declassification_reconciliation()?;
            state.seal_declassification_live_dispatch()?;
        }
        for grant in ["pending", "terminal", "compacted"] {
            let consumed = consumption("tenant", grant)?;
            for state in [&native, &legacy] {
                state.commit_declassification_consumption_evidence(&consumed, || Ok(1_000))?;
                state.record_declassification_evidence_retry(&retry(&consumed)?)?;
            }
            assert_eq!(
                all_rows(&tx, Some(A))?,
                all_rows(owner.transaction(), None)?
            );
            if grant == "pending" {
                continue;
            }
            let outcome = release(&consumed)?;
            for state in [&native, &legacy] {
                state.commit_declassification_outcome_evidence(&outcome)?;
                for (phase, receipt) in [
                    (
                        DeclassificationEvidencePhase::Consumption,
                        &consumed.receipt,
                    ),
                    (DeclassificationEvidencePhase::Outcome, &outcome.receipt),
                ] {
                    state.acknowledge_declassification_evidence(&ack(
                        &consumed.consumption.grant_id,
                        receipt,
                        phase,
                    ))?;
                }
            }
            assert_eq!(
                all_rows(&tx, Some(A))?,
                all_rows(owner.transaction(), None)?
            );
            if grant == "compacted" {
                let request = compaction_request(&consumed, &outcome)?;
                assert_eq!(
                    native.compact_declassification_evidence(&request)?,
                    legacy.compact_declassification_evidence(&request)?
                );
            }
            assert_eq!(
                all_rows(&tx, Some(A))?,
                all_rows(owner.transaction(), None)?
            );
        }
        assert!(all_rows(&tx, Some(B))?.iter().all(Vec::is_empty));
        integrity::verify(native.reader())?;
        integrity::verify(legacy.reader())?;
        owner.into_transaction().rollback()?;
        tx.rollback()?;
        Ok(())
    })
}

#[test]
fn native_flow_use_and_evidence_rollback_together_after_each_late_write_failure() -> TestResult {
    with_flow_sql_fixture(false, |connection| {
        for failing_phase in ["consumption", "outcome", "cancel"] {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            seed_lifecycle(&tx, A)?;
            let state = ScopedMutation::native_for_test(&tx, A);
            state.seal_declassification_live_dispatch()?;
            let consumed = consumption("tenant", "grant")?;
            // The trigger and all test-only native mutations share the rollback.
            tx.execute_batch(&format!("CREATE TRIGGER fail_native_outbox BEFORE INSERT ON security_participant_state_declassification_receipt_outbox WHEN NEW.phase = '{failing_phase}' BEGIN SELECT RAISE(ABORT, 'late evidence failure'); END;"))?;
            let join = FlowJoinRequest {
                key: FlowStateKey {
                    tenant_id: TenantId::new("tenant")?,
                    principal_id: chio_security_types::PrincipalId::new("principal")?,
                    lineage_id: chio_security_types::ports::LineageId::new("lineage")?,
                    session_id: chio_security_types::ports::SessionId::new("session")?,
                    isolation_epoch_id: chio_security_types::ports::IsolationEpochId::new("epoch")?,
                },
                principal_join: InformationLabel::bottom(),
                lineage_join: InformationLabel::bottom(),
                session_join: InformationLabel::bottom(),
                transition_id: RecordId::new("join")?,
            };
            state.join(&join)?;
            let result =
                state.commit_declassification_consumption_evidence(&consumed, || Ok(1_000));
            if failing_phase == "consumption" {
                assert!(result.is_err());
            } else {
                result?;
                if failing_phase == "outcome" {
                    assert!(state
                        .commit_declassification_outcome_evidence(&release(&consumed)?)
                        .is_err());
                }
            }
            drop(tx);
            assert!(connection.is_autocommit());
            assert!(all_rows(connection, Some(A))?.iter().all(Vec::is_empty));
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM security_participant_state_flow_contexts",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(count, 0);
        }
        Ok(())
    })
}
