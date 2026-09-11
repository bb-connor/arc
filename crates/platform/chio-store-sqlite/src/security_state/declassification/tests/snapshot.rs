use super::*;

struct FixedClock;
impl SecurityStateClock for FixedClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(1_000)
    }
}

#[test]
fn readiness_and_compaction_reads_keep_one_snapshot_across_concurrent_compaction() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let reader = SqliteSecurityStateStore::open_with_trusted_clock(&path, Arc::new(FixedClock))?;
    let writer = SqliteSecurityStateStore::open_with_trusted_clock(&path, Arc::new(FixedClock))?;
    writer.seal_declassification_live_dispatch()?;
    let consumed = consumption("tenant", "grant")?;
    let outcome = release(&consumed)?;
    writer.commit_declassification_consumption_evidence(&consumed)?;
    writer.commit_declassification_outcome_evidence(&outcome)?;
    for (phase, receipt) in [
        (
            DeclassificationEvidencePhase::Consumption,
            &consumed.receipt,
        ),
        (DeclassificationEvidencePhase::Outcome, &outcome.receipt),
    ] {
        writer.acknowledge_declassification_evidence(&ack(
            &consumed.consumption.grant_id,
            receipt,
            phase,
        ))?;
    }
    let request = compaction_request(&consumed, &outcome)?;
    let query = DeclassificationCompactionQuery {
        readiness_cursor: request.readiness_cursor.clone(),
        now_unix_ms: request.compacted_at_unix_ms,
        after_tenant_id: None,
        after_grant_id: None,
        max_records: 10,
    };
    reader.declassification_read(|tx| {
        // The retirement check has already pinned the read snapshot. Commit on
        // another real WAL connection before the first domain read, without
        // timing assumptions, sleeps or a production cutpoint.
        writer.compact_declassification_evidence(&request)?;
        validate_declassification_evidence_schema(tx)?;
        let scope = ScopedReader::legacy(tx);
        integrity::verify(scope)?;
        assert_eq!(
            scope
                .query_row(sql::COUNT_EVIDENCE, &[], |row| row.get::<_, i64>(0))
                .map_err(sqlite_error)?,
            2
        );
        assert_eq!(
            super::super::compaction::candidates(scope, &query)?.len(),
            1
        );
        Ok(())
    })?;
    assert!(reader
        .load_declassification_compaction_candidates(&query)?
        .is_empty());
    reader.ensure_declassification_evidence_ready()?;
    Ok(())
}

#[test]
fn late_compaction_failure_rolls_back_tombstone_deletes_and_lifecycle_flag() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("security.db");
    let store = SqliteSecurityStateStore::open_with_trusted_clock(&path, Arc::new(FixedClock))?;
    store.seal_declassification_live_dispatch()?;
    let consumed = consumption("tenant", "grant")?;
    let outcome = release(&consumed)?;
    store.commit_declassification_consumption_evidence(&consumed)?;
    store.commit_declassification_outcome_evidence(&outcome)?;
    for (phase, receipt) in [
        (
            DeclassificationEvidencePhase::Consumption,
            &consumed.receipt,
        ),
        (DeclassificationEvidencePhase::Outcome, &outcome.receipt),
    ] {
        store.acknowledge_declassification_evidence(&ack(
            &consumed.consumption.grant_id,
            receipt,
            phase,
        ))?;
    }
    let connection = Connection::open(path)?;
    let before = equivalence::all_rows(&connection, None)?;
    connection.execute_batch("CREATE TRIGGER reject_compaction_use_delete BEFORE DELETE ON security_declassification_uses BEGIN SELECT RAISE(ABORT, 'injected final delete failure'); END;")?;
    assert!(store
        .compact_declassification_evidence(&compaction_request(&consumed, &outcome)?)
        .is_err());
    assert_eq!(equivalence::all_rows(&connection, None)?, before);
    lifecycle::verify(ScopedReader::legacy(&connection))?;
    integrity::verify(ScopedReader::legacy(&connection))?;
    Ok(())
}
