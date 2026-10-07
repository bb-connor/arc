use super::*;

#[test]
fn busy_checkpoint_without_frame_counts_refuses_admission() -> Result<(), Box<dyn std::error::Error>>
{
    let connection = Connection::open_in_memory()?;
    // SQLite returns this exact observation when another checkpoint owns the
    // lock. The valid preceding NOOP measurement must not become zero pressure.
    assert!(wal_backlog(&connection, "SELECT 1, -1, -1").is_err());
    Ok(())
}

#[test]
fn intake_and_settlement_require_distinct_free_space_reserves() {
    let usage = PhysicalUsage {
        wal: 0,
        available: 128 * MIB - 1,
    };
    assert!(!admits(usage, true));
    assert!(admits(usage, false));
    assert!(!admits(
        PhysicalUsage {
            available: 16 * MIB - 1,
            ..usage
        },
        false
    ));
}

#[cfg(unix)]
#[test]
fn intake_recovers_after_reader_release_without_operator_checkpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("reader-pressure.db");
    let writer = Connection::open(&path)?;
    initialize_history(&writer)?;
    let reader = Connection::open(&path)?;
    reader.execute_batch("BEGIN;")?;
    assert_eq!(history_count(&reader)?, 1);
    append_history(&writer, 17)?;
    let high_water = std::fs::metadata(format!("{}-wal", path.display()))?.len();
    assert!(high_water > 64 * MIB);
    assert!(check(&writer, true).is_err());
    check(&writer, false)?;
    assert_eq!(history_count(&reader)?, 1);
    assert_eq!(history_count(&writer)?, 18);

    reader.execute_batch("ROLLBACK;")?;
    check(&writer, true)?;
    assert_eq!(history_count(&writer)?, 18);
    assert_eq!(
        writer.query_row("SELECT payload FROM retained WHERE id=1", [], |row| {
            row.get::<_, Vec<u8>>(0)
        })?,
        [1, 2, 3]
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn capture_writer_ignores_checkpointed_wal_high_water() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("capture-pressure.db");
    let mut writer = Connection::open(&path)?;
    initialize_history(&writer)?;
    let reader = Connection::open(&path)?;
    reader.execute_batch("BEGIN;")?;
    assert_eq!(history_count(&reader)?, 1);
    append_history(&writer, 33)?;
    assert!(std::fs::metadata(format!("{}-wal", path.display()))?.len() > 128 * MIB);
    assert!(check(&writer, false).is_err());
    reader.execute_batch("ROLLBACK;")?;
    let (busy, log, checkpointed): (i64, i64, i64) =
        writer.query_row("PRAGMA main.wal_checkpoint(PASSIVE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    assert_eq!(busy, 0);
    assert_eq!(log, checkpointed);
    assert!(std::fs::metadata(format!("{}-wal", path.display()))?.len() > 128 * MIB);

    let tx = writer.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    check_committing(&tx)?;
    tx.execute("INSERT INTO retained(payload) VALUES(X'040506')", [])?;
    tx.commit()?;
    assert_eq!(history_count(&writer)?, 35);
    Ok(())
}

#[cfg(unix)]
#[test]
#[ignore = "materializes two GiB of unrelated retained history"]
fn unrelated_retained_history_above_two_gib_preserves_recovery(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("retained-history.db");
    let mut writer = Connection::open(&path)?;
    initialize_history(&writer)?;
    for _ in 0..129 {
        writer.execute(
            "INSERT INTO retained(payload) VALUES(zeroblob(16777216))",
            [],
        )?;
        let (busy, log, checkpointed): (i64, i64, i64) =
            writer.query_row("PRAGMA main.wal_checkpoint(PASSIVE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
        assert_eq!(busy, 0);
        assert_eq!(log, checkpointed);
    }
    assert!(std::fs::metadata(&path)?.len() > 2048 * MIB);
    check(&writer, true)?;
    check(&writer, false)?;
    let tx = writer.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    check_committing(&tx)?;
    tx.execute("INSERT INTO retained(payload) VALUES(X'040506')", [])?;
    tx.commit()?;
    assert_eq!(history_count(&writer)?, 131);
    Ok(())
}

#[cfg(unix)]
fn initialize_history(writer: &Connection) -> Result<(), rusqlite::Error> {
    writer.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA wal_autocheckpoint=0;
         CREATE TABLE retained(id INTEGER PRIMARY KEY, payload BLOB NOT NULL);
         INSERT INTO retained VALUES(1,X'010203');",
    )?;
    let _: (i64, i64, i64) =
        writer.query_row("PRAGMA main.wal_checkpoint(PASSIVE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    Ok(())
}

#[cfg(unix)]
fn append_history(writer: &Connection, records: usize) -> Result<(), rusqlite::Error> {
    for _ in 0..records {
        writer.execute(
            "INSERT INTO retained(payload) VALUES(zeroblob(4194304))",
            [],
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn history_count(connection: &Connection) -> Result<i64, rusqlite::Error> {
    connection.query_row("SELECT count(*) FROM retained", [], |row| row.get(0))
}
