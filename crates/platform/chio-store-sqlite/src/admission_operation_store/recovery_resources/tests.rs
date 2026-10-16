use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn usage(wal: u64, available: u64) -> PhysicalUsage {
    PhysicalUsage { wal, available }
}

fn refused(message: &str) -> Result<(), AdmissionOperationStoreError> {
    Err(invariant(message))
}

#[test]
fn floors_refuse_exactly_at_their_wal_and_free_space_boundaries() {
    use RecoveryPressureStage::{Intake, OwedProgress};
    assert!(admits(usage(64 * MIB - 1, 128 * MIB), Intake));
    assert!(!admits(usage(64 * MIB, u64::MAX), Intake));
    assert!(!admits(usage(0, 128 * MIB - 1), Intake));
    assert!(admits(usage(128 * MIB - 1, 16 * MIB), OwedProgress));
    assert!(!admits(usage(128 * MIB, u64::MAX), OwedProgress));
    assert!(!admits(usage(0, 16 * MIB - 1), OwedProgress));
}

#[test]
fn intake_stops_before_owed_progress_and_disk_exhaustion() {
    let pressured = usage(64 * MIB, 127 * MIB);
    assert!(!admits(pressured, RecoveryPressureStage::Intake));
    assert!(admits(pressured, RecoveryPressureStage::OwedProgress));
    assert!(!admits(
        PhysicalUsage {
            available: 16 * MIB - 1,
            ..pressured
        },
        RecoveryPressureStage::OwedProgress
    ));
    assert!(!admits(
        PhysicalUsage {
            wal: 128 * MIB,
            ..pressured
        },
        RecoveryPressureStage::OwedProgress
    ));
}

#[test]
fn intake_and_owed_progress_keep_distinct_free_space_reserves() {
    let low = usage(0, 128 * MIB - 1);
    assert!(!admits(low, RecoveryPressureStage::Intake));
    assert!(admits(low, RecoveryPressureStage::OwedProgress));
}

#[test]
fn committed_wal_bytes_use_checked_frame_and_page_arithmetic() -> TestResult {
    assert_eq!(committed_wal_bytes(1, 4096)?, 32 + 24 + 4096);
    assert_eq!(committed_wal_bytes(1, 512)?, 32 + 24 + 512);
    assert_eq!(committed_wal_bytes(1, 65536)?, 32 + 24 + 65536);
    let below = committed_wal_bytes(16_288, 4096)?;
    let at = committed_wal_bytes(16_289, 4096)?;
    assert_eq!((below, at), (67_106_592, 67_110_712));
    assert!(admits(
        usage(below, u64::MAX),
        RecoveryPressureStage::Intake
    ));
    assert!(!admits(usage(at, u64::MAX), RecoveryPressureStage::Intake));
    for page_size in [-1, 0, 256, 511, 513, 1025, 131_072] {
        assert_eq!(
            committed_wal_bytes(1, page_size),
            Err(invariant("recovery WAL page size refused")),
            "{page_size}"
        );
    }
    assert_eq!(
        committed_wal_bytes(u64::MAX, 512),
        Err(invariant("recovery WAL capacity refused"))
    );
    Ok(())
}

#[test]
fn checkpoint_rows_refuse_busy_negative_and_regressed_frame_counts() -> TestResult {
    assert_eq!(backlog_frames(0, -1, -1)?, None);
    assert_eq!(backlog_frames(0, 5, 5)?, None);
    assert_eq!(backlog_frames(1, 7, 3)?, Some(4));
    assert_eq!(
        backlog_frames(0, i64::MAX, 0)?,
        Some(u64::try_from(i64::MAX)?)
    );
    assert_eq!(
        backlog_frames(1, -1, -1),
        Err(invariant("recovery WAL observation is unavailable"))
    );
    for (busy, log, checkpointed) in [(2, 0, 0), (-1, 0, 0), (0, 3, 4), (0, -2, -2), (0, -1, 0)] {
        assert_eq!(
            backlog_frames(busy, log, checkpointed),
            Err(invariant("recovery WAL observation refused")),
            "{busy} {log} {checkpointed}"
        );
    }
    Ok(())
}

#[test]
fn busy_checkpoint_without_frame_counts_refuses_admission() -> TestResult {
    let connection = Connection::open_in_memory()?;
    // SQLite returns this row when another checkpoint owns the lock. A valid
    // earlier measurement must not become zero pressure.
    assert_eq!(
        wal_backlog(&connection, "SELECT 1, -1, -1"),
        Err(invariant("recovery WAL observation is unavailable"))
    );
    Ok(())
}

#[test]
fn memory_and_temporary_databases_are_not_persistent_authorities() -> TestResult {
    for connection in [Connection::open_in_memory()?, Connection::open("")?] {
        for stage in [
            RecoveryPressureStage::Intake,
            RecoveryPressureStage::OwedProgress,
        ] {
            assert_eq!(
                require_recovery_floor(&connection, stage),
                refused("recovery requires a persistent authority")
            );
            assert_eq!(
                require_recovery_floor_before_transaction(&connection, stage),
                refused("recovery requires a persistent authority")
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn rollback_journal_files_refuse_the_wal_profile() -> TestResult {
    let directory = tempfile::tempdir()?;
    let connection = Connection::open(directory.path().join("rollback.db"))?;
    connection.execute_batch(
        "PRAGMA journal_mode=DELETE;
         CREATE TABLE retained(id INTEGER PRIMARY KEY, payload BLOB NOT NULL);",
    )?;
    assert_eq!(
        require_recovery_floor(&connection, RecoveryPressureStage::OwedProgress),
        refused("recovery WAL profile is unsupported")
    );
    assert_eq!(
        require_recovery_floor_before_transaction(&connection, RecoveryPressureStage::Intake),
        refused("recovery WAL profile is unsupported")
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn pinned_reader_backlog_refuses_intake_until_release_and_passive_checkpoint() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("reader-pressure.db");
    let writer = Connection::open(&path)?;
    initialize_history(&writer)?;
    let reader = Connection::open(&path)?;
    reader.execute_batch("BEGIN;")?;
    assert_eq!(history_count(&reader)?, 1);
    append_history(&writer, 17)?;
    assert!(std::fs::metadata(format!("{}-wal", path.display()))?.len() > 64 * MIB);
    assert!(physical_usage(&writer, false)?.wal >= 64 * MIB);
    assert_eq!(
        require_recovery_floor_before_transaction(&writer, RecoveryPressureStage::Intake),
        refused("recovery disk headroom exhausted")
    );
    require_recovery_floor(&writer, RecoveryPressureStage::OwedProgress)?;
    assert_eq!(history_count(&reader)?, 1);
    assert_eq!(history_count(&writer)?, 18);

    reader.execute_batch("ROLLBACK;")?;
    assert_eq!(
        require_recovery_floor(&writer, RecoveryPressureStage::Intake),
        refused("recovery disk headroom exhausted")
    );
    require_recovery_floor_before_transaction(&writer, RecoveryPressureStage::Intake)?;
    require_recovery_floor(&writer, RecoveryPressureStage::Intake)?;
    assert_eq!(history_count(&writer)?, 18);
    assert_eq!(first_payload(&writer)?, [1, 2, 3]);
    Ok(())
}

#[cfg(unix)]
#[test]
fn active_writer_observes_committed_frames_without_checkpointing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("active-writer.db");
    let mut writer = Connection::open(&path)?;
    initialize_history(&writer)?;
    let reader = Connection::open(&path)?;
    reader.execute_batch("BEGIN;")?;
    assert_eq!(history_count(&reader)?, 1);
    append_history(&writer, 17)?;
    let (_, log, checkpointed) = checkpoint_row(&writer, "NOOP")?;
    let page_size: i64 = writer.query_row("PRAGMA main.page_size", [], |row| row.get(0))?;
    let committed = committed_wal_bytes(u64::try_from(log - checkpointed)?, page_size)?;
    assert!(committed >= 64 * MIB);

    let transaction = writer.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    assert_eq!(physical_usage(&transaction, true)?.wal, committed);
    assert_eq!(
        require_recovery_floor(&transaction, RecoveryPressureStage::Intake),
        refused("recovery disk headroom exhausted")
    );
    require_recovery_floor(&transaction, RecoveryPressureStage::OwedProgress)?;
    assert_eq!(
        require_recovery_floor_before_transaction(&transaction, RecoveryPressureStage::Intake),
        refused("recovery checkpoint requires an idle writer")
    );
    transaction.execute(
        "INSERT INTO retained(payload) VALUES(zeroblob(4194304))",
        [],
    )?;
    assert_eq!(physical_usage(&transaction, true)?.wal, committed);
    transaction.commit()?;

    let (_, after_log, after_checkpointed) = checkpoint_row(&writer, "NOOP")?;
    assert!(after_log > log);
    assert_eq!(after_checkpointed, checkpointed);
    assert_eq!(history_count(&reader)?, 1);
    reader.execute_batch("ROLLBACK;")?;
    assert_eq!(history_count(&writer)?, 19);
    Ok(())
}

#[cfg(unix)]
#[test]
fn checkpointed_wal_high_water_is_not_pressure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("capture-pressure.db");
    let mut writer = Connection::open(&path)?;
    initialize_history(&writer)?;
    let reader = Connection::open(&path)?;
    reader.execute_batch("BEGIN;")?;
    assert_eq!(history_count(&reader)?, 1);
    append_history(&writer, 33)?;
    assert!(std::fs::metadata(format!("{}-wal", path.display()))?.len() > 128 * MIB);
    assert_eq!(
        require_recovery_floor(&writer, RecoveryPressureStage::OwedProgress),
        refused("recovery disk headroom exhausted")
    );
    reader.execute_batch("ROLLBACK;")?;
    let (busy, log, checkpointed) = checkpoint_row(&writer, "PASSIVE")?;
    assert_eq!(busy, 0);
    assert_eq!(log, checkpointed);
    assert!(std::fs::metadata(format!("{}-wal", path.display()))?.len() > 128 * MIB);

    let transaction = writer.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    assert_eq!(physical_usage(&transaction, false)?.wal, 0);
    require_recovery_floor(&transaction, RecoveryPressureStage::OwedProgress)?;
    require_recovery_floor(&transaction, RecoveryPressureStage::Intake)?;
    transaction.execute("INSERT INTO retained(payload) VALUES(X'040506')", [])?;
    transaction.commit()?;
    assert_eq!(history_count(&writer)?, 35);
    Ok(())
}

#[cfg(unix)]
#[test]
fn sparse_shared_database_above_two_gib_preserves_recovery() -> TestResult {
    use std::os::unix::fs::MetadataExt;

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("retained-history.db");
    let writer = Connection::open(&path)?;
    writer.pragma_update(None, "page_size", 65536)?;
    initialize_history(&writer)?;
    drop(writer);
    extend_sparse_freelist(&path)?;
    let metadata = std::fs::metadata(&path)?;
    assert!(metadata.len() > 2048 * MIB);
    assert!(metadata.blocks() * 512 < 16 * MIB);

    // A valid large SQLite file whose free pages are sparse. Its retained row
    // stays live, and its size is not an intake quota.
    let mut writer = Connection::open(&path)?;
    assert_eq!(sqlite_integrity(&writer)?, "ok");
    let (pages, page_size): (i64, i64) = writer.query_row(
        "SELECT page_count,page_size FROM pragma_page_count,pragma_page_size",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let pages = u64::try_from(pages)?;
    let page_size = u64::try_from(page_size)?;
    assert_eq!(pages.checked_mul(page_size), Some(metadata.len()));
    assert_eq!(history_count(&writer)?, 1);
    require_recovery_floor_before_transaction(&writer, RecoveryPressureStage::Intake)?;
    require_recovery_floor(&writer, RecoveryPressureStage::OwedProgress)?;
    let transaction = writer.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    require_recovery_floor(&transaction, RecoveryPressureStage::OwedProgress)?;
    transaction.execute("INSERT INTO retained(payload) VALUES(X'040506')", [])?;
    transaction.commit()?;
    assert_eq!(history_count(&writer)?, 2);
    assert_eq!(sqlite_integrity(&writer)?, "ok");
    assert_eq!(first_payload(&writer)?, [1, 2, 3]);
    Ok(())
}

#[cfg(unix)]
#[test]
fn observer_refuses_a_replaced_or_missing_writer_path() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("authority.db");
    let mut writer = Connection::open(&path)?;
    initialize_history(&writer)?;
    let transaction = writer.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    require_recovery_floor(&transaction, RecoveryPressureStage::OwedProgress)?;

    for suffix in ["", "-wal", "-shm"] {
        let current = directory.path().join(format!("authority.db{suffix}"));
        if current.exists() {
            std::fs::rename(&current, directory.path().join(format!("moved.db{suffix}")))?;
        }
    }
    let foreign = Connection::open(&path)?;
    initialize_history(&foreign)?;
    assert_eq!(
        require_recovery_floor(&transaction, RecoveryPressureStage::OwedProgress),
        refused("recovery WAL observer does not hold the writer's main file")
    );
    drop(foreign);

    for suffix in ["", "-wal", "-shm"] {
        let current = directory.path().join(format!("authority.db{suffix}"));
        if current.exists() {
            std::fs::remove_file(current)?;
        }
    }
    assert_eq!(
        require_recovery_floor(&transaction, RecoveryPressureStage::OwedProgress),
        Err(AdmissionOperationStoreError::Unavailable(
            "recovery WAL observer is unavailable".into()
        ))
    );
    transaction.rollback()?;
    Ok(())
}

#[cfg(unix)]
fn checkpoint_row(connection: &Connection, mode: &str) -> Result<(i64, i64, i64), rusqlite::Error> {
    connection.query_row(&format!("PRAGMA main.wal_checkpoint({mode})"), [], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })
}

#[cfg(unix)]
fn sqlite_integrity(connection: &Connection) -> Result<String, rusqlite::Error> {
    connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))
}

#[cfg(unix)]
fn first_payload(connection: &Connection) -> Result<Vec<u8>, rusqlite::Error> {
    connection.query_row("SELECT payload FROM retained WHERE id=1", [], |row| {
        row.get(0)
    })
}

#[cfg(unix)]
fn extend_sparse_freelist(path: &std::path::Path) -> TestResult {
    use std::io::{Read, Seek, SeekFrom, Write};

    // SQLite's freelist format stores leaf page numbers in trunk pages. Leaf
    // pages have no content and SQLite never reads them. The last six trunk
    // slots stay empty and the reserved lock-byte page is excluded.
    // https://sqlite.org/fileformat.html#the_freelist
    const PAGE_SIZE: usize = 65536;
    const PAGE_COUNT: u32 = 32776;
    const TRUNK_LEAVES: usize = PAGE_SIZE / 4 - 8;
    const LOCK_PAGE: u32 = 0x40000000 / PAGE_SIZE as u32 + 1;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    let mut header = [0_u8; 100];
    file.read_exact(&mut header)?;
    assert_eq!(&header[..16], b"SQLite format 3\0");
    assert_eq!(&header[16..18], &[0, 1]);
    assert_eq!(header[20], 0);
    assert_eq!(&header[32..40], &[0; 8]);
    let original_pages = u32::from_be_bytes(header[28..32].try_into()?);
    assert!((1..LOCK_PAGE).contains(&original_pages));
    let free_pages: Vec<u32> = (original_pages + 1..=PAGE_COUNT)
        .filter(|page| *page != LOCK_PAGE)
        .collect();
    let trunks: Vec<&[u32]> = free_pages.chunks(TRUNK_LEAVES + 1).collect();
    file.set_len(u64::from(PAGE_COUNT) * PAGE_SIZE as u64)?;
    for (index, pages) in trunks.iter().enumerate() {
        let mut trunk = [0_u8; PAGE_SIZE];
        let next = trunks.get(index + 1).map_or(0, |next| next[0]);
        trunk[..4].copy_from_slice(&next.to_be_bytes());
        trunk[4..8].copy_from_slice(&u32::try_from(pages.len() - 1)?.to_be_bytes());
        for (offset, page) in pages[1..].iter().enumerate() {
            trunk[8 + offset * 4..12 + offset * 4].copy_from_slice(&page.to_be_bytes());
        }
        file.seek(SeekFrom::Start(u64::from(pages[0] - 1) * PAGE_SIZE as u64))?;
        file.write_all(&trunk)?;
    }
    let change_counter = u32::from_be_bytes(header[24..28].try_into()?)
        .checked_add(1)
        .ok_or("SQLite fixture change counter exhausted")?;
    header[24..28].copy_from_slice(&change_counter.to_be_bytes());
    header[28..32].copy_from_slice(&PAGE_COUNT.to_be_bytes());
    header[32..36].copy_from_slice(&free_pages[0].to_be_bytes());
    header[36..40].copy_from_slice(&u32::try_from(free_pages.len())?.to_be_bytes());
    header[92..96].copy_from_slice(&change_counter.to_be_bytes());
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header)?;
    file.sync_all()?;
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
    checkpoint_row(writer, "PASSIVE").map(|_| ())
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
