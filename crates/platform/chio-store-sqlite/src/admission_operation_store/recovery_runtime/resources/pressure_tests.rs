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
fn sparse_shared_database_above_two_gib_preserves_recovery(
) -> Result<(), Box<dyn std::error::Error>> {
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

    // This is a valid large SQLite file, not trailing bytes past its declared
    // size. The original retained row remains live. Sparse free pages exercise
    // the former absolute file-size check without allocating two GiB per test.
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
    check(&writer, true)?;
    check(&writer, false)?;
    let tx = writer.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    check_committing(&tx)?;
    tx.execute("INSERT INTO retained(payload) VALUES(X'040506')", [])?;
    tx.commit()?;
    assert_eq!(history_count(&writer)?, 2);
    assert_eq!(sqlite_integrity(&writer)?, "ok");
    assert_eq!(
        writer.query_row("SELECT payload FROM retained WHERE id=1", [], |row| {
            row.get::<_, Vec<u8>>(0)
        })?,
        [1, 2, 3]
    );
    Ok(())
}

#[cfg(unix)]
fn sqlite_integrity(connection: &Connection) -> Result<String, rusqlite::Error> {
    connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))
}

#[cfg(unix)]
fn extend_sparse_freelist(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Seek, SeekFrom, Write};

    // SQLite's documented freelist format stores leaf page numbers in trunk
    // pages. Leaf pages have no content and SQLite never reads them. Keep the
    // last six trunk slots empty and exclude the reserved lock-byte page.
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
