//! Real WAL frames and page growth of the pinned bundled SQLite stay within
//! the calculated prices.

use super::super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const FLOW_CONTEXTS: &str = "CREATE TABLE flow_contexts (
    authority TEXT NOT NULL, tenant TEXT NOT NULL, principal TEXT NOT NULL,
    lineage TEXT NOT NULL, session TEXT NOT NULL, epoch TEXT NOT NULL,
    generation INTEGER NOT NULL,
    PRIMARY KEY (authority, tenant, principal, lineage, session, epoch)
 ) STRICT, WITHOUT ROWID;";

fn open_flow_contexts(
    path: &std::path::Path,
    page_size: u64,
) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    let connection = rusqlite::Connection::open(path)?;
    connection.execute_batch(&format!(
        "PRAGMA page_size = {page_size}; PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL; PRAGMA cache_spill = 0;
         PRAGMA wal_autocheckpoint = 0; PRAGMA auto_vacuum = NONE;
         {FLOW_CONTEXTS}"
    ))?;
    Ok(connection)
}

/// The frame profile of `connection`'s actual file, with its queried
/// `auto_vacuum` mode.
fn observed_profile(
    connection: &rusqlite::Connection,
    page_size: u64,
) -> Result<SqliteFramePriceProfileData, Box<dyn std::error::Error>> {
    let mode: i64 = connection.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
    Ok(SqliteFramePriceProfileData::checked(
        page_size,
        0,
        u64::try_from(mode)?,
    )?)
}

fn page_count(connection: &rusqlite::Connection) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(u64::try_from(connection.query_row(
        "PRAGMA page_count",
        [],
        |row| row.get::<_, i64>(0),
    )?)?)
}

/// Run one generation UPDATE as its own transaction after truncating the WAL,
/// and return the frames that transaction wrote.
fn update_frames(
    connection: &rusqlite::Connection,
    wal: &std::path::Path,
    page_size: u64,
    update: &str,
    generation: i64,
) -> Result<u64, Box<dyn std::error::Error>> {
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    connection.execute(update, [generation])?;
    let bytes = std::fs::metadata(wal)?
        .len()
        .checked_sub(WAL_HEADER_BYTES)
        .ok_or("the rewrite left no WAL header")?;
    Ok(bytes / (page_size + FRAME_HEADER_BYTES))
}

/// Rewrite every contexts row's generation in one transaction.
fn rewrite_generation(
    connection: &rusqlite::Connection,
    wal: &std::path::Path,
    page_size: u64,
    generation: i64,
) -> Result<u64, Box<dyn std::error::Error>> {
    update_frames(
        connection,
        wal,
        page_size,
        "UPDATE flow_contexts SET generation = ?1",
        generation,
    )
}

fn width(generation: i64) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(SqliteTreeWriteShapeData::generation_width_class(
        u64::try_from(generation)?,
    )?)
}

/// The page-bounded price of `shape` for a file of `current_pages` pages.
fn page_bounded_frames(
    shape: &SqliteTransactionWriteShapeData,
    profile: &SqliteFramePriceProfileData,
    current_pages: u64,
) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let growth = shape.maximum_page_growth(profile)?;
    let ceiling = (current_pages + growth).next_power_of_two();
    Ok((
        shape.price_within_pages(profile, ceiling)?.wal_frames(),
        growth,
    ))
}

#[test]
fn no_spill_price_preserves_overflow_and_freelist_writes() -> TestResult {
    for page_size in [512_u64, 4096] {
        for secure_delete in [0, 1] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("freelist.sqlite3");
            let mut connection = rusqlite::Connection::open(&path)?;
            connection.execute_batch(&format!(
                "PRAGMA page_size={page_size}; PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL; PRAGMA cache_spill=0;
                 PRAGMA auto_vacuum=NONE; PRAGMA wal_autocheckpoint=0;
                 PRAGMA secure_delete={secure_delete};
                 CREATE TABLE payloads (id INTEGER PRIMARY KEY, body BLOB NOT NULL);"
            ))?;
            // Retain several original freelist trunks. Allocation must
            // consume their leaves and cross trunks, not just append.
            let tx = connection.transaction()?;
            for id in 0..128 {
                tx.execute("INSERT INTO payloads VALUES (?1, zeroblob(65536))", [id])?;
            }
            tx.commit()?;
            connection.execute("DELETE FROM payloads", [])?;
            connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            let free_before: i64 =
                connection.query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
            assert!(free_before > i64::try_from(2 * (page_size / 4))?);
            let tx = connection.transaction()?;
            for id in 0..32 {
                tx.execute("INSERT INTO payloads VALUES (?1, zeroblob(131072))", [id])?;
            }
            for id in 0..16 {
                tx.execute(
                    "UPDATE payloads SET body=zeroblob(262144) WHERE id=?1",
                    [id],
                )?;
            }
            tx.commit()?;
            let profile = observed_profile(&connection, page_size)?;
            let shape = SqliteTransactionWriteShapeData::checked(vec![
                SqliteTreeWriteShapeData::fresh_insertions(131072 + 32, 32)?
                    .within_retained_rows(64)?,
                SqliteTreeWriteShapeData::same_key_rewrites(16, 16 * (262144 + 32))?
                    .within_retained_rows(64)?,
            ])?;
            let price = shape.price_without_spill(&profile)?;
            let wal = std::fs::metadata(path.with_extension("sqlite3-wal"))?.len();
            assert!(wal > 0);
            assert!(
                wal <= price.wal_bytes(),
                "page_size={page_size} secure_delete={secure_delete}: {wal} > {}",
                price.wal_bytes()
            );
            assert!(
                price.wal_bytes() < price_transaction_write_shape(&profile, &shape)?.wal_bytes()
            );
        }
    }
    Ok(())
}

/// Real WAL frames of a width-growing UPDATE of a WITHOUT ROWID table stay
/// within the page-bounded price, at the transitions an integer's encoded
/// width changes (0 to 1 byte at 1 to 2, 1 to 2 bytes at 127 to 128).
#[test]
fn real_width_growing_rewrites_stay_within_the_page_bounded_price() -> TestResult {
    const ROWS: u64 = 4096;
    for (page_size, before, after) in [(4096_u64, 1_i64, 2_i64), (512, 127, 128)] {
        assert!(width(before)? < width(after)?);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("rewrite.sqlite3");
        let connection = open_flow_contexts(&path, page_size)?;
        let mut insert = connection.prepare(
            "INSERT INTO flow_contexts VALUES ('authority', 'tenant', ?1, ?2, ?3, 'epoch', ?4)",
        )?;
        for index in 0..ROWS {
            insert.execute(rusqlite::params![
                format!("principal-{}", index % 7),
                format!("lineage-{index:05}"),
                format!(
                    "session-{index:05}-{}",
                    "x".repeat(usize::try_from(index % 64)?)
                ),
                before,
            ])?;
        }
        drop(insert);
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let current = page_count(&connection)?;
        let profile = observed_profile(&connection, page_size)?;
        // Every record, before and after, encodes in at most 160 bytes.
        let shape = SqliteTransactionWriteShapeData::checked(vec![
            SqliteTreeWriteShapeData::same_key_rewrites(ROWS, ROWS * 160)?,
        ])?;
        let (priced, growth) = page_bounded_frames(&shape, &profile, current)?;
        let frames = rewrite_generation(
            &connection,
            &path.with_extension("sqlite3-wal"),
            page_size,
            after,
        )?;
        assert!(frames > 1, "the update wrote no frames");
        assert!(
            frames <= priced,
            "page size {page_size}: {frames} frames exceed the price {priced}"
        );
        assert!(page_count(&connection)? <= current + growth);
    }
    Ok(())
}

/// Real WAL frames of a same-width UPDATE of the WITHOUT ROWID contexts
/// table stay within the split price with no growing row: the pinned SQLite
/// overwrites equal-size cells in place and dirties only the pages holding
/// differing bytes. A following 3 to 128 rewrite crosses the serial-width
/// boundary and stays within the split price with every row growing.
#[test]
fn real_same_width_rewrites_stay_within_the_split_price() -> TestResult {
    const ROWS: u64 = 512;
    const PAGE: u64 = 4096;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("split.sqlite3");
    let wal = path.with_extension("sqlite3-wal");
    let connection = open_flow_contexts(&path, PAGE)?;
    let mut insert = connection.prepare(
        "INSERT INTO flow_contexts VALUES ('authority', 'tenant', ?1, ?2, ?3, 'epoch', 2)",
    )?;
    for index in 0..ROWS {
        insert.execute(rusqlite::params![
            format!("principal-{}", index % 7),
            format!("lineage-{index:05}"),
            "x".repeat(1200),
        ])?;
    }
    drop(insert);
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    let profile = observed_profile(&connection, PAGE)?;
    let row_bytes = ROWS * 1600;
    let split = |growing: u64| {
        SqliteTransactionWriteShapeData::checked(vec![
            SqliteTreeWriteShapeData::same_key_rewrites_class_split(ROWS, row_bytes, growing)?,
        ])
    };

    assert_eq!(width(2)?, width(3)?);
    let before_same = page_count(&connection)?;
    let (same_priced, _) = page_bounded_frames(&split(0)?, &profile, before_same)?;
    let same_width = rewrite_generation(&connection, &wal, PAGE, 3)?;
    let after_same = page_count(&connection)?;
    assert_eq!(
        after_same, before_same,
        "the same-width update grew the file"
    );
    assert!(same_width > 1, "the same-width update wrote no frames");
    assert!(
        same_width <= same_priced,
        "{same_width} same-width frames exceed the priced {same_priced}"
    );

    assert!(width(3)? < width(128)?);
    let (growing_priced, growth) = page_bounded_frames(&split(ROWS)?, &profile, after_same)?;
    let boundary = rewrite_generation(&connection, &wal, PAGE, 128)?;
    assert!(
        boundary <= growing_priced,
        "{boundary} growing frames exceed the priced {growing_priced}"
    );
    assert!(page_count(&connection)? <= after_same + growth);
    Ok(())
}

/// Real WAL frames and real page growth of 64 spilled contexts rows on
/// 512-byte pages stay inside the split price as every row grows, then as
/// every row keeps its width, and inside the same-key price as every row
/// shrinks. Each record is 1054 bytes at generation 2 (a 9-byte header and a
/// 1045-byte body), so the index leaf keeps `minLocal` (39) bytes and each
/// row spills 1015 or 1016 bytes onto exactly two 508-byte chain pages. The
/// per-row chains therefore cost no more than the ceil of their summed bytes,
/// and this workload does not exercise the per-row rounding slack; a
/// separate test covers that.
#[test]
fn real_spilled_generation_rewrites_stay_within_the_split_and_same_key_prices() -> TestResult {
    const ROWS: u64 = 64;
    const PAGE: u64 = 512;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("rounding.sqlite3");
    let wal = path.with_extension("sqlite3-wal");
    let connection = open_flow_contexts(&path, PAGE)?;
    let mut insert = connection.prepare(
        "INSERT INTO flow_contexts VALUES ('authority', 'tenant', ?1, ?2, ?3, 'epoch', 2)",
    )?;
    for index in 0..ROWS {
        insert.execute(rusqlite::params![
            format!("principal-{}", index % 7),
            format!("lineage-{index:05}"),
            "x".repeat(1000),
        ])?;
    }
    drop(insert);
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    let profile = observed_profile(&connection, PAGE)?;
    // Every row's session alone spills past one 508-byte chain page, and
    // every record encodes in at most 1100 bytes at any generation.
    let row_bytes = ROWS * 1100;
    let split = |growing: u64| {
        SqliteTransactionWriteShapeData::checked(vec![
            SqliteTreeWriteShapeData::same_key_rewrites_class_split(ROWS, row_bytes, growing)?,
        ])
    };

    // Every cell grows from the one-byte serial class of 2 to the two-byte
    // class of 128, replacing every spilled row.
    assert!(width(2)? < width(128)?);
    let before = page_count(&connection)?;
    let (priced, growth) = page_bounded_frames(&split(ROWS)?, &profile, before)?;
    let growing_frames = rewrite_generation(&connection, &wal, PAGE, 128)?;
    let after_growing = page_count(&connection)?;
    assert!(growing_frames > 1, "the growing update wrote no frames");
    assert!(
        growing_frames <= priced,
        "{growing_frames} growing frames exceed the priced {priced}"
    );
    assert!(
        after_growing <= before + growth,
        "{after_growing} pages exceed {before} plus the priced growth {growth}"
    );

    // 128 and 129 share the two-byte serial class, so every cell keeps its
    // size and is overwritten in place.
    assert_eq!(width(128)?, width(129)?);
    let (same_priced, same_growth) = page_bounded_frames(&split(0)?, &profile, after_growing)?;
    assert_eq!(same_growth, LOCK_BYTE_PAGE_SKIP);
    let same_frames = rewrite_generation(&connection, &wal, PAGE, 129)?;
    let after_same = page_count(&connection)?;
    assert_eq!(
        after_same, after_growing,
        "the same-width update grew the file"
    );
    assert!(same_frames > 0, "the same-width update wrote no frames");
    assert!(
        same_frames <= same_priced,
        "{same_frames} same-width frames exceed the priced {same_priced}"
    );

    // 129 to 3 shrinks every cell from the two-byte to the one-byte class.
    assert!(width(3)? < width(129)?);
    let shrink = SqliteTransactionWriteShapeData::checked(vec![
        SqliteTreeWriteShapeData::same_key_rewrites(ROWS, row_bytes)?,
    ])?;
    let (shrink_priced, shrink_growth) = page_bounded_frames(&shrink, &profile, after_same)?;
    let shrink_frames = rewrite_generation(&connection, &wal, PAGE, 3)?;
    let after_shrink = page_count(&connection)?;
    assert!(shrink_frames > 1, "the shrinking update wrote no frames");
    assert!(
        shrink_frames <= shrink_priced,
        "{shrink_frames} shrinking frames exceed the priced {shrink_priced}"
    );
    assert!(after_shrink <= after_same + shrink_growth);
    Ok(())
}

/// `OPFLAG_ISNOOP` of the pinned bundled SQLite: an `OP_Delete` carrying it
/// only invokes the pre-update hook and deletes nothing.
const OPFLAG_ISNOOP: i64 = 0x40;

/// A rowid table whose `generation` is a child key of a foreign key into the
/// same table. Every row's 4500-byte body spills to one overflow page.
fn open_self_referencing(
    path: &std::path::Path,
    foreign_keys: bool,
) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    let connection = rusqlite::Connection::open(path)?;
    connection.execute_batch(&format!(
        "PRAGMA page_size = 4096; PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL; PRAGMA cache_spill = 0;
         PRAGMA wal_autocheckpoint = 0; PRAGMA auto_vacuum = NONE;
         PRAGMA foreign_keys = {};
         CREATE TABLE contexts (
             id INTEGER PRIMARY KEY,
             generation INTEGER NOT NULL REFERENCES contexts(id),
             body BLOB NOT NULL
         ) STRICT;
         WITH RECURSIVE ids(id) AS (SELECT 1 UNION ALL SELECT id + 1 FROM ids WHERE id < 64)
         INSERT INTO contexts SELECT id, 3, zeroblob(4500) FROM ids;
         PRAGMA wal_checkpoint(TRUNCATE);",
        u8::from(foreign_keys)
    ))?;
    Ok(connection)
}

/// Count the `OP_Delete` instructions of one UPDATE plan that really delete,
/// excluding pre-update-hook-only deletes.
fn deleting_instructions(
    connection: &rusqlite::Connection,
    update: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut plan = connection.prepare(&format!("EXPLAIN {update}"))?;
    let mut rows = plan.query([])?;
    let mut deletes = 0;
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(1)? == "Delete" && (row.get::<_, i64>(3)? & OPFLAG_ISNOOP) == 0 {
            deletes += 1;
        }
    }
    Ok(deletes)
}

fn generations_equal_to(
    connection: &rusqlite::Connection,
    generation: i64,
) -> Result<i64, Box<dyn std::error::Error>> {
    Ok(connection.query_row(
        "SELECT count(*) FROM contexts WHERE generation = ?1 AND length(body) = 4500",
        [generation],
        |row| row.get(0),
    )?)
}

/// The same valid, equal-size, unchanged-key UPDATE takes the in-place
/// overwrite path with foreign keys off, and a real delete and reinsert of
/// every row when foreign keys are on and `generation` is a child key into
/// the same table (`sqlite3FkRequired` returns 2, so `sqlite3Update` emits a
/// deleting `OP_Delete` before the reinsertion). The overwrite stays within
/// the split price with no growing row. The delete and reinsert violates the
/// same-key premises; its measured frames are only shown to exceed the
/// overwrite, not to exceed any price.
#[test]
fn a_self_referencing_foreign_key_turns_an_equal_size_rewrite_into_delete_and_reinsert(
) -> TestResult {
    const ROWS: u64 = 64;
    const PAGE: u64 = 4096;
    const UPDATE: &str = "UPDATE contexts SET generation = ?1";
    // Generations 3 and 2 share the one-byte serial class, so every record
    // keeps its exact encoded size.
    assert_eq!(width(3)?, width(2)?);
    let mut measured = Vec::new();
    for foreign_keys in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("self_referencing.sqlite3");
        let connection = open_self_referencing(&path, foreign_keys)?;
        let profile = observed_profile(&connection, PAGE)?;
        let enabled: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
        assert_eq!(enabled, i64::from(u8::from(foreign_keys)));
        assert_eq!(generations_equal_to(&connection, 3)?, 64);
        let deletes = deleting_instructions(&connection, "UPDATE contexts SET generation = 2")?;
        if foreign_keys {
            assert!(
                deletes > 0,
                "foreign keys did not select delete and reinsert"
            );
        } else {
            assert_eq!(deletes, 0, "an unchanged-key overwrite planned a delete");
        }
        let before = page_count(&connection)?;
        let frames = update_frames(
            &connection,
            &path.with_extension("sqlite3-wal"),
            PAGE,
            UPDATE,
            2,
        )?;
        assert!(frames > 0, "the update wrote no frames");
        assert_eq!(generations_equal_to(&connection, 2)?, 64);
        let violations: i64 = connection.query_row(
            "SELECT count(*) FROM pragma_foreign_key_check('contexts')",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(violations, 0);
        if foreign_keys {
            // The constraint is live: a dangling parent refuses and the
            // stored rows keep their committed generation.
            match connection.execute(UPDATE, [1000]) {
                Err(rusqlite::Error::SqliteFailure(error, _)) => {
                    assert_eq!(error.code, rusqlite::ErrorCode::ConstraintViolation);
                    assert_eq!(
                        error.extended_code,
                        rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY
                    );
                }
                other => {
                    return Err(
                        format!("expected SQLITE_CONSTRAINT_FOREIGNKEY, got {other:?}").into(),
                    );
                }
            }
            assert_eq!(generations_equal_to(&connection, 2)?, 64);
        } else {
            assert_eq!(
                page_count(&connection)?,
                before,
                "the overwrite grew the file"
            );
            let shape = SqliteTransactionWriteShapeData::checked(vec![
                SqliteTreeWriteShapeData::same_key_rewrites_class_split(ROWS, ROWS * 4600, 0)?,
            ])?;
            let (priced, _) = page_bounded_frames(&shape, &profile, before)?;
            assert!(
                frames <= priced,
                "{frames} overwrite frames exceed the priced {priced}"
            );
        }
        measured.push(frames);
    }
    assert!(
        measured[1] > measured[0],
        "delete and reinsert wrote {} frames, the overwrite {}",
        measured[1],
        measured[0]
    );
    Ok(())
}

/// Overflow bytes of one table-leaf cell of the pinned bundled SQLite:
/// `btreeParseCellAdjustSizeForOverflow` keeps `surplus = minLocal +
/// (payload - minLocal) % (usable - 4)` locally when it is at most
/// `maxLocal`, otherwise `minLocal`. A table leaf has `maxLocal = usable - 35`
/// and `minLocal = (usable - 12) * 32 / 255 - 23`.
fn table_leaf_overflow_bytes(page_size: u64, payload: u64) -> u64 {
    let max_local = page_size - 35;
    let min_local = (page_size - 12) * 32 / 255 - 23;
    if payload <= max_local {
        return 0;
    }
    let surplus = min_local + (payload - min_local) % (page_size - 4);
    payload
        - if surplus <= max_local {
            surplus
        } else {
            min_local
        }
}

fn chain_pages(
    connection: &rusqlite::Connection,
) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let (pages, payload): (i64, i64) = connection.query_row(
        "SELECT count(*), coalesce(sum(payload), 0) FROM dbstat
         WHERE name = 'chains' AND pagetype = 'overflow'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((u64::try_from(pages)?, u64::try_from(payload)?))
}

/// Every row's overflow payload ends 450 or 451 bytes into its second chain
/// page, so the per-row chains cost more pages than the ceil of the summed
/// record bytes and only the per-row slack of the split image term covers the
/// stored chains. A record is `[header 5][generation][body 991]`: the header
/// holds its own size, NULL for the rowid alias, the integer serial type and
/// the 2-byte blob serial type 1994. Generation 2 encodes in one byte (997
/// payload bytes) and 128 in two (998). The growing rewrite's WAL frames and
/// page growth stay within the split price; the page ceiling dominates that
/// frame bound, so it does not prove the cascade term tight.
#[test]
fn real_per_row_overflow_rounding_needs_the_per_row_image_slack() -> TestResult {
    const ROWS: u64 = 64;
    const PAGE: u64 = 512;
    let payload = PAGE - 4;
    let (before_payload, after_payload) = (997, 998);
    for record in [before_payload, after_payload] {
        let overflow = table_leaf_overflow_bytes(PAGE, record);
        assert_eq!(overflow, record - 39);
        assert_eq!(overflow.div_ceil(payload), 2);
        assert!(ROWS * overflow.div_ceil(payload) > (ROWS * record).div_ceil(payload));
    }
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("chains.sqlite3");
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch(
        "PRAGMA page_size = 512; PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL; PRAGMA cache_spill = 0;
         PRAGMA wal_autocheckpoint = 0; PRAGMA auto_vacuum = NONE;
         CREATE TABLE chains (
             id INTEGER PRIMARY KEY,
             generation INTEGER NOT NULL,
             body BLOB NOT NULL
         ) STRICT;
         WITH RECURSIVE ids(id) AS (SELECT 1 UNION ALL SELECT id + 1 FROM ids WHERE id < 64)
         INSERT INTO chains SELECT id, 2, zeroblob(991) FROM ids;
         PRAGMA wal_checkpoint(TRUNCATE);",
    )?;
    let stored: i64 = connection.query_row(
        "SELECT count(*) FROM chains WHERE generation = 2 AND length(body) = 991",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(stored, 64);
    assert_eq!(
        chain_pages(&connection)?,
        (
            ROWS * 2,
            ROWS * table_leaf_overflow_bytes(PAGE, before_payload)
        )
    );

    assert!(width(2)? < width(128)?);
    let total = ROWS * after_payload;
    let profile = observed_profile(&connection, PAGE)?;
    let shape = SqliteTransactionWriteShapeData::checked(vec![
        SqliteTreeWriteShapeData::same_key_rewrites_class_split(ROWS, total, ROWS)?,
    ])?;
    let before = page_count(&connection)?;
    let (priced, growth) = page_bounded_frames(&shape, &profile, before)?;
    let frames = update_frames(
        &connection,
        &path.with_extension("sqlite3-wal"),
        PAGE,
        "UPDATE chains SET generation = ?1",
        128,
    )?;
    assert!(frames > 1, "the growing update wrote no frames");
    assert!(
        frames <= priced,
        "{frames} growing frames exceed the priced {priced}"
    );
    assert!(page_count(&connection)? <= before + growth);
    let rewritten: i64 = connection.query_row(
        "SELECT count(*) FROM chains WHERE generation = 128 AND length(body) = 991",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(rewritten, 64);
    let (pages, stored_payload) = chain_pages(&connection)?;
    assert_eq!(
        (pages, stored_payload),
        (
            ROWS * 2,
            ROWS * table_leaf_overflow_bytes(PAGE, after_payload)
        )
    );
    // One image set without slack falls short of the stored chains; the
    // priced per-row slack covers them.
    assert!(pages > total.div_ceil(payload));
    assert!(pages <= total.div_ceil(payload) + ROWS);
    Ok(())
}

/// The profile accepts only the `auto_vacuum` mode queried from the actual
/// file: NONE prices, FULL and INCREMENTAL refuse before any price exists.
#[test]
fn queried_auto_vacuum_mode_selects_or_refuses_the_frame_profile() -> TestResult {
    for (setting, mode) in [("NONE", 0_i64), ("FULL", 1), ("INCREMENTAL", 2)] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("vacuum.sqlite3");
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(&format!(
            "PRAGMA page_size = 4096; PRAGMA auto_vacuum = {setting};
             PRAGMA journal_mode = WAL;
             CREATE TABLE vacuumed (id INTEGER PRIMARY KEY, body BLOB NOT NULL);"
        ))?;
        let queried: i64 = connection.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
        assert_eq!(queried, mode, "auto_vacuum {setting}");
        match (mode, observed_profile(&connection, 4096)) {
            (0, Ok(_)) => {}
            (_, Err(error))
                if mode != 0
                    && error.to_string() == "SQLite frame price requires auto-vacuum NONE" => {}
            (_, other) => {
                return Err(format!("auto_vacuum {setting} produced {other:?}").into());
            }
        }
    }
    Ok(())
}
