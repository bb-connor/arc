//! Current ordinary writes observed by the existing authority transaction gate.
//! These bounds grant no future credit. Every callback, including a rolled-back
//! statement or savepoint, remains charged until the whole transaction ends.
use chio_sqlite_file_identity::{SqliteTransactionWriteShapeData, SqliteTreeWriteShapeData};
use rusqlite::{hooks::PreUpdateCase, types::ValueRef, Connection, OptionalExtension};
use std::collections::BTreeMap;

const MAX_TABLES: usize = 256;
const MAX_COLUMNS: usize = 256;
const MAX_ROW_SHAPES: usize = 4096;

#[derive(Default)]
pub(super) struct WriteLedger {
    tables: BTreeMap<String, TableWrites>,
    shapes: usize,
    failure: Option<String>,
}

#[derive(Default)]
struct TableWrites {
    columns: Option<usize>,
    mutations: u64,
    inserts: u64,
    images: BTreeMap<RowImage, u64>,
}

// Store only byte lengths, never payloads or row identifiers. Equal shapes
// share a bounded counter; heterogeneous rows keep their own physical bounds.
// At most 4096 shapes across the transaction hold 256 before/after lengths.
#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct RowImage {
    before: Option<Vec<u64>>,
    after: Vec<u64>,
    possible_recovery_indexes: u8,
}

fn body_bytes(value: ValueRef<'_>) -> Result<u64, String> {
    match value {
        ValueRef::Null => Ok(0),
        ValueRef::Integer(_) | ValueRef::Real(_) => Ok(8),
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
            u64::try_from(bytes.len()).map_err(|error| error.to_string())
        }
    }
}

fn row_image<'a>(
    table: &str,
    count: i32,
    mut get: impl FnMut(i32) -> rusqlite::Result<ValueRef<'a>>,
) -> Result<(Vec<u64>, u8), String> {
    let count = usize::try_from(count).map_err(|error| error.to_string())?;
    if count == 0 || count > MAX_COLUMNS {
        return Err("ordinary writer changed its bounded column layout".into());
    }
    let bytes = (0..count)
        .map(|index| {
            let value = get(i32::try_from(index).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
            body_bytes(value)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let possible = if table == RECOVERY_TABLE {
        if count != 7 {
            return Err("ordinary recovery writer changed its compiled layout".into());
        }
        recovery_index_membership(
            get(0).map_err(|error| error.to_string())?,
            get(2).map_err(|error| error.to_string())?,
            get(6).map_err(|error| error.to_string())?,
        )
    } else {
        u8::MAX
    };
    Ok((bytes, possible))
}

// This describes possible index entries, not writer authority or a reserve
// exemption. The complete compiled table/index SQL is verified before use.
// JSON predicates stay conservative: only their non-JSON conjuncts can prove
// exclusion. Both images of UPDATE retain every possibly affected index.
const RECOVERY_TABLE: &str = "admission_operation_recovery_records";
fn recovery_index_membership(key: ValueRef<'_>, kind: ValueRef<'_>, native: ValueRef<'_>) -> u8 {
    let (ValueRef::Text(key), ValueRef::Text(kind)) = (key, kind) else {
        return u8::MAX;
    };
    let mut mask = u8::from(!matches!(native, ValueRef::Null));
    for (bit, possible) in [
        (1, key.starts_with(b"knowledge-join:")),
        (2, key.starts_with(b"knowledge-encoding-chunk:")),
        (3, kind == b"command" && key.starts_with(b"command:")),
        (4, kind == b"workflow"),
        (5, kind == b"command" && key.starts_with(b"command-alias:")),
        (
            6,
            kind == b"command" && key.starts_with(b"knowledge-reference-capacity:"),
        ),
    ] {
        if possible {
            mask |= 1 << bit;
        }
    }
    mask
}

impl WriteLedger {
    pub(super) fn changed(&mut self, database: &str, table: &str, change: &PreUpdateCase) {
        if self.failure.is_some() {
            return;
        }
        if let Err(error) = self.capture(database, table, change) {
            self.failure = Some(error);
        }
    }

    fn capture(
        &mut self,
        database: &str,
        table: &str,
        change: &PreUpdateCase,
    ) -> Result<(), String> {
        if database != "main"
            || table.len() > 192
            || !table
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err("ordinary writer left its main-file table vocabulary".into());
        }
        if !self.tables.contains_key(table) && self.tables.len() >= MAX_TABLES {
            return Err("ordinary writer exceeded its bounded table census".into());
        }
        let image = match change {
            PreUpdateCase::Insert(new) => {
                let (after, possible_recovery_indexes) =
                    row_image(table, new.get_column_count(), |i| {
                        new.get_new_column_value(i)
                    })?;
                RowImage {
                    before: None,
                    after,
                    possible_recovery_indexes,
                }
            }
            PreUpdateCase::Update {
                old_value_accessor: old,
                new_value_accessor: new,
            } => {
                let (before, old_indexes) = row_image(table, old.get_column_count(), |i| {
                    old.get_old_column_value(i)
                })?;
                let (after, new_indexes) = row_image(table, new.get_column_count(), |i| {
                    new.get_new_column_value(i)
                })?;
                RowImage {
                    before: Some(before),
                    after,
                    possible_recovery_indexes: old_indexes | new_indexes,
                }
            }
            PreUpdateCase::Delete(old) => {
                let (before, _) = row_image(table, old.get_column_count(), |i| {
                    old.get_old_column_value(i)
                })?;
                // DELETE also reports incremental blob writes. Without the
                // new image retain every index and both full row images.
                RowImage {
                    after: before.clone(),
                    before: Some(before),
                    possible_recovery_indexes: u8::MAX,
                }
            }
            PreUpdateCase::Unknown => {
                return Err("ordinary writer received an unknown row callback".into())
            }
        };
        let row = self.tables.entry(table.to_owned()).or_default();
        let columns = image.after.len();
        if row.columns.is_some_and(|prior| prior != columns)
            || image
                .before
                .as_ref()
                .is_some_and(|before| before.len() != columns)
        {
            return Err("ordinary writer changed its bounded column layout".into());
        }
        row.columns = Some(columns);
        row.mutations = row
            .mutations
            .checked_add(1)
            .ok_or("ordinary mutation count overflow")?;
        if image.before.is_none() {
            row.inserts = row
                .inserts
                .checked_add(1)
                .ok_or("ordinary insert count overflow")?;
        }
        if !row.images.contains_key(&image) {
            if self.shapes >= MAX_ROW_SHAPES {
                return Err("ordinary writer exceeded its bounded row-shape census".into());
            }
            self.shapes += 1;
        }
        let mutations = row.images.entry(image).or_default();
        *mutations = mutations
            .checked_add(1)
            .ok_or("ordinary row-shape count overflow")?;
        Ok(())
    }

    pub(super) fn shape(
        &self,
        source: &Connection,
    ) -> Result<Option<SqliteTransactionWriteShapeData>, String> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if self.tables.is_empty() {
            return Ok(None);
        }
        let mut trees = Vec::new();
        for (table, writes) in &self.tables {
            #[cfg(feature = "admission-test-support")]
            let tree_start = trees.len();
            // The observer is pinned to the held writer's committed predecessor.
            // Schema mutation is denied while loans exist. Only regular stored
            // columns and their actual B-tree indexes have this closed shape.
            let layout: Option<(String, i64)> = source
                .query_row(
                    "SELECT type,ncol FROM pragma_table_list WHERE schema='main' AND name=?1",
                    [table],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let Some((kind, count)) = layout else {
                return Err(format!(
                    "ordinary writer lacks predecessor catalog: {table}"
                ));
            };
            let count = usize::try_from(count).map_err(|error| error.to_string())?;
            let hidden: i64 = source
                .query_row(
                    "SELECT count(*) FROM pragma_table_xinfo(?1,'main') WHERE hidden<>0",
                    [table],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if kind != "table" || hidden != 0 || writes.columns != Some(count) {
                return Err(format!(
                    "ordinary writer has an unpriced table layout: {table}"
                ));
            }
            if table == RECOVERY_TABLE {
                verify_compiled_sql(
                    source,
                    "table",
                    table,
                    include_str!("../../admission_operation_recovery.sql"),
                    "CREATE TABLE IF NOT EXISTS admission_operation_recovery_records",
                )?;
            }
            let retained: i64 = source
                .query_row(
                    &format!("SELECT count(*) FROM main.\"{table}\" NOT INDEXED"),
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            let ceiling = u64::try_from(retained)
                .map_err(|error| error.to_string())?
                .checked_add(writes.inserts)
                .ok_or("ordinary row ceiling overflow")?
                .max(1);
            let columns: Vec<i64> = (0..count)
                .map(i64::try_from)
                .collect::<Result<_, _>>()
                .map_err(|error| error.to_string())?;
            trees.extend(trees_for_rows(
                source, table, writes, &columns, ceiling, None,
            )?);
            let mut indexes = source
                .prepare("SELECT name,origin FROM pragma_index_list(?1,'main')")
                .map_err(|error| error.to_string())?;
            let indexes = indexes
                .query_map([table], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|error| error.to_string())?;
            for index in indexes {
                let (index, origin) = index.map_err(|error| error.to_string())?;
                let without_rowid: bool = source
                    .query_row(
                        "SELECT wr FROM pragma_table_list WHERE schema='main' AND name=?1",
                        [table],
                        |row| row.get(0),
                    )
                    .map_err(|error| error.to_string())?;
                if without_rowid && origin == "pk" {
                    continue;
                }
                let mut statement = source
                    .prepare("SELECT cid FROM pragma_index_xinfo(?1,'main') ORDER BY seqno")
                    .map_err(|error| error.to_string())?;
                let columns = statement
                    .query_map([&index], |row| row.get::<_, i64>(0))
                    .map_err(|error| error.to_string())?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(|error| error.to_string())?;
                let known = known_recovery_index(source, table, &index)?;
                let known_json = known.is_some_and(|(_, expression)| expression);
                if columns.is_empty()
                    || columns.len() > MAX_COLUMNS
                    || columns.iter().any(|column| {
                        (*column < -1 && !(*column == -2 && known_json)) || *column >= count as i64
                    })
                {
                    return Err(format!(
                        "ordinary writer has an unpriced index expression: {index}"
                    ));
                }
                trees.extend(trees_for_rows(
                    source,
                    &index,
                    writes,
                    &columns,
                    ceiling,
                    known.map(|(bit, _)| bit),
                )?);
            }
            let sql: String = source
                .query_row(
                    "SELECT sql FROM main.sqlite_schema WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if sql.to_ascii_uppercase().contains("AUTOINCREMENT") {
                // SQLite's internal sequence maintenance has no application
                // preupdate callback. Include an old/new row for every mutation.
                let bytes =
                    3 * 9 + u64::try_from(table.len()).map_err(|error| error.to_string())? + 8;
                trees.push(SqliteTreeWriteShapeData::record(
                    Some(bytes),
                    bytes,
                    writes.mutations,
                )?);
            }
            #[cfg(feature = "admission-test-support")]
            if std::env::var_os("CHIO_NATIVE_WRITE_PRICE_DIAGNOSTICS").is_some() {
                let page_size: i64 = source
                    .pragma_query_value(None, "page_size", |row| row.get(0))
                    .map_err(|error| error.to_string())?;
                let profile = chio_sqlite_file_identity::SqliteFramePriceProfileData::checked(
                    u64::try_from(page_size).map_err(|error| error.to_string())?,
                    0,
                )?;
                let shape = SqliteTransactionWriteShapeData::checked(trees[tree_start..].to_vec())?;
                let price = shape.price_without_spill(&profile)?;
                eprintln!("ordinary native write: table={table} mutations={} inserts={} shapes={} trees={} row_ceiling={ceiling} wal={} growth={}", writes.mutations, writes.inserts, writes.images.len(), trees.len()-tree_start, price.wal_bytes(), shape.maximum_page_growth(&profile)?);
            }
        }
        SqliteTransactionWriteShapeData::checked(trees).map(Some)
    }
}

// Source-owned predicates and expressions. A nonmatching partial index has
// no entry to write; every possibly matching or unknown predicate is charged.
fn recovery_index_definition(index: &str) -> Option<(u8, bool, &'static str, &'static str)> {
    Some(match index {
        "admission_operation_recovery_native_identity" => (
            0,
            false,
            include_str!("../../admission_operation_recovery.sql"),
            "CREATE UNIQUE INDEX IF NOT EXISTS admission_operation_recovery_native_identity",
        ),
        "idx_recovery_knowledge_join_release" => (
            1,
            true,
            include_str!("../../recovery_knowledge_join_release_index.sql"),
            "CREATE INDEX idx_recovery_knowledge_join_release",
        ),
        "idx_recovery_knowledge_journal_chunk_authority" => (
            2,
            true,
            include_str!("../../recovery_knowledge_journal_chunk_accounting.sql"),
            "CREATE INDEX idx_recovery_knowledge_journal_chunk_authority",
        ),
        "admission_operation_recovery_first_report" => (
            3,
            true,
            include_str!("../../recovery_captured_terminal.sql"),
            "CREATE UNIQUE INDEX admission_operation_recovery_first_report",
        ),
        "admission_operation_recovery_origin_presence" => (
            4,
            true,
            include_str!("../../recovery_origin_presence.sql"),
            "CREATE INDEX IF NOT EXISTS admission_operation_recovery_origin_presence",
        ),
        "admission_operation_recovery_command_alias" => (
            5,
            false,
            include_str!("../../recovery_command_alias.sql"),
            "CREATE INDEX IF NOT EXISTS admission_operation_recovery_command_alias",
        ),
        "admission_operation_recovery_reference_capacity" => (
            6,
            false,
            include_str!("../../recovery_reference_capacity.sql"),
            "CREATE INDEX admission_operation_recovery_reference_capacity",
        ),
        _ => return None,
    })
}

fn compiled_statement(ddl: &str, start: &str) -> Result<String, String> {
    let position = ddl
        .find(start)
        .ok_or("compiled ordinary write object is absent")?;
    Ok(ddl[position..]
        .split(';')
        .next()
        .ok_or("compiled ordinary write object is empty")?
        .trim()
        .replacen(" IF NOT EXISTS ", " ", 1))
}

fn verify_compiled_sql(
    source: &Connection,
    kind: &str,
    name: &str,
    ddl: &str,
    start: &str,
) -> Result<(), String> {
    let actual: String = source
        .query_row(
            "SELECT sql FROM main.sqlite_schema WHERE type=?1 AND tbl_name=?2 AND name=?3",
            [kind, RECOVERY_TABLE, name],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if actual != compiled_statement(ddl, start)? {
        return Err(format!(
            "ordinary recovery object changed its compiled definition: {name}"
        ));
    }
    Ok(())
}

fn known_recovery_index(
    source: &Connection,
    table: &str,
    index: &str,
) -> Result<Option<(u8, bool)>, String> {
    if table != RECOVERY_TABLE {
        return Ok(None);
    }
    let Some((bit, expression, ddl, start)) = recovery_index_definition(index) else {
        return Ok(None);
    };
    verify_compiled_sql(source, "index", index, ddl, start)?;
    Ok(Some((bit, expression)))
}

fn trees_for_rows(
    source: &Connection,
    tree_name: &str,
    writes: &TableWrites,
    columns: &[i64],
    ceiling: u64,
    recovery_index: Option<u8>,
) -> Result<Vec<SqliteTreeWriteShapeData>, String> {
    let bytes = |image: &[u64]| -> Result<u64, String> {
        let mut total = 9_u64; // record header length varint
        for &column in columns {
            let body = if column == -1 {
                8
            } else if column == -2 && recovery_index == Some(4) {
                // The exact compiled origin predicate stores a JSON type
                // name (at most "integer", seven bytes), or "null".
                8
            } else if column == -2 {
                image
                    .iter()
                    .try_fold(0_u64, |sum, bytes| {
                        sum.checked_add(*bytes)
                            .ok_or("ordinary JSON expression size overflow")
                    })?
                    .max(8)
            } else {
                *image
                    .get(usize::try_from(column).map_err(|error| error.to_string())?)
                    .ok_or("ordinary index lost a stored column")?
            };
            total = total
                .checked_add(9)
                .and_then(|sum| sum.checked_add(body))
                .ok_or("ordinary record byte bound overflow")?;
        }
        Ok(total)
    };
    let mut maximum_cell = 0_u64;
    let mut new_cells = 0_u64;
    for (image, &mutations) in &writes.images {
        if recovery_index.is_some_and(|bit| image.possible_recovery_indexes & (1 << bit) == 0) {
            continue;
        }
        let after = bytes(&image.after)?;
        let before = image
            .before
            .as_ref()
            .map(|before| bytes(before))
            .transpose()?
            .unwrap_or(0);
        maximum_cell = maximum_cell.max(before).max(after);
        // Two maximum 9-byte varints (payload length and rowid) and the
        // 2-byte cell pointer cover both table and index leaf framing.
        // Charge a fresh full cell for EVERY mutation. No deleted or replaced
        // cell and no savepoint rollback supplies free-space credit.
        new_cells = new_cells
            .checked_add(
                after
                    .checked_add(20)
                    .and_then(|cell| cell.checked_mul(mutations))
                    .ok_or("ordinary root-leaf cell bound overflow")?,
            )
            .ok_or("ordinary root-leaf total overflow")?;
    }
    if new_cells == 0 {
        return Ok(Vec::new());
    }
    if observed_root_leaf_fits(source, tree_name, maximum_cell, new_cells)? {
        return Ok(vec![SqliteTreeWriteShapeData::observed_root_leaf()]);
    }
    let mut trees = Vec::with_capacity(writes.images.len());
    for (image, &mutations) in &writes.images {
        if recovery_index.is_some_and(|bit| image.possible_recovery_indexes & (1 << bit) == 0) {
            continue;
        }
        let after = bytes(&image.after)?;
        // Reused keys after DELETE, REPLACE or rollback do not get a refund:
        // each removal and each abandoned write remains separately charged.
        let tree = match &image.before {
            None => SqliteTreeWriteShapeData::fresh_insertions(after, mutations)?,
            Some(before) => {
                SqliteTreeWriteShapeData::record(Some(bytes(before)?), after, mutations)?
            }
        };
        trees.push(tree.within_retained_rows(ceiling)?);
    }
    Ok(trees)
}

// The observer reads only the root from SQLite's bundled dbstat module at
// the held writer's committed predecessor. No walk over historical pages is
// needed. All new cells fitting in its initial free bytes proves no split;
// local old/new payload bounds prove no overflow allocation or free. This
// remains valid for key changes, FK actions, REPLACE and delete/insert UPDATE.
fn observed_root_leaf_fits(
    source: &Connection,
    name: &str,
    maximum_cell: u64,
    new_cells: u64,
) -> Result<bool, String> {
    let root: Option<(i64, String, i64, i64)> = source.query_row(
        "SELECT pageno,pagetype,unused,mx_payload FROM dbstat('main') WHERE name=?1 AND path='/'",
        [name], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional().map_err(|error| error.to_string())?;
    let Some((page, kind, unused, old_payload)) = root else {
        return Ok(false);
    };
    let page_size: i64 = source
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    let usable = u64::try_from(page_size).map_err(|error| error.to_string())?;
    // The index maximum-local payload is the smaller leaf limit. Use it for
    // both table and index roots; the authenticated geometry reserves0 bytes.
    let local = usable
        .checked_sub(12)
        .and_then(|n| n.checked_mul(64))
        .map(|n| n / 255)
        .and_then(|n| n.checked_sub(23))
        .ok_or("ordinary root geometry invalid")?;
    Ok(page > 1
        && kind == "leaf"
        && maximum_cell <= local
        && u64::try_from(old_payload).map_err(|error| error.to_string())? <= local
        && u64::try_from(unused).map_err(|error| error.to_string())? >= new_cells)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_sqlite_file_identity::SqliteFramePriceProfileData;
    use std::sync::{Arc, Mutex};

    #[test]
    fn protected_writer_cannot_enable_spilling_inside_its_transaction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch("PRAGMA cache_spill=0; BEGIN IMMEDIATE")?;
        crate::native_authority_capacity::install_schema_guard(&connection, true)?;
        assert!(connection.execute_batch("PRAGMA cache_spill=1").is_err());
        let spill: i64 = connection.query_row("PRAGMA cache_spill", [], |row| row.get(0))?;
        assert_eq!(spill, 0);
        connection.execute_batch("ROLLBACK")?;
        Ok(())
    }

    #[test]
    fn observed_rows_bound_real_wal_after_overflow_indexes_triggers_and_rollback(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("ordinary-writes.sqlite");
        let mut writer = Connection::open(&path)?;
        writer.execute_batch("PRAGMA page_size=512; PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL; PRAGMA cache_spill=0; PRAGMA wal_autocheckpoint=0;
            PRAGMA secure_delete=ON; PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=ON;
            CREATE TABLE rows(key INTEGER PRIMARY KEY, name TEXT, payload BLOB);
            CREATE INDEX row_name ON rows(name);
            CREATE TABLE audit(key INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);
            CREATE TABLE children(key INTEGER PRIMARY KEY, parent INTEGER REFERENCES rows(key) ON DELETE CASCADE);
            CREATE TABLE without_rowid(key TEXT PRIMARY KEY, payload BLOB) WITHOUT ROWID;
            CREATE TRIGGER retain_audit AFTER INSERT ON rows BEGIN INSERT INTO audit(name) VALUES(NEW.name); END;
            PRAGMA wal_checkpoint(TRUNCATE);")?;
        let source =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let ledger = Arc::new(Mutex::new(WriteLedger::default()));
        let observed = Arc::clone(&ledger);
        writer.preupdate_hook(Some(
            move |_, database: &str, table: &str, change: &PreUpdateCase| match observed.lock() {
                Ok(mut ledger) => ledger.changed(database, table, change),
                Err(poisoned) => {
                    poisoned.into_inner().failure = Some("test callback lock poisoned".into())
                }
            },
        ))?;
        let before_pages: i64 = writer.query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let tx = writer.transaction()?;
        for key in 0..12 {
            tx.execute(
                "INSERT INTO rows VALUES(?1,?2,zeroblob(8192))",
                rusqlite::params![key, format!("row-{key}")],
            )?;
        }
        tx.execute("INSERT INTO children VALUES(1,11)", [])?;
        tx.execute(
            "INSERT OR REPLACE INTO rows VALUES(2,'replacement',zeroblob(9000))",
            [],
        )?;
        tx.execute_batch("INSERT INTO without_rowid VALUES('overflow',zeroblob(12000));
            SAVEPOINT attempted; UPDATE rows SET payload=zeroblob(16000); ROLLBACK TO attempted; RELEASE attempted;
            UPDATE rows SET name=name||'-changed', payload=zeroblob(5000) WHERE key<6;
            DELETE FROM rows WHERE key>=10;
            UPDATE without_rowid SET payload=zeroblob(7000);")?;
        {
            use std::io::Write;
            let mut blob = tx.blob_open("main", "rows", "payload", 0, false)?;
            blob.write_all(&[7_u8; 256])?;
        }
        {
            let ledger = ledger.lock().map_err(|_| "test ledger poisoned")?;
            assert_eq!(
                ledger
                    .tables
                    .get("children")
                    .ok_or("missing FK callbacks")?
                    .mutations,
                2
            );
            assert!(ledger.tables.get("rows").ok_or("missing row callbacks")?.mutations >= 35,
                "INSERT, REPLACE delete/insert, rolled-back UPDATE, UPDATE, DELETE and blob callbacks are all required");
        }
        let shape = ledger
            .lock()
            .map_err(|_| "test ledger poisoned")?
            .shape(&source)?
            .ok_or("missing actual writes")?;
        let profile = SqliteFramePriceProfileData::checked(512, 0)?;
        let price = shape.price_without_spill(&profile)?;
        tx.commit()?;
        let wal_bytes = std::fs::metadata(path.with_extension("sqlite-wal"))?.len();
        let after_pages: i64 = writer.query_row("PRAGMA page_count", [], |row| row.get(0))?;
        assert!(
            wal_bytes > 100_000,
            "the test must execute real overflow writes"
        );
        assert!(
            wal_bytes <= price.wal_bytes(),
            "actual WAL {wal_bytes} exceeds {}",
            price.wal_bytes()
        );
        assert!(u64::try_from(after_pages - before_pages)? <= shape.maximum_page_growth(&profile)?);
        writer.preupdate_hook(None::<fn(rusqlite::hooks::Action, &str, &str, &PreUpdateCase)>)?;
        writer.execute_batch("CREATE INDEX expression_key ON rows(lower(name))")?;
        assert!(
            ledger
                .lock()
                .map_err(|_| "test ledger poisoned")?
                .shape(&source)
                .is_err(),
            "unknown index expressions require their producing price"
        );
        Ok(())
    }

    #[test]
    fn compiled_partial_index_membership_preserves_real_insert_update_wal_bounds(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("recovery-indexes.sqlite");
        let mut writer = Connection::open(&path)?;
        writer.execute_batch(
            "PRAGMA page_size=512; PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL; PRAGMA cache_spill=0; PRAGMA wal_autocheckpoint=0;",
        )?;
        writer.execute_batch(&compiled_statement(
            include_str!("../../admission_operation_recovery.sql"),
            "CREATE TABLE IF NOT EXISTS admission_operation_recovery_records",
        )?)?;
        let indexes = [
            "admission_operation_recovery_native_identity",
            "idx_recovery_knowledge_join_release",
            "idx_recovery_knowledge_journal_chunk_authority",
            "admission_operation_recovery_first_report",
            "admission_operation_recovery_origin_presence",
            "admission_operation_recovery_command_alias",
            "admission_operation_recovery_reference_capacity",
        ];
        for index in indexes {
            let (_, _, ddl, start) =
                recovery_index_definition(index).ok_or("compiled index absent")?;
            writer.execute_batch(&compiled_statement(ddl, start)?)?;
        }
        writer.execute_batch("CREATE INDEX admission_operation_recovery_scope ON admission_operation_recovery_records(scope_key,kind);
            PRAGMA wal_checkpoint(TRUNCATE);")?;
        let source =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let ledger = Arc::new(Mutex::new(WriteLedger::default()));
        let observed = Arc::clone(&ledger);
        writer.preupdate_hook(Some(
            move |_, database: &str, table: &str, change: &PreUpdateCase| match observed.lock() {
                Ok(mut ledger) => ledger.changed(database, table, change),
                Err(poisoned) => {
                    poisoned.into_inner().failure = Some("test callback lock poisoned".into())
                }
            },
        ))?;
        let tx = writer.transaction()?;
        let payload = serde_json::to_vec(&serde_json::json!({
            "origin":{}, "release":{"release":"original"},
            "owner":{"authority":"native", "kind":"journal"},
            "reported_decision":{"workflow_id":"reported"}, "padding":"x".repeat(8192),
        }))?;
        for (key, kind, native) in [
            ("native-finishing-account:original", "command", false),
            ("workflow:original", "workflow", true),
            ("knowledge-join:original", "command", false),
            ("knowledge-encoding-chunk:original", "command", false),
            ("command:original", "command", false),
            ("command-alias:original", "command", false),
            ("knowledge-reference-capacity:original", "command", false),
        ] {
            tx.execute(
                "INSERT INTO admission_operation_recovery_records VALUES(?1,?2,?3,1,?4,?5,?6)",
                rusqlite::params![
                    key,
                    "s".repeat(64),
                    kind,
                    payload,
                    native.then(|| "n".repeat(64)),
                    native.then_some("request")
                ],
            )?;
        }
        // Exercise both entering and leaving a partial predicate. This test
        // deliberately omits the production immutable-key trigger so the
        // observed pricing must preserve both old and new index membership.
        tx.execute_batch("UPDATE admission_operation_recovery_records SET record_key='knowledge-join:entered'
                WHERE record_key='native-finishing-account:original';
            UPDATE admission_operation_recovery_records SET record_key='native-finishing-account:left'
                WHERE record_key='knowledge-join:original';
            UPDATE admission_operation_recovery_records SET version=version+1;")?;
        let shape = {
            let ledger = ledger.lock().map_err(|_| "test ledger poisoned")?;
            let images = &ledger
                .tables
                .get(RECOVERY_TABLE)
                .ok_or("missing recovery rows")?
                .images;
            assert!(images
                .keys()
                .any(|image| image.before.is_none() && image.possible_recovery_indexes == 0));
            assert!(images
                .keys()
                .any(|image| image.before.is_some() && image.possible_recovery_indexes == 2));
            assert!(images
                .keys()
                .any(|image| image.possible_recovery_indexes == 17));
            ledger.shape(&source)?.ok_or("missing priced changes")?
        };
        let price = shape.price_without_spill(&SqliteFramePriceProfileData::checked(512, 0)?)?;
        tx.commit()?;
        let wal = std::fs::metadata(path.with_extension("sqlite-wal"))?.len();
        assert!(wal > 50_000);
        assert!(
            wal <= price.wal_bytes(),
            "actual partial-index WAL {wal} exceeds {}",
            price.wal_bytes()
        );
        writer.preupdate_hook(None::<fn(rusqlite::hooks::Action, &str, &str, &PreUpdateCase)>)?;
        writer.execute_batch("DROP INDEX admission_operation_recovery_origin_presence;
            CREATE INDEX admission_operation_recovery_origin_presence ON admission_operation_recovery_records(
                coalesce(json_type(payload,'$.origin'),'null'), record_key) WHERE kind='command';")?;
        assert!(
            ledger
                .lock()
                .map_err(|_| "test ledger poisoned")?
                .shape(&source)
                .is_err(),
            "a changed partial predicate must never inherit the compiled exclusion proof"
        );
        Ok(())
    }

    #[test]
    fn observed_root_slack_bounds_real_writes_and_falls_back_before_a_split(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("root-slack.sqlite");
        let mut writer = Connection::open(&path)?;
        writer.execute_batch(
            "PRAGMA page_size=512; PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL; PRAGMA cache_spill=0; PRAGMA wal_autocheckpoint=0;
            CREATE TABLE leaf_rows(key INTEGER PRIMARY KEY, value TEXT);
            CREATE INDEX leaf_values ON leaf_rows(value);
            INSERT INTO leaf_rows VALUES(1,'first'); PRAGMA wal_checkpoint(TRUNCATE);",
        )?;
        let source =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let ledger = Arc::new(Mutex::new(WriteLedger::default()));
        let observed = Arc::clone(&ledger);
        writer.preupdate_hook(Some(
            move |_, database: &str, table: &str, change: &PreUpdateCase| match observed.lock() {
                Ok(mut ledger) => ledger.changed(database, table, change),
                Err(poisoned) => {
                    poisoned.into_inner().failure = Some("test callback lock poisoned".into())
                }
            },
        ))?;
        let profile = SqliteFramePriceProfileData::checked(512, 0)?;
        for (value, fits) in [("small".to_owned(), true), ("x".repeat(16000), false)] {
            *ledger.lock().map_err(|_| "test ledger poisoned")? = WriteLedger::default();
            let tx = writer.transaction()?;
            tx.execute("UPDATE leaf_rows SET key=key, value=?1", [&value])?;
            let shape = ledger
                .lock()
                .map_err(|_| "test ledger poisoned")?
                .shape(&source)?
                .ok_or("missing actual UPDATE")?;
            let price = shape.price_without_spill(&profile)?;
            if fits {
                // Two root pages plus the common metadata/freelist slack.
                assert_eq!(price.wal_bytes(), profile.price_frames(5)?.wal_bytes());
                assert!(
                    chio_sqlite_file_identity::price_transaction_write_shape(&profile, &shape)
                        .is_err(),
                    "the narrower current-root price cannot be used with spilling"
                );
            } else {
                assert!(price.wal_bytes() > profile.price_frames(5)?.wal_bytes());
            }
            tx.commit()?;
            let wal = std::fs::metadata(path.with_extension("sqlite-wal"))?.len();
            assert!(
                wal <= price.wal_bytes(),
                "root leaf WAL {wal} exceeds {}",
                price.wal_bytes()
            );
            writer.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        }
        Ok(())
    }
}
