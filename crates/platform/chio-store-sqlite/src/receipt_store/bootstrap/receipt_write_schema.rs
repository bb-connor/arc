//! Exact DDL of the tables one tool receipt append writes. The store's open
//! and the native finishing reference catalog apply these same statements, so
//! a changed table, index or trigger can never authenticate as canonical.
//!
//! It also quotes the physical cost of one native receipt append: the receipt
//! row with its claim-log projection, the lineage row, the settlement
//! attempt-zero row and the sink-generation compare-and-swap. A quote is DATA;
//! it neither reserves capacity nor authorizes a writer.

use std::sync::OnceLock;

use chio_core::crypto::sha256_hex;
use chio_sqlite_file_identity::{
    main_database_write_geometry, price_transaction_write_shape, write_price_algorithm_descriptor,
    SqliteFramePriceProfileData, SqliteTransactionWriteShapeData, SqliteTreeWriteShapeData,
};
use rusqlite::OptionalExtension;

use super::super::ReceiptStoreError;
use crate::admission_operation_store::BUNDLED_SQLITE_SOURCE_ID;

pub(in crate::receipt_store) const TOOL_RECEIPTS_SQL: &str = r#"CREATE TABLE IF NOT EXISTS chio_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                grant_index INTEGER,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                cost_currency TEXT CHECK (
                    cost_currency IS NULL OR (
                        typeof(cost_currency) = 'text' AND
                        length(cost_currency) = 3 AND
                        cost_currency NOT GLOB '*[^A-Z]*'
                    )
                ),
                cost_charged_be BLOB CHECK (
                    (cost_currency IS NULL AND cost_charged_be IS NULL) OR
                    (
                        cost_currency IS NOT NULL AND
                        typeof(cost_charged_be) = 'blob' AND
                        length(cost_charged_be) = 8
                    )
                ),
                attempted_cost_be BLOB CHECK (
                    attempted_cost_be IS NULL OR (
                        typeof(attempted_cost_be) = 'blob' AND length(attempted_cost_be) = 8
                    )
                )
            );

            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_timestamp
                ON chio_tool_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_capability
                ON chio_tool_receipts(capability_id);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_subject
                ON chio_tool_receipts(subject_key);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_grant
                ON chio_tool_receipts(capability_id, grant_index);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_tool
                ON chio_tool_receipts(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_decision
                ON chio_tool_receipts(decision_kind);"#;

pub(in crate::receipt_store) const CLAIM_RECEIPT_LOG_SQL: &str = r#"CREATE TABLE IF NOT EXISTS claim_receipt_log_entries (
                entry_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                receipt_kind TEXT NOT NULL,
                source_seq INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                capability_id TEXT,
                session_id TEXT,
                parent_request_id TEXT,
                request_id TEXT,
                subject_key TEXT,
                issuer_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                raw_json TEXT NOT NULL,
                CHECK (entry_seq > 0),
                CHECK (source_seq > 0),
                CHECK (receipt_kind IN ('tool_receipt', 'child_receipt')),
                CHECK (
                    (receipt_kind = 'tool_receipt'
                        AND capability_id IS NOT NULL
                        AND session_id IS NULL
                        AND parent_request_id IS NULL
                        AND request_id IS NULL
                        AND tool_server IS NOT NULL
                        AND tool_name IS NOT NULL)
                    OR
                    (receipt_kind = 'child_receipt'
                        AND capability_id IS NULL
                        AND session_id IS NOT NULL
                        AND parent_request_id IS NOT NULL
                        AND request_id IS NOT NULL
                        AND tool_server IS NULL
                        AND tool_name IS NULL)
                )
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_claim_receipt_log_kind_source
                ON claim_receipt_log_entries(receipt_kind, source_seq);
            CREATE INDEX IF NOT EXISTS idx_claim_receipt_log_timestamp
                ON claim_receipt_log_entries(timestamp, entry_seq);
            CREATE INDEX IF NOT EXISTS idx_claim_receipt_log_tool
                ON claim_receipt_log_entries(tool_server, tool_name, timestamp)
                WHERE receipt_kind = 'tool_receipt';
            CREATE INDEX IF NOT EXISTS idx_claim_receipt_log_child_request
                ON claim_receipt_log_entries(session_id, request_id, timestamp)
                WHERE receipt_kind = 'child_receipt';

            DROP TRIGGER IF EXISTS chio_tool_receipts_project_claim_log_entry;
            CREATE TRIGGER chio_tool_receipts_project_claim_log_entry
            AFTER INSERT ON chio_tool_receipts
            BEGIN
                INSERT INTO claim_receipt_log_entries (
                    receipt_id,
                    receipt_kind,
                    source_seq,
                    timestamp,
                    capability_id,
                    session_id,
                    parent_request_id,
                    request_id,
                    subject_key,
                    issuer_key,
                    tool_server,
                    tool_name,
                    raw_json
                ) VALUES (
                    NEW.receipt_id,
                    'tool_receipt',
                    NEW.seq,
                    NEW.timestamp,
                    NEW.capability_id,
                    NULL,
                    NULL,
                    NULL,
                    NEW.subject_key,
                    NEW.issuer_key,
                    NEW.tool_server,
                    NEW.tool_name,
                    NEW.raw_json
                );
            END;"#;

pub(in crate::receipt_store) const RECEIPT_LINEAGE_STATEMENTS_SQL: &str = r#"CREATE TABLE IF NOT EXISTS receipt_lineage_statements (
                receipt_id TEXT PRIMARY KEY,
                statement_id TEXT,
                request_id TEXT,
                session_id TEXT,
                session_anchor_id TEXT REFERENCES session_anchors(anchor_id),
                chain_id TEXT,
                parent_request_id TEXT,
                parent_receipt_id TEXT,
                evidence_class TEXT,
                evidence_sources_json TEXT,
                verified_session_anchor INTEGER NOT NULL DEFAULT 0,
                verified_parent_request INTEGER NOT NULL DEFAULT 0,
                verified_parent_receipt INTEGER NOT NULL DEFAULT 0,
                replay_protected INTEGER NOT NULL DEFAULT 0,
                recorded_at INTEGER NOT NULL,
                source_kind TEXT NOT NULL,
                json_sha256 TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_request
                ON receipt_lineage_statements(session_id, request_id);
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_parent_request
                ON receipt_lineage_statements(session_id, parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_parent_receipt
                ON receipt_lineage_statements(parent_receipt_id);
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_anchor
                ON receipt_lineage_statements(session_anchor_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_receipt_lineage_request_anchor
                ON receipt_lineage_statements(session_id, COALESCE(session_anchor_id, ''), request_id)
                WHERE session_id IS NOT NULL
                  AND request_id IS NOT NULL;"#;

const QUOTE_DESCRIPTOR: &str = "chio.receipt-append-quote; bundled3.51.3; rowid_tables_only; \
fresh_insertions_per_tree; one_fresh_lineage_row; sqlite_sequence_two_updates; \
sink_generation_singleton_root; exact_lineage_key_lengths; auto_vacuum_none_or_incremental; \
page_bucket=max(minimum,pow2(page_count+growth)); \
ptrmap_extra=min(map_pages_at_bucket,frames*(usable/2+1)); \
cache_spill_off; temp_schema_empty; model_schema_equality";
const WRITE_TABLES_SQL: &str = "'chio_tool_receipts', 'claim_receipt_log_entries', \
'receipt_lineage_statements', 'settle_attempts', 'chio_receipt_sink_generation', \
'capability_lineage'";
const SCHEMA_TABLES: [&str; 5] = [
    "chio_tool_receipts",
    "claim_receipt_log_entries",
    "receipt_lineage_statements",
    "settle_attempts",
    "capability_lineage",
];
const AUTOINCREMENT_NAME_BYTES: u64 = 25;
const SEQUENCE_VALUE_BYTES: u64 = 8;
const GENERATION_DIGIT_BYTES: u64 = 20;
const DECISION_KIND_BYTES: u64 = 32;
const SOURCE_KIND_BYTES: u64 = 32;
const SHA256_HEX_BYTES: u64 = 64;
const WORK_KIND_BYTES: u64 = 19;
const RECEIPT_KIND_BYTES: u64 = 12;
const INTEGER_BYTES: u64 = 8;
/// A lineage statement is re-encoded from the typed call chain, which can add
/// the defaulted evidence class beyond the stored receipt text.
const REENCODING_SLACK_BYTES: u64 = 256;
/// Payload-size varint, overflow pointer and record-header-size varint.
const CELL_FIXED_BYTES: u64 = 22;
const ROWID_VARINT_BYTES: u64 = 9;
const COLUMN_HEADER_BYTES: u64 = 9;

/// Largest value one written column can hold.
#[derive(Clone, Copy, Debug)]
enum Cap {
    /// The stored receipt JSON itself.
    RawJson,
    /// Text copied out of the receipt JSON. All such columns of one record are
    /// disjoint substrings of it, so together they never exceed its length.
    Field,
    /// Subject key: the larger of its capability-lineage length and the receipt.
    SubjectKey,
    /// Issuer key: the larger of its capability-lineage length and the receipt.
    IssuerKey,
    /// JSON re-encoded from typed values parsed out of the receipt.
    Reencoded,
    Fixed(u64),
}

struct WriteTable {
    table: &'static str,
    columns: &'static [(&'static str, Cap)],
}

const TOOL_RECEIPT_WRITE: WriteTable = WriteTable {
    table: "chio_tool_receipts",
    columns: &[
        ("seq", Cap::Fixed(0)),
        ("receipt_id", Cap::Field),
        ("timestamp", Cap::Fixed(INTEGER_BYTES)),
        ("capability_id", Cap::Field),
        ("subject_key", Cap::SubjectKey),
        ("issuer_key", Cap::IssuerKey),
        ("grant_index", Cap::Fixed(INTEGER_BYTES)),
        ("tool_server", Cap::Field),
        ("tool_name", Cap::Field),
        ("decision_kind", Cap::Fixed(DECISION_KIND_BYTES)),
        ("policy_hash", Cap::Field),
        ("content_hash", Cap::Field),
        ("raw_json", Cap::RawJson),
        ("cost_currency", Cap::Fixed(3)),
        ("cost_charged_be", Cap::Fixed(INTEGER_BYTES)),
        ("attempted_cost_be", Cap::Fixed(INTEGER_BYTES)),
        ("tenant_id", Cap::Field),
    ],
};

const CLAIM_LOG_WRITE: WriteTable = WriteTable {
    table: "claim_receipt_log_entries",
    columns: &[
        ("entry_seq", Cap::Fixed(0)),
        ("receipt_id", Cap::Field),
        ("receipt_kind", Cap::Fixed(RECEIPT_KIND_BYTES)),
        ("source_seq", Cap::Fixed(INTEGER_BYTES)),
        ("timestamp", Cap::Fixed(INTEGER_BYTES)),
        ("capability_id", Cap::Field),
        ("session_id", Cap::Fixed(0)),
        ("parent_request_id", Cap::Fixed(0)),
        ("request_id", Cap::Fixed(0)),
        ("subject_key", Cap::SubjectKey),
        ("issuer_key", Cap::IssuerKey),
        ("tool_server", Cap::Field),
        ("tool_name", Cap::Field),
        ("raw_json", Cap::RawJson),
    ],
};

const LINEAGE_WRITE: WriteTable = WriteTable {
    table: "receipt_lineage_statements",
    columns: &[
        ("receipt_id", Cap::Field),
        ("statement_id", Cap::Field),
        ("request_id", Cap::Field),
        ("session_id", Cap::Field),
        ("session_anchor_id", Cap::Field),
        ("chain_id", Cap::Field),
        ("parent_request_id", Cap::Field),
        ("parent_receipt_id", Cap::Field),
        ("evidence_class", Cap::Field),
        ("evidence_sources_json", Cap::Reencoded),
        ("verified_session_anchor", Cap::Fixed(INTEGER_BYTES)),
        ("verified_parent_request", Cap::Fixed(INTEGER_BYTES)),
        ("verified_parent_receipt", Cap::Fixed(INTEGER_BYTES)),
        ("replay_protected", Cap::Fixed(INTEGER_BYTES)),
        ("recorded_at", Cap::Fixed(INTEGER_BYTES)),
        ("source_kind", Cap::Fixed(SOURCE_KIND_BYTES)),
        ("json_sha256", Cap::Fixed(SHA256_HEX_BYTES)),
        ("raw_json", Cap::Reencoded),
    ],
};

const SETTLE_ATTEMPT_WRITE: WriteTable = WriteTable {
    table: "settle_attempts",
    columns: &[
        ("receipt_id", Cap::Field),
        ("finalized_at", Cap::Fixed(INTEGER_BYTES)),
        ("work_kind", Cap::Fixed(WORK_KIND_BYTES)),
        ("attempts", Cap::Fixed(INTEGER_BYTES)),
        ("next_visible_at_ms", Cap::Fixed(INTEGER_BYTES)),
        ("row_version", Cap::Fixed(INTEGER_BYTES)),
        ("lease_owner", Cap::Fixed(0)),
        ("lease_token", Cap::Fixed(0)),
        ("lease_until_ms", Cap::Fixed(0)),
        ("reason_code", Cap::Fixed(0)),
        ("reason_detail_sha256", Cap::Fixed(0)),
        ("updated_at_ms", Cap::Fixed(INTEGER_BYTES)),
    ],
};

const SINK_GENERATION_WRITE: WriteTable = WriteTable {
    table: "chio_receipt_sink_generation",
    columns: &[
        ("singleton", Cap::Fixed(0)),
        ("store_generation", Cap::Fixed(GENERATION_DIGIT_BYTES)),
    ],
};

const INSERTED_TABLES: [&WriteTable; 4] = [
    &TOOL_RECEIPT_WRITE,
    &CLAIM_LOG_WRITE,
    &LINEAGE_WRITE,
    &SETTLE_ATTEMPT_WRITE,
];

/// Authenticated inputs of one quote, supplied by the sink owner. They are not
/// authority.
pub(in crate::receipt_store) struct ReceiptAppendRecipeData<'a> {
    /// Whether the owning writer advances an authenticated rollback anchor.
    pub(in crate::receipt_store) anchored: bool,
    /// The original profile's receipt envelope.
    pub(in crate::receipt_store) receipt_bytes: u64,
    /// The original's capability id; its lineage row supplies the key lengths.
    pub(in crate::receipt_store) capability_id: &'a str,
    /// Power of two, at least one.
    pub(in crate::receipt_store) minimum_page_bucket: u64,
}

/// Exact physical cost of one native receipt append, with the source profile
/// it was derived under. This DATA is not authority and funds nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::receipt_store) struct ReceiptAppendQuoteData {
    wal_bytes: u64,
    disk_bytes: u64,
    wal_frames: u64,
    fingerprint: String,
    page_bucket: u64,
    maximum_page_growth: u64,
}

impl ReceiptAppendQuoteData {
    pub(in crate::receipt_store) fn wal_bytes(&self) -> u64 {
        self.wal_bytes
    }

    pub(in crate::receipt_store) fn disk_bytes(&self) -> u64 {
        self.disk_bytes
    }

    pub(in crate::receipt_store) fn wal_frames(&self) -> u64 {
        self.wal_frames
    }

    pub(in crate::receipt_store) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Power-of-two page ceiling the pointer-map term assumed.
    pub(in crate::receipt_store) fn page_bucket(&self) -> u64 {
        self.page_bucket
    }

    /// Most pages the append adds, pointer-map pages included.
    pub(in crate::receipt_store) fn maximum_page_growth(&self) -> u64 {
        self.maximum_page_growth
    }
}

fn refuse(message: impl Into<String>) -> ReceiptStoreError {
    ReceiptStoreError::Conflict(message.into())
}

fn add(left: u64, right: u64) -> Result<u64, ReceiptStoreError> {
    left.checked_add(right)
        .ok_or_else(|| refuse("receipt append quote bound exhausted"))
}

fn mul(left: u64, right: u64) -> Result<u64, ReceiptStoreError> {
    left.checked_mul(right)
        .ok_or_else(|| refuse("receipt append quote bound exhausted"))
}

/// Stored byte lengths of the capability's attribution keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AttributionKeyLengths {
    subject: u64,
    issuer: u64,
}

#[derive(Clone, Copy)]
struct RecordBounds {
    receipt_bytes: u64,
    subject_bytes: u64,
    issuer_bytes: u64,
}

impl RecordBounds {
    fn new(receipt_bytes: u64, keys: AttributionKeyLengths) -> Self {
        Self {
            receipt_bytes,
            subject_bytes: receipt_bytes.max(keys.subject),
            issuer_bytes: receipt_bytes.max(keys.issuer),
        }
    }

    /// Cell bytes of one table row or index entry made of `caps`.
    fn cell_bytes(
        &self,
        caps: impl IntoIterator<Item = Cap>,
        rowid_cell: bool,
    ) -> Result<u64, ReceiptStoreError> {
        let mut total = if rowid_cell {
            add(CELL_FIXED_BYTES, ROWID_VARINT_BYTES)?
        } else {
            CELL_FIXED_BYTES
        };
        let mut field_pool = false;
        for cap in caps {
            total = add(total, COLUMN_HEADER_BYTES)?;
            let value = match cap {
                Cap::Fixed(bytes) => bytes,
                Cap::RawJson => self.receipt_bytes,
                Cap::SubjectKey => self.subject_bytes,
                Cap::IssuerKey => self.issuer_bytes,
                Cap::Reencoded => add(self.receipt_bytes, REENCODING_SLACK_BYTES)?,
                Cap::Field if field_pool => 0,
                Cap::Field => {
                    field_pool = true;
                    self.receipt_bytes
                }
            };
            total = add(total, value)?;
        }
        Ok(total)
    }
}

type SchemaRow = (String, String, String, Option<String>);

fn schema_rows(connection: &rusqlite::Connection) -> Result<Vec<SchemaRow>, ReceiptStoreError> {
    let mut statement = connection.prepare(&format!(
        "SELECT type, name, tbl_name, sql FROM main.sqlite_schema \
         WHERE tbl_name IN ({WRITE_TABLES_SQL}) ORDER BY type, name"
    ))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn canonical_schema_rows(anchored: bool) -> Result<&'static Vec<SchemaRow>, ReceiptStoreError> {
    static ANCHORED: OnceLock<Vec<SchemaRow>> = OnceLock::new();
    static UNANCHORED: OnceLock<Vec<SchemaRow>> = OnceLock::new();
    let cache = if anchored { &ANCHORED } else { &UNANCHORED };
    if let Some(rows) = cache.get() {
        return Ok(rows);
    }
    let rows = schema_rows(&super::open::canonical_receipt_schema_model(anchored)?)?;
    Ok(cache.get_or_init(|| rows))
}

fn verify_schema_against(
    connection: &rusqlite::Connection,
    canonical: &[SchemaRow],
) -> Result<Vec<SchemaRow>, ReceiptStoreError> {
    let actual = schema_rows(connection)?;
    for table in SCHEMA_TABLES {
        if !canonical
            .iter()
            .any(|(kind, name, _, _)| kind == "table" && name == table)
        {
            return Err(refuse(format!("canonical receipt schema lacks `{table}`")));
        }
    }
    if actual != canonical {
        return Err(refuse(
            "receipt write schema differs from the canonical maintained model",
        ));
    }
    Ok(actual)
}

fn table_columns(
    connection: &rusqlite::Connection,
    table: &str,
) -> Result<Vec<String>, ReceiptStoreError> {
    let mut statement =
        connection.prepare("SELECT name, hidden FROM pragma_table_xinfo(?1) ORDER BY cid")?;
    let rows = statement
        .query_map([table], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.iter().any(|(_, hidden)| *hidden != 0) {
        return Err(refuse(format!("`{table}` has hidden or generated columns")));
    }
    Ok(rows.into_iter().map(|(name, _)| name).collect())
}

fn require_rowid_table(
    connection: &rusqlite::Connection,
    table: &str,
) -> Result<(), ReceiptStoreError> {
    let without_rowid: i64 = connection.query_row(
        "SELECT wr FROM pragma_table_list(?1) WHERE schema = 'main' AND type = 'table'",
        [table],
        |row| row.get(0),
    )?;
    if without_rowid != 0 {
        return Err(refuse(format!("`{table}` is not a rowid table")));
    }
    Ok(())
}

fn index_names(
    connection: &rusqlite::Connection,
    table: &str,
) -> Result<Vec<String>, ReceiptStoreError> {
    let mut statement =
        connection.prepare("SELECT name FROM pragma_index_list(?1) ORDER BY name")?;
    let names = statement
        .query_map([table], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names)
}

/// Every entry column of an index, including its trailing rowid, as
/// `(cid, name)`. An expression column has cid -2 and no name.
fn index_columns(
    connection: &rusqlite::Connection,
    index: &str,
) -> Result<Vec<(i64, Option<String>)>, ReceiptStoreError> {
    let mut statement =
        connection.prepare("SELECT cid, name FROM pragma_index_xinfo(?1) ORDER BY seqno")?;
    let columns = statement
        .query_map([index], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(columns)
}

fn inserted_table_shapes(
    connection: &rusqlite::Connection,
    write: &WriteTable,
    bounds: &RecordBounds,
) -> Result<Vec<SqliteTreeWriteShapeData>, ReceiptStoreError> {
    require_rowid_table(connection, write.table)?;
    let columns = table_columns(connection, write.table)?;
    if columns.len() != write.columns.len()
        || columns
            .iter()
            .zip(write.columns)
            .any(|(actual, (expected, _))| actual != expected)
    {
        return Err(refuse(format!(
            "`{}` columns differ from the priced writer",
            write.table
        )));
    }
    let row = bounds.cell_bytes(write.columns.iter().map(|(_, cap)| *cap), true)?;
    let mut trees = vec![SqliteTreeWriteShapeData::fresh_insertions(row, 1).map_err(refuse)?];
    for index in index_names(connection, write.table)? {
        let mut caps = Vec::new();
        for (cid, name) in index_columns(connection, &index)? {
            let cap = match (cid, name.as_deref()) {
                (-1, _) => Cap::Fixed(INTEGER_BYTES),
                (-2, _) => Cap::Field,
                (_, Some(name)) => write
                    .columns
                    .iter()
                    .find(|(column, _)| *column == name)
                    .map(|(_, cap)| *cap)
                    .ok_or_else(|| refuse(format!("index `{index}` has an unpriced column")))?,
                _ => return Err(refuse(format!("index `{index}` has an unnamed column"))),
            };
            caps.push(cap);
        }
        let entry = bounds.cell_bytes(caps, false)?;
        trees.push(SqliteTreeWriteShapeData::fresh_insertions(entry, 1).map_err(refuse)?);
    }
    Ok(trees)
}

fn sink_generation_shape(
    connection: &rusqlite::Connection,
    bounds: &RecordBounds,
) -> Result<SqliteTreeWriteShapeData, ReceiptStoreError> {
    let write = &SINK_GENERATION_WRITE;
    require_rowid_table(connection, write.table)?;
    let columns = table_columns(connection, write.table)?;
    if columns != ["singleton", "store_generation"]
        || !index_names(connection, write.table)?.is_empty()
    {
        return Err(refuse(
            "sink generation table is not an index-free singleton",
        ));
    }
    let row = bounds.cell_bytes(write.columns.iter().map(|(_, cap)| *cap), true)?;
    SqliteTreeWriteShapeData::singleton_root(row, 1).map_err(refuse)
}

/// `sqlite_sequence` holds one row per AUTOINCREMENT table; the receipt and
/// claim-log tables each rewrite theirs within the same transaction.
fn sequence_shape(bounds: &RecordBounds) -> Result<SqliteTreeWriteShapeData, ReceiptStoreError> {
    let row = bounds.cell_bytes(
        [
            Cap::Fixed(AUTOINCREMENT_NAME_BYTES),
            Cap::Fixed(SEQUENCE_VALUE_BYTES),
        ],
        true,
    )?;
    SqliteTreeWriteShapeData::record(Some(row), row, 2).map_err(refuse)
}

struct PhysicalProfile {
    page_size: u64,
    page_count: u64,
    incremental_vacuum: bool,
    reserved_bytes: u64,
    sector_bytes: u64,
    device_characteristics: u32,
    vfs_name: String,
}

fn pragma_i64(connection: &rusqlite::Connection, sql: &str) -> Result<i64, ReceiptStoreError> {
    Ok(connection.query_row(sql, [], |row| row.get::<_, i64>(0))?)
}

fn pragma_u64(connection: &rusqlite::Connection, sql: &str) -> Result<u64, ReceiptStoreError> {
    u64::try_from(pragma_i64(connection, sql)?)
        .map_err(|_| refuse("SQLite reported a negative physical measure"))
}

fn attached_database_names(
    connection: &rusqlite::Connection,
) -> Result<Vec<String>, ReceiptStoreError> {
    let mut statement = connection.prepare("SELECT name FROM pragma_database_list")?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names)
}

fn physical_profile(
    connection: &rusqlite::Connection,
) -> Result<PhysicalProfile, ReceiptStoreError> {
    let source: String = connection.query_row("SELECT sqlite_source_id()", [], |row| row.get(0))?;
    let encoding: String = connection.query_row("PRAGMA main.encoding", [], |row| row.get(0))?;
    let journal: String = connection.query_row("PRAGMA main.journal_mode", [], |row| row.get(0))?;
    let synchronous = pragma_i64(connection, "PRAGMA main.synchronous")?;
    let spill = pragma_i64(connection, "PRAGMA main.cache_spill")?;
    let auto_vacuum = pragma_i64(connection, "PRAGMA main.auto_vacuum")?;
    let page_size = pragma_u64(connection, "PRAGMA main.page_size")?;
    let page_count = pragma_u64(connection, "PRAGMA main.page_count")?;
    let attached = attached_database_names(connection)?;
    let temporary_objects = pragma_i64(connection, "SELECT COUNT(*) FROM temp.sqlite_schema")?;
    if source != BUNDLED_SQLITE_SOURCE_ID
        || encoding != "UTF-8"
        || !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        // A spilled cache would rewrite pages after the frame bound is taken.
        || spill != 0
        // FULL auto-vacuum compacts at commit, relocating an unbounded number
        // of pages; NONE and INCREMENTAL never do.
        || !matches!(auto_vacuum, 0 | 2)
        || attached.iter().any(|name| name != "main" && name != "temp")
        || temporary_objects != 0
    {
        return Err(refuse("receipt append physical profile is unsupported"));
    }
    let geometry = main_database_write_geometry(connection).map_err(refuse)?;
    SqliteFramePriceProfileData::checked(page_size, geometry.reserved_bytes()).map_err(refuse)?;
    Ok(PhysicalProfile {
        page_size,
        page_count,
        incremental_vacuum: auto_vacuum == 2,
        reserved_bytes: geometry.reserved_bytes(),
        sector_bytes: geometry.sector_bytes(),
        device_characteristics: geometry.device_characteristics(),
        vfs_name: geometry.vfs_name().to_owned(),
    })
}

struct PageBudget {
    bucket: u64,
    growth: u64,
    extra_frames: u64,
}

/// Page growth, the power-of-two page ceiling, and the extra frames an
/// auto-vacuum database dirties in its pointer-map pages.
///
/// Every page the append allocates is one of its `base_frames`, so data growth
/// is at most that. Extending a file by `g` pages adds at most `ceil(g / map
/// span) + 1` pointer-map pages. Every `ptrmapPut` (btree.c: overflow,
/// free-page, new-sibling, root and `setChildPtrmaps`) rewrites at most one
/// pointer-map page and only when its entry changes; a page holds at most
/// `usable/2 + 1` puts (two per minimum four-byte cell plus the right child),
/// and puts come only from pages already counted in `base_frames`. The distinct
/// pages are also capped by the pointer-map pages of a database no larger than
/// the bucket, which is the larger of the retained minimum and the power of two
/// above the current size plus growth.
fn page_budget(
    profile: &PhysicalProfile,
    base_frames: u64,
    minimum_bucket: u64,
) -> Result<PageBudget, ReceiptStoreError> {
    let pages_per_map = profile.page_size / 5 + 1;
    let growth = if profile.incremental_vacuum {
        add(add(base_frames, base_frames.div_ceil(pages_per_map))?, 1)?
    } else {
        base_frames
    };
    let bucket = add(profile.page_count, growth)?
        .checked_next_power_of_two()
        .ok_or_else(|| refuse("receipt append database size bound exhausted"))?
        .max(minimum_bucket);
    let extra_frames = if profile.incremental_vacuum {
        // One more for the pending-byte page the map layout skips.
        let map_pages = add(bucket.div_ceil(pages_per_map), 1)?;
        map_pages.min(mul(base_frames, profile.page_size / 2 + 1)?)
    } else {
        0
    };
    Ok(PageBudget {
        bucket,
        growth,
        extra_frames,
    })
}

/// Stored lengths of the capability's attribution keys. The row is the
/// original's own token snapshot and its keys are never updated after insert.
fn attribution_key_lengths(
    connection: &rusqlite::Connection,
    capability_id: &str,
) -> Result<AttributionKeyLengths, ReceiptStoreError> {
    let lengths = connection
        .query_row(
            "SELECT length(CAST(subject_key AS BLOB)), length(CAST(issuer_key AS BLOB)) \
             FROM capability_lineage WHERE capability_id = ?1",
            [capability_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((subject, issuer)) = lengths else {
        return Err(refuse("receipt append capability lineage row is absent"));
    };
    let to_length = |length: i64| {
        u64::try_from(length).map_err(|_| refuse("capability lineage key length is invalid"))
    };
    Ok(AttributionKeyLengths {
        subject: to_length(subject)?,
        issuer: to_length(issuer)?,
    })
}

fn fingerprint(
    profile: &PhysicalProfile,
    schema: &[SchemaRow],
    keys: AttributionKeyLengths,
    page_bucket: u64,
) -> String {
    fn part(bytes: &mut Vec<u8>, text: &str) {
        bytes.extend_from_slice(&(text.len() as u64).to_le_bytes());
        bytes.extend_from_slice(text.as_bytes());
    }
    let mut bytes = Vec::new();
    part(&mut bytes, QUOTE_DESCRIPTOR);
    part(&mut bytes, write_price_algorithm_descriptor());
    part(&mut bytes, BUNDLED_SQLITE_SOURCE_ID);
    part(
        &mut bytes,
        &format!(
            "{};{};{};{};{};{};{};{};{};{}",
            profile.page_size,
            profile.incremental_vacuum,
            profile.reserved_bytes,
            profile.sector_bytes,
            profile.device_characteristics,
            profile.vfs_name,
            REENCODING_SLACK_BYTES,
            keys.subject,
            keys.issuer,
            page_bucket,
        ),
    );
    for write in INSERTED_TABLES
        .iter()
        .copied()
        .chain([&SINK_GENERATION_WRITE])
    {
        part(&mut bytes, write.table);
        for (column, cap) in write.columns {
            part(&mut bytes, &format!("{column}={cap:?}"));
        }
    }
    for (kind, name, table, sql) in schema {
        part(&mut bytes, kind);
        part(&mut bytes, name);
        part(&mut bytes, table);
        part(&mut bytes, sql.as_deref().unwrap_or(""));
    }
    sha256_hex(&bytes)
}

fn quote_against(
    connection: &rusqlite::Connection,
    recipe: &ReceiptAppendRecipeData<'_>,
    canonical: &[SchemaRow],
) -> Result<ReceiptAppendQuoteData, ReceiptStoreError> {
    if recipe.receipt_bytes == 0 {
        return Err(refuse("receipt append quote has no receipt bytes"));
    }
    if !recipe.minimum_page_bucket.is_power_of_two() {
        return Err(refuse("receipt append page bucket is not a power of two"));
    }
    let profile = physical_profile(connection)?;
    let schema = verify_schema_against(connection, canonical)?;
    let keys = attribution_key_lengths(connection, recipe.capability_id)?;
    let bounds = RecordBounds::new(recipe.receipt_bytes, keys);
    let mut trees = Vec::new();
    for write in INSERTED_TABLES {
        trees.extend(inserted_table_shapes(connection, write, &bounds)?);
    }
    trees.push(sequence_shape(&bounds)?);
    if recipe.anchored {
        trees.push(sink_generation_shape(connection, &bounds)?);
    }

    let frame_profile =
        SqliteFramePriceProfileData::checked(profile.page_size, profile.reserved_bytes)
            .map_err(refuse)?;
    let shape = SqliteTransactionWriteShapeData::checked(trees).map_err(refuse)?;
    let base = price_transaction_write_shape(&frame_profile, &shape).map_err(refuse)?;
    let padding = frame_profile
        .price_frames(1)
        .map_err(refuse)?
        .wal_frames()
        .checked_sub(1)
        .ok_or_else(|| refuse("receipt append commit padding is empty"))?;
    let base_frames = base
        .wal_frames()
        .checked_sub(padding)
        .filter(|frames| *frames > 0)
        .ok_or_else(|| refuse("receipt append frame bound is empty"))?;
    let budget = page_budget(&profile, base_frames, recipe.minimum_page_bucket)?;
    let priced = frame_profile
        .price_frames(add(base_frames, budget.extra_frames)?)
        .map_err(refuse)?;
    if priced.disk_bytes() < priced.wal_bytes() || priced.wal_bytes() < base.wal_bytes() {
        return Err(refuse("receipt append quote is inconsistent"));
    }
    Ok(ReceiptAppendQuoteData {
        wal_bytes: priced.wal_bytes(),
        disk_bytes: priced.disk_bytes(),
        wal_frames: priced.wal_frames(),
        fingerprint: fingerprint(&profile, &schema, keys, budget.bucket),
        page_bucket: budget.bucket,
        maximum_page_growth: budget.growth,
    })
}

/// Quote one append of the recipe's receipt.
///
/// The write set is the receipt row with its claim-log trigger row and both
/// `sqlite_sequence` rows, one fresh lineage row, settlement attempt zero and
/// the sink-generation compare-and-swap. The sink guarantees no lineage row
/// names an owed native receipt as `receipt_id` or `parent_receipt_id` before
/// the append commits, so the lineage writer refreshes nothing. Reads only; it
/// opens no transaction.
pub(in crate::receipt_store) fn quote_receipt_append(
    connection: &rusqlite::Connection,
    recipe: &ReceiptAppendRecipeData<'_>,
) -> Result<ReceiptAppendQuoteData, ReceiptStoreError> {
    quote_against(connection, recipe, canonical_schema_rows(recipe.anchored)?)
}

/// Authenticated inputs of one ordinary batch request, mapped by the batch
/// writer from its own request queue. They are DATA, not authority: the quote
/// prices only what the real writer can write for these inputs.
pub(in crate::receipt_store) struct OrdinaryReceiptAppendRequestData<'a> {
    /// Canonical raw bytes of the request's receipt envelope.
    pub(in crate::receipt_store) receipt_bytes: u64,
    /// The receipt's own id, which the lineage ensure helper refreshes by.
    pub(in crate::receipt_store) receipt_id: &'a str,
    /// The capability whose lineage row supplies the attribution key lengths.
    pub(in crate::receipt_store) capability_id: &'a str,
    /// Whether the writer runs the lineage ensure helper for this request.
    pub(in crate::receipt_store) ensure_lineage: bool,
    /// Whether the ensure helper would CREATE a fresh lineage row for this
    /// receipt: governed transaction metadata with a call chain, exactly the
    /// writer's own extraction.
    pub(in crate::receipt_store) creates_governed_lineage_row: bool,
    /// Parent receipt id of the governed call chain when one is present.
    pub(in crate::receipt_store) governed_parent_receipt_id: Option<String>,
}

const ORDINARY_BATCH_QUOTE_DESCRIPTOR: &str = "chio.ordinary-receipt-batch-quote; bundled3.51.3; \
rowid_tables_only; fresh_insertions_per_tree; streamed_existing_lineage_refreshes; \
intra_batch_created_edges; duplicate_requests_repriced; sequence_two_updates; \
sink_generation_singleton_root; absent_capability_lineage_bounded_by_receipt; \
page_bucket=max(minimum,pow2(page_count+growth)); \
ptrmap_extra=min(map_pages_at_bucket,frames*(usable/2+1)); cache_spill_off; \
temp_schema_empty; model_schema_equality";

/// Column positions, in the priced lineage column order, of the four
/// verification booleans the lineage refresh update rewrites.
const LINEAGE_REFRESH_BOOLEAN_COLUMNS: [usize; 4] = [10, 11, 12, 13];

/// Stored byte width of one actual value under its serial type, at the
/// widest encoding of its class.
fn value_ref_bound(value: rusqlite::types::ValueRef<'_>) -> u64 {
    use rusqlite::types::ValueRef;
    match value {
        ValueRef::Null => 0,
        ValueRef::Integer(_) | ValueRef::Real(_) => INTEGER_BYTES,
        ValueRef::Text(text) => u64::try_from(text.len()).unwrap_or(u64::MAX),
        ValueRef::Blob(blob) => u64::try_from(blob.len()).unwrap_or(u64::MAX),
    }
}

/// One column of a schema-verified lineage index.
enum LineageIndexColumn {
    Rowid,
    Column(usize),
    Expression,
}

struct LineageIndexShape {
    columns: Vec<LineageIndexColumn>,
}

/// Every schema-verified index of the lineage table with its priced column
/// positions. An index column outside the priced writer refuses the quote.
fn lineage_index_shapes(
    connection: &rusqlite::Connection,
) -> Result<Vec<LineageIndexShape>, ReceiptStoreError> {
    let mut shapes = Vec::new();
    for index in index_names(connection, LINEAGE_WRITE.table)? {
        let mut columns = Vec::new();
        for (cid, name) in index_columns(connection, &index)? {
            let column = match (cid, name.as_deref()) {
                (-1, _) => LineageIndexColumn::Rowid,
                (-2, _) => LineageIndexColumn::Expression,
                (_, Some(name)) => LineageIndexColumn::Column(
                    LINEAGE_WRITE
                        .columns
                        .iter()
                        .position(|(column, _)| *column == name)
                        .ok_or_else(|| {
                            refuse(format!("lineage index `{index}` has an unpriced column"))
                        })?,
                ),
                _ => {
                    return Err(refuse(format!(
                        "lineage index `{index}` has an unnamed column"
                    )))
                }
            };
            columns.push(column);
        }
        shapes.push(LineageIndexShape { columns });
    }
    Ok(shapes)
}

/// Conservative physical price of the existing lineage rows one ensure
/// request's helper updates: its own statement row and every child row
/// naming the request's receipt as parent. Rows stream through a cursor;
/// only checked scalar bounds are accumulated, never row history.
struct LineageRefreshPrice {
    self_row_exists: bool,
    /// UPDATE statements the real helper issues over the streamed rows: one
    /// per self row plus one per parent-naming row, bounded by the actual
    /// matching row count.
    updates: u64,
    /// Widest existing record image among the refreshed rows.
    max_old_cell: u64,
    /// Widest rewritten record image, the four booleans at their widest.
    max_new_cell: u64,
    /// Widest index entry among the refreshed rows, per verified index.
    max_index_entries: Vec<u64>,
}

fn accumulate_existing_lineage_refresh(
    connection: &rusqlite::Connection,
    indexes: &[LineageIndexShape],
    receipt_id: &str,
) -> Result<LineageRefreshPrice, ReceiptStoreError> {
    let columns = LINEAGE_WRITE
        .columns
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT {columns} FROM receipt_lineage_statements \
         WHERE receipt_id = ?1 OR parent_receipt_id = ?1"
    );
    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement.query([receipt_id])?;
    let mut price = LineageRefreshPrice {
        self_row_exists: false,
        updates: 0,
        max_old_cell: 0,
        max_new_cell: 0,
        max_index_entries: vec![0; indexes.len()],
    };
    while let Some(row) = rows.next().map_err(ReceiptStoreError::Sqlite)? {
        use rusqlite::types::ValueRef;
        let mut values = [0_u64; 18];
        let mut max_value = 0_u64;
        for (position, value) in values.iter_mut().enumerate() {
            let bound = value_ref_bound(row.get_ref(position)?);
            *value = bound;
            max_value = add(max_value, bound)?;
        }
        let mut old_cell = add(CELL_FIXED_BYTES, ROWID_VARINT_BYTES)?;
        let mut new_cell = old_cell;
        for (position, bound) in values.iter().copied().enumerate() {
            old_cell = add(old_cell, add(COLUMN_HEADER_BYTES, bound)?)?;
            let after = if LINEAGE_REFRESH_BOOLEAN_COLUMNS.contains(&position) {
                bound.max(INTEGER_BYTES)
            } else {
                bound
            };
            new_cell = add(new_cell, add(COLUMN_HEADER_BYTES, after)?)?;
        }
        price.max_old_cell = price.max_old_cell.max(old_cell);
        price.max_new_cell = price.max_new_cell.max(new_cell);
        for (position, shape) in indexes.iter().enumerate() {
            let mut entry = CELL_FIXED_BYTES;
            for column in &shape.columns {
                entry = add(entry, COLUMN_HEADER_BYTES)?;
                entry = add(
                    entry,
                    match column {
                        LineageIndexColumn::Rowid => INTEGER_BYTES,
                        LineageIndexColumn::Column(at) => values[*at],
                        // An expression column is computed from the row's own
                        // stored values, so the widest of them bounds it.
                        LineageIndexColumn::Expression => max_value,
                    },
                )?;
            }
            price.max_index_entries[position] = price.max_index_entries[position].max(entry);
        }
        let self_match =
            matches!(row.get_ref(0)?, ValueRef::Text(text) if text == receipt_id.as_bytes());
        let parent_match =
            matches!(row.get_ref(7)?, ValueRef::Text(text) if text == receipt_id.as_bytes());
        price.self_row_exists |= self_match;
        price.updates = add(
            price.updates,
            add(u64::from(self_match), u64::from(parent_match))?,
        )?;
    }
    Ok(price)
}

/// Priced rewrite trees of the streamed existing-lineage refresh.
fn lineage_refresh_trees(
    price: &LineageRefreshPrice,
) -> Result<Vec<SqliteTreeWriteShapeData>, ReceiptStoreError> {
    let mut trees = Vec::new();
    if price.updates == 0 {
        return Ok(trees);
    }
    let after = price.max_new_cell.max(price.max_old_cell);
    trees.push(
        SqliteTreeWriteShapeData::record(Some(price.max_old_cell), after, price.updates)
            .map_err(refuse)?,
    );
    for entry in &price.max_index_entries {
        // A verified index is overcounted: the refresh rewrites only the
        // four verification booleans, so index entries that contain none of
        // them never reach SQLite. Charging them is the safe side.
        if *entry > 0 {
            trees.push(
                SqliteTreeWriteShapeData::record(Some(*entry), *entry, price.updates)
                    .map_err(refuse)?,
            );
        }
    }
    Ok(trees)
}

/// Priced rewrite trees of one lineage row an earlier request of the same
/// batch created, bounded by that creating receipt's own record bounds.
fn created_lineage_refresh_trees(
    bounds: &RecordBounds,
    indexes: &[LineageIndexShape],
    updates: u64,
) -> Result<Vec<SqliteTreeWriteShapeData>, ReceiptStoreError> {
    let mut trees = Vec::new();
    if updates == 0 {
        return Ok(trees);
    }
    let cell = bounds.cell_bytes(LINEAGE_WRITE.columns.iter().map(|(_, cap)| *cap), true)?;
    trees.push(SqliteTreeWriteShapeData::record(Some(cell), cell, updates).map_err(refuse)?);
    for shape in indexes {
        let caps = shape
            .columns
            .iter()
            .map(|column| match column {
                LineageIndexColumn::Rowid => Cap::Fixed(INTEGER_BYTES),
                LineageIndexColumn::Column(at) => LINEAGE_WRITE.columns[*at].1,
                LineageIndexColumn::Expression => Cap::Field,
            })
            .collect::<Vec<_>>();
        let entry = bounds.cell_bytes(caps, false)?;
        trees.push(SqliteTreeWriteShapeData::record(Some(entry), entry, updates).map_err(refuse)?);
    }
    Ok(trees)
}

/// Stored lengths of the capability's attribution keys when its lineage row
/// exists. An ordinary receipt without one keeps its attribution inside its
/// own envelope (or NULL), so the receipt bound covers it; the funded native
/// quote still refuses this case.
fn ordinary_attribution_key_lengths(
    connection: &rusqlite::Connection,
    capability_id: &str,
) -> Result<AttributionKeyLengths, ReceiptStoreError> {
    let lengths = connection
        .query_row(
            "SELECT length(CAST(subject_key AS BLOB)), length(CAST(issuer_key AS BLOB)) \
             FROM capability_lineage WHERE capability_id = ?1",
            [capability_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((subject, issuer)) = lengths else {
        return Ok(AttributionKeyLengths {
            subject: 0,
            issuer: 0,
        });
    };
    let to_length = |length: i64| {
        u64::try_from(length).map_err(|_| refuse("capability lineage key length is invalid"))
    };
    Ok(AttributionKeyLengths {
        subject: to_length(subject)?,
        issuer: to_length(issuer)?,
    })
}

fn ordinary_batch_fingerprint(
    profile: &PhysicalProfile,
    schema: &[SchemaRow],
    requests: &[OrdinaryReceiptAppendRequestData<'_>],
    page_bucket: u64,
) -> String {
    fn part(bytes: &mut Vec<u8>, text: &str) {
        bytes.extend_from_slice(&(text.len() as u64).to_le_bytes());
        bytes.extend_from_slice(text.as_bytes());
    }
    let mut bytes = Vec::new();
    part(&mut bytes, ORDINARY_BATCH_QUOTE_DESCRIPTOR);
    part(&mut bytes, write_price_algorithm_descriptor());
    part(&mut bytes, BUNDLED_SQLITE_SOURCE_ID);
    part(
        &mut bytes,
        &format!(
            "{};{};{};{};{};{};{};{};{}",
            profile.page_size,
            profile.incremental_vacuum,
            profile.reserved_bytes,
            profile.sector_bytes,
            profile.device_characteristics,
            profile.vfs_name,
            REENCODING_SLACK_BYTES,
            requests.len(),
            page_bucket,
        ),
    );
    for request in requests {
        part(
            &mut bytes,
            &format!(
                "{};{};{};{};{};{}",
                request.receipt_bytes,
                request.receipt_id.len(),
                request.capability_id,
                request.ensure_lineage,
                request.creates_governed_lineage_row,
                request
                    .governed_parent_receipt_id
                    .as_deref()
                    .map_or(0, str::len),
            ),
        );
    }
    for (kind, name, table, sql) in schema {
        part(&mut bytes, kind);
        part(&mut bytes, name);
        part(&mut bytes, table);
        part(&mut bytes, sql.as_deref().unwrap_or(""));
    }
    sha256_hex(&bytes)
}

fn quote_ordinary_batch_against(
    connection: &rusqlite::Connection,
    requests: &[OrdinaryReceiptAppendRequestData<'_>],
    canonical: &[SchemaRow],
    anchored: bool,
) -> Result<ReceiptAppendQuoteData, ReceiptStoreError> {
    if requests.is_empty() {
        return Err(refuse("ordinary receipt batch quote has no requests"));
    }
    for request in requests {
        if request.receipt_bytes == 0 {
            return Err(refuse("ordinary receipt batch quote has no receipt bytes"));
        }
    }
    let profile = physical_profile(connection)?;
    let schema = verify_schema_against(connection, canonical)?;
    // The lineage table shape is validated up front even when no request
    // creates a row: the streamed refresh bound below reads every column.
    require_rowid_table(connection, LINEAGE_WRITE.table)?;
    let lineage_columns = table_columns(connection, LINEAGE_WRITE.table)?;
    if lineage_columns.len() != LINEAGE_WRITE.columns.len()
        || lineage_columns
            .iter()
            .zip(LINEAGE_WRITE.columns)
            .any(|(actual, (expected, _))| actual != expected)
    {
        return Err(refuse(format!(
            "`{}` columns differ from the priced writer",
            LINEAGE_WRITE.table
        )));
    }
    let indexes = lineage_index_shapes(connection)?;
    let mut trees = Vec::new();
    // Lineage rows an earlier request of this batch creates, as
    // (receipt id, parent receipt id, record bounds). A later request's
    // ensure helper refreshes them inside the same transaction; the list
    // length is bounded by the batch queue length.
    let mut created: Vec<(&str, Option<&str>, RecordBounds)> = Vec::new();
    let mut first_bounds = None;
    for request in requests {
        let keys = ordinary_attribution_key_lengths(connection, request.capability_id)?;
        let bounds = RecordBounds::new(request.receipt_bytes, keys);
        if first_bounds.is_none() {
            first_bounds = Some(bounds);
        }
        // The fresh receipt and claim-log insertions are priced for every
        // request, duplicates included: an idempotent duplicate writes less,
        // never more, than its priced fresh shape.
        trees.extend(inserted_table_shapes(
            connection,
            &TOOL_RECEIPT_WRITE,
            &bounds,
        )?);
        trees.extend(inserted_table_shapes(
            connection,
            &CLAIM_LOG_WRITE,
            &bounds,
        )?);
        // Each attempted insert may advance both AUTOINCREMENT rows,
        // including a conflicting duplicate. Retain every mutation in the
        // bound rather than assuming only the final images reach SQLite.
        trees.push(sequence_shape(&bounds)?);
        if !request.ensure_lineage {
            continue;
        }
        // Stream every existing lineage row this request's ensure helper
        // updates: its own statement row and every child naming this receipt
        // as parent.
        let refresh =
            accumulate_existing_lineage_refresh(connection, &indexes, request.receipt_id)?;
        trees.extend(lineage_refresh_trees(&refresh)?);
        // Intra-batch edges: a row created by an earlier request of this
        // same batch is refreshed the same way, priced from its creating
        // receipt's own record bounds.
        let mut self_created = false;
        for (created_id, created_parent, created_bounds) in &created {
            let self_edge = *created_id == request.receipt_id;
            let parent_edge = *created_parent == Some(request.receipt_id);
            if !self_edge && !parent_edge {
                continue;
            }
            trees.extend(created_lineage_refresh_trees(created_bounds, &indexes, 1)?);
            self_created |= self_edge;
        }
        if refresh.self_row_exists || self_created {
            // The helper found its own statement row and only refreshes.
            continue;
        }
        if request.creates_governed_lineage_row {
            trees.extend(inserted_table_shapes(connection, &LINEAGE_WRITE, &bounds)?);
            created.push((
                request.receipt_id,
                request.governed_parent_receipt_id.as_deref(),
                bounds,
            ));
        }
    }
    let Some(first_bounds) = first_bounds else {
        return Err(refuse("ordinary receipt batch quote has no requests"));
    };
    if anchored {
        trees.push(sink_generation_shape(connection, &first_bounds)?);
    }

    let frame_profile =
        SqliteFramePriceProfileData::checked(profile.page_size, profile.reserved_bytes)
            .map_err(refuse)?;
    let shape = SqliteTransactionWriteShapeData::checked(trees).map_err(refuse)?;
    let base = price_transaction_write_shape(&frame_profile, &shape).map_err(refuse)?;
    let padding = frame_profile
        .price_frames(1)
        .map_err(refuse)?
        .wal_frames()
        .checked_sub(1)
        .ok_or_else(|| refuse("ordinary receipt batch commit padding is empty"))?;
    let base_frames = base
        .wal_frames()
        .checked_sub(padding)
        .filter(|frames| *frames > 0)
        .ok_or_else(|| refuse("ordinary receipt batch frame bound is empty"))?;
    let budget = page_budget(&profile, base_frames, 1)?;
    let priced = frame_profile
        .price_frames(add(base_frames, budget.extra_frames)?)
        .map_err(refuse)?;
    if priced.disk_bytes() < priced.wal_bytes() || priced.wal_bytes() < base.wal_bytes() {
        return Err(refuse("ordinary receipt batch quote is inconsistent"));
    }
    Ok(ReceiptAppendQuoteData {
        wal_bytes: priced.wal_bytes(),
        disk_bytes: priced.disk_bytes(),
        wal_frames: priced.wal_frames(),
        fingerprint: ordinary_batch_fingerprint(&profile, &schema, requests, budget.bucket),
        page_bucket: budget.bucket,
        maximum_page_growth: budget.growth,
    })
}

/// Quote one coalesced ordinary receipt batch before its first mutation:
/// every request's fresh receipt and claim-log insertion with its indexes,
/// the two `sqlite_sequence` rows, the sink-generation compare-and-swap,
/// and, for each ensure request, the actual existing lineage rows the real
/// helper updates plus every intra-batch created edge, duplicates priced
/// as their fresh shape. Ordinary is Intake: the quote prices DATA, funds
/// nothing and authorizes no writer. A request without a capability lineage
/// row stays quotable (its attribution stays inside its own envelope).
/// Reads only; it opens no transaction.
pub(in crate::receipt_store) fn quote_ordinary_receipt_batch(
    connection: &rusqlite::Connection,
    requests: &[OrdinaryReceiptAppendRequestData<'_>],
    anchored: bool,
) -> Result<ReceiptAppendQuoteData, ReceiptStoreError> {
    quote_ordinary_batch_against(
        connection,
        requests,
        canonical_schema_rows(anchored)?,
        anchored,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYS: AttributionKeyLengths = AttributionKeyLengths {
        subject: 64,
        issuer: 64,
    };

    fn canonical_model() -> Result<rusqlite::Connection, ReceiptStoreError> {
        super::super::open::canonical_receipt_schema_model(true)
    }

    #[test]
    fn canonical_model_prices_every_written_tree() -> Result<(), ReceiptStoreError> {
        let model = canonical_model()?;
        let bounds = RecordBounds::new(4096, KEYS);
        let mut trees = 0;
        for write in INSERTED_TABLES {
            let shapes = inserted_table_shapes(&model, write, &bounds)?;
            assert!(shapes.len() > 1, "{} has no priced index", write.table);
            trees += shapes.len();
        }
        sink_generation_shape(&model, &bounds)?;
        sequence_shape(&bounds)?;
        assert!(trees > 20);
        Ok(())
    }

    #[test]
    fn a_changed_index_trigger_or_column_is_refused() -> Result<(), ReceiptStoreError> {
        let canonical = schema_rows(&canonical_model()?)?;
        assert_eq!(
            verify_schema_against(&canonical_model()?, &canonical)?,
            canonical
        );
        for drift in [
            "CREATE INDEX idx_extra ON chio_tool_receipts(raw_json)",
            "CREATE TRIGGER trg_extra AFTER INSERT ON settle_attempts BEGIN SELECT 1; END",
            "ALTER TABLE receipt_lineage_statements ADD COLUMN extra TEXT",
        ] {
            let drifted = canonical_model()?;
            drifted.execute_batch(drift)?;
            assert!(
                verify_schema_against(&drifted, &canonical).is_err(),
                "{drift}"
            );
        }
        Ok(())
    }

    #[test]
    fn receipt_schema_matches_the_owning_writers_anchor_mode() -> Result<(), ReceiptStoreError> {
        for anchored in [false, true] {
            let model = super::super::open::canonical_receipt_schema_model(anchored)?;
            let canonical = canonical_schema_rows(anchored)?;
            assert_eq!(verify_schema_against(&model, canonical)?, *canonical);
            // A missing generation in an anchored sink is corruption, not an
            // instruction to fall back to the ordinary unanchored contract.
            assert!(verify_schema_against(&model, canonical_schema_rows(!anchored)?).is_err());
            model.execute_batch(
                "CREATE INDEX extra_receipt_write ON chio_tool_receipts(raw_json)",
            )?;
            assert!(verify_schema_against(&model, canonical).is_err());
        }
        Ok(())
    }

    #[test]
    fn an_unpriced_column_is_refused() -> Result<(), ReceiptStoreError> {
        let model = canonical_model()?;
        model.execute_batch("ALTER TABLE claim_receipt_log_entries ADD COLUMN extra TEXT")?;
        let bounds = RecordBounds::new(64, KEYS);
        assert!(inserted_table_shapes(&model, &CLAIM_LOG_WRITE, &bounds).is_err());
        Ok(())
    }

    #[test]
    fn exact_key_lengths_and_larger_receipts_raise_the_cell_bound() -> Result<(), ReceiptStoreError>
    {
        let caps = [Cap::Field, Cap::RawJson, Cap::SubjectKey, Cap::Reencoded];
        let small = RecordBounds::new(1, KEYS).cell_bytes(caps, true)?;
        let large = RecordBounds::new(1 << 20, KEYS).cell_bytes(caps, true)?;
        let long_subject = AttributionKeyLengths {
            subject: 1 << 20,
            issuer: 64,
        };
        let keyed = RecordBounds::new(1, long_subject).cell_bytes(caps, true)?;
        assert!(large > small);
        assert!(keyed > small);
        assert!(RecordBounds::new(u64::MAX, KEYS)
            .cell_bytes(caps, true)
            .is_err());
        Ok(())
    }

    #[test]
    fn page_budget_is_deterministic_and_pointer_maps_need_incremental_vacuum(
    ) -> Result<(), ReceiptStoreError> {
        let profile = |incremental_vacuum, page_count| PhysicalProfile {
            page_size: 4096,
            page_count,
            incremental_vacuum,
            reserved_bytes: 0,
            sector_bytes: 4096,
            device_characteristics: 0,
            vfs_name: "unix".to_owned(),
        };
        let none = page_budget(&profile(false, 1 << 20), 1000, 1)?;
        assert_eq!((none.extra_frames, none.growth), (0, 1000));
        let small = page_budget(&profile(true, 100), 1000, 1)?;
        let large = page_budget(&profile(true, 1 << 20), 1000, 1)?;
        assert!(small.extra_frames > 0 && large.extra_frames > small.extra_frames);
        assert!(large.extra_frames <= 1000 * (4096 / 2 + 1));
        assert!(large.bucket.is_power_of_two() && large.bucket >= (1 << 20) + large.growth);
        let retained = page_budget(&profile(true, 100), 1000, large.bucket)?;
        assert_eq!(retained.bucket, large.bucket);
        assert_eq!(retained.extra_frames, large.extra_frames);
        assert_eq!(
            page_budget(&profile(true, 100), 1000, 1)?.bucket,
            small.bucket
        );
        Ok(())
    }

    fn seeded_lineage_row(
        connection: &rusqlite::Connection,
        receipt_id: &str,
        parent_receipt_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        connection.execute(
            "INSERT INTO receipt_lineage_statements \
             (receipt_id, parent_receipt_id, verified_session_anchor, verified_parent_request, \
              verified_parent_receipt, replay_protected, recorded_at, source_kind, \
              json_sha256, raw_json) \
             VALUES (?1, ?2, 0, 0, 0, 0, 1, 'test', ?3, ?4)",
            rusqlite::params![
                receipt_id,
                parent_receipt_id,
                format!("{receipt_id}-sha"),
                format!("{{\"id\":\"{receipt_id}\"}}"),
            ],
        )?;
        Ok(())
    }

    /// The existing-lineage refresh streams the exact rows the real ensure
    /// helper updates: one statement per self row plus one per child naming
    /// the request's receipt as parent, with actual old/new record bounds.
    #[test]
    fn existing_parent_refresh_streams_actual_rows() -> Result<(), ReceiptStoreError> {
        let model = canonical_model()?;
        seeded_lineage_row(&model, "child-1", Some("parent-1"))?;
        seeded_lineage_row(&model, "child-2", Some("parent-1"))?;
        let indexes = lineage_index_shapes(&model)?;
        let refresh = accumulate_existing_lineage_refresh(&model, &indexes, "parent-1")?;
        assert!(!refresh.self_row_exists);
        assert_eq!(refresh.updates, 2);
        assert!(refresh.max_old_cell > 0);
        let trees = lineage_refresh_trees(&refresh)?;
        assert_eq!(trees.len(), indexes.len() + 1);
        let self_refresh = accumulate_existing_lineage_refresh(&model, &indexes, "child-1")?;
        assert!(self_refresh.self_row_exists);
        assert_eq!(self_refresh.updates, 1);
        let absent = accumulate_existing_lineage_refresh(&model, &indexes, "absent")?;
        assert_eq!(absent.updates, 0);
        assert!(lineage_refresh_trees(&absent)?.is_empty());
        Ok(())
    }

    /// An ordinary request without a capability lineage row stays bounded by
    /// its own envelope; the funded native quote still refuses that case.
    #[test]
    fn absent_capability_lineage_is_bounded_by_the_receipt() -> Result<(), ReceiptStoreError> {
        let model = canonical_model()?;
        let keys = ordinary_attribution_key_lengths(&model, "no-such-capability")?;
        assert_eq!((keys.subject, keys.issuer), (0, 0));
        let bounds = RecordBounds::new(1024, keys);
        let cell = bounds.cell_bytes([Cap::SubjectKey, Cap::IssuerKey], false)?;
        assert_eq!(
            cell,
            add(
                add(CELL_FIXED_BYTES, add(COLUMN_HEADER_BYTES, 1024)?)?,
                add(COLUMN_HEADER_BYTES, 1024)?
            )?
        );
        Ok(())
    }

    /// A lineage row one request of a batch creates and a later request
    /// refreshes is priced as a same-size record rewrite on the table and on
    /// every schema-verified index, bounded by the creating receipt.
    #[test]
    fn created_lineage_edges_price_rewrites_on_every_verified_index(
    ) -> Result<(), ReceiptStoreError> {
        let model = canonical_model()?;
        let indexes = lineage_index_shapes(&model)?;
        let bounds = RecordBounds::new(
            2048,
            AttributionKeyLengths {
                subject: 0,
                issuer: 0,
            },
        );
        let trees = created_lineage_refresh_trees(&bounds, &indexes, 1)?;
        assert_eq!(trees.len(), indexes.len() + 1);
        let cell = bounds.cell_bytes(LINEAGE_WRITE.columns.iter().map(|(_, cap)| *cap), true)?;
        assert_eq!(
            trees[0],
            SqliteTreeWriteShapeData::record(Some(cell), cell, 1)
                .map_err(ReceiptStoreError::Unsupported)?
        );
        Ok(())
    }

    /// The complete ordinary batch quote prices a coalesced batch (fresh
    /// insert, idempotent duplicate, existing-parent lineage refresh) on a
    /// real WAL sink file and covers its actual committed WAL growth at a
    /// bounded price, never the whole-file ceiling.
    #[test]
    fn an_ordinary_batch_quote_covers_actual_wal_growth() -> Result<(), Box<dyn std::error::Error>>
    {
        let model = canonical_model()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("ordinary-batch-sink.sqlite3");
        model.execute(
            "VACUUM INTO ?1",
            [path.to_str().ok_or("sink path is not UTF-8")?],
        )?;
        let mut sink = rusqlite::Connection::open(&path)?;
        sink.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA cache_spill = OFF;",
        )?;
        seeded_lineage_row(&sink, "child-1", Some("parent-1"))?;
        seeded_lineage_row(&sink, "child-2", Some("parent-1"))?;
        let request = |id: &'static str| OrdinaryReceiptAppendRequestData {
            receipt_bytes: 2048,
            receipt_id: id,
            capability_id: "cap-ordinary-batch",
            ensure_lineage: false,
            creates_governed_lineage_row: false,
            governed_parent_receipt_id: None,
        };
        let mut parent = request("parent-1");
        parent.ensure_lineage = true;
        let quote = quote_ordinary_receipt_batch(
            &sink,
            &[request("fresh-1"), request("fresh-1"), parent],
            true,
        )?;
        assert!(quote.wal_bytes() > 0);
        // Bounded: orders of magnitude under the whole-file ceiling fallback
        // (the operator default cap prices near 17 TB).
        assert!(
            quote.wal_bytes() < 256 * 1024 * 1024,
            "ordinary batch quote is unbounded: {}",
            quote.wal_bytes()
        );
        assert!(quote.disk_bytes() >= quote.wal_bytes());
        let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
        let wal_len = || std::fs::metadata(&wal).map(|data| data.len()).unwrap_or(0);
        let before = wal_len();
        let tx = sink.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO chio_tool_receipts \
             (receipt_id, timestamp, capability_id, tool_server, tool_name, decision_kind, \
              policy_hash, content_hash, raw_json) \
             VALUES (?1, 1, 'cap-ordinary-batch', 'shell', 'bash', 'allow', 'p', 'c', ?2)",
            rusqlite::params!["fresh-1", "{\"id\":\"fresh-1\"}"],
        )?;
        tx.execute(
            "UPDATE receipt_lineage_statements SET replay_protected = 1 \
             WHERE parent_receipt_id = 'parent-1'",
            [],
        )?;
        tx.commit()?;
        let after = wal_len();
        assert!(
            after > before,
            "ordinary batch must grow the WAL: {before} -> {after}"
        );
        assert!(
            after - before <= quote.wal_bytes(),
            "actual WAL growth {} exceeds the quote {}",
            after - before,
            quote.wal_bytes()
        );
        Ok(())
    }
}
