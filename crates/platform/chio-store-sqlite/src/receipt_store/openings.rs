//! Receipt openings: per-receipt salts and tombstones, the erasure log and facts, erasure
//! conflicts, per-origin watermarks and the store's own erasure origin identity.

use chio_core::receipt::commitment::{Salt, SALT_LEN};
use chio_core::rng::Rng;
use chio_core::root_authority::SaltRef;
use chio_kernel::receipt_store::{
    OpenedSalts, OpeningReadScope, OpeningState, OpeningStatus, ReceiptStoreError,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::collections::BTreeMap;

/// Fresh-only v1 layout. Catalog validation compares a store against this exact text.
pub(crate) const RECEIPT_OPENINGS_SCHEMA: &str = r#"
CREATE TABLE receipt_openings (
  receipt_id TEXT NOT NULL CHECK (typeof(receipt_id) = 'text' AND instr(receipt_id, char(0)) = 0 AND length(CAST(receipt_id AS BLOB)) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  salt_ref TEXT NOT NULL CHECK (typeof(salt_ref) = 'text' AND instr(salt_ref, char(0)) = 0 AND length(CAST(salt_ref AS BLOB)) BETWEEN 1 AND 64 AND salt_ref GLOB '[a-z]*' AND salt_ref NOT GLOB '*[^a-z0-9_.]*' AND salt_ref NOT GLOB '*..*' AND salt_ref NOT GLOB '*.'),
  state TEXT NOT NULL CHECK (typeof(state) = 'text' AND instr(state, char(0)) = 0 AND state IN ('present', 'erased')),
  salt BLOB,
  state_at INTEGER NOT NULL CHECK (typeof(state_at) = 'integer' AND state_at >= 0),
  CHECK ((state = 'present' AND typeof(salt) = 'blob' AND length(salt) = 32) OR (state = 'erased' AND salt IS NULL)),
  PRIMARY KEY (receipt_id, salt_ref)
) WITHOUT ROWID;
CREATE TABLE receipt_metadata_values (
  receipt_id TEXT NOT NULL CHECK (typeof(receipt_id) = 'text' AND instr(receipt_id, char(0)) = 0 AND length(CAST(receipt_id AS BLOB)) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  salt_ref TEXT NOT NULL CHECK (typeof(salt_ref) = 'text' AND instr(salt_ref, char(0)) = 0 AND length(CAST(salt_ref AS BLOB)) BETWEEN 10 AND 64 AND salt_ref GLOB 'metadata.[a-z]*' AND salt_ref NOT GLOB '*[^a-z0-9_.]*' AND salt_ref NOT GLOB '*..*' AND salt_ref NOT GLOB '*.'),
  state TEXT NOT NULL CHECK (typeof(state) = 'text' AND instr(state, char(0)) = 0 AND state IN ('present', 'erased')),
  value TEXT,
  state_at INTEGER NOT NULL CHECK (typeof(state_at) = 'integer' AND state_at >= 0),
  CHECK ((state = 'present' AND typeof(value) = 'text' AND json_valid(value)) OR (state = 'erased' AND value IS NULL)),
  PRIMARY KEY (receipt_id, salt_ref)
) WITHOUT ROWID;
CREATE TABLE receipt_store_identity (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  store_id TEXT NOT NULL CHECK (typeof(store_id) = 'text' AND instr(store_id, char(0)) = 0 AND length(CAST(store_id AS BLOB)) = 32 AND store_id NOT GLOB '*[^0-9a-f]*')
);
CREATE TRIGGER receipt_store_identity_no_replace BEFORE INSERT ON receipt_store_identity WHEN EXISTS (SELECT 1 FROM receipt_store_identity) BEGIN SELECT RAISE(ABORT, 'receipt store id is immutable'); END;
CREATE TRIGGER receipt_store_identity_no_update BEFORE UPDATE ON receipt_store_identity BEGIN SELECT RAISE(ABORT, 'receipt store id is immutable'); END;
CREATE TRIGGER receipt_store_identity_no_delete BEFORE DELETE ON receipt_store_identity BEGIN SELECT RAISE(ABORT, 'receipt store id is immutable'); END;
CREATE TABLE receipt_opening_erasures (
  openings_seq INTEGER PRIMARY KEY AUTOINCREMENT,
  receipt_id TEXT NOT NULL CHECK (typeof(receipt_id) = 'text' AND instr(receipt_id, char(0)) = 0 AND length(CAST(receipt_id AS BLOB)) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  origin_store_id TEXT NOT NULL CHECK (typeof(origin_store_id) = 'text' AND instr(origin_store_id, char(0)) = 0 AND length(CAST(origin_store_id AS BLOB)) = 32 AND origin_store_id NOT GLOB '*[^0-9a-f]*'),
  origin_openings_seq INTEGER NOT NULL CHECK (typeof(origin_openings_seq) = 'integer' AND origin_openings_seq >= 1),
  erased_at INTEGER NOT NULL CHECK (typeof(erased_at) = 'integer' AND erased_at >= 0),
  UNIQUE (origin_store_id, origin_openings_seq)
);
CREATE INDEX receipt_opening_erasures_by_receipt ON receipt_opening_erasures (receipt_id);
CREATE TABLE receipt_erasure_facts (
  receipt_id TEXT NOT NULL CHECK (typeof(receipt_id) = 'text' AND instr(receipt_id, char(0)) = 0 AND length(CAST(receipt_id AS BLOB)) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
  origin_store_id TEXT NOT NULL CHECK (typeof(origin_store_id) = 'text' AND instr(origin_store_id, char(0)) = 0 AND length(CAST(origin_store_id AS BLOB)) = 32 AND origin_store_id NOT GLOB '*[^0-9a-f]*'),
  origin_openings_seq INTEGER NOT NULL CHECK (typeof(origin_openings_seq) = 'integer' AND origin_openings_seq >= 1),
  erased_at INTEGER NOT NULL CHECK (typeof(erased_at) = 'integer' AND erased_at >= 0),
  recorded_at INTEGER NOT NULL CHECK (typeof(recorded_at) = 'integer' AND recorded_at >= 0),
  conflicted INTEGER NOT NULL CHECK (typeof(conflicted) = 'integer' AND conflicted IN (0, 1)),
  PRIMARY KEY (receipt_id)
) WITHOUT ROWID;
CREATE TRIGGER receipt_erasure_facts_no_replace BEFORE INSERT ON receipt_erasure_facts WHEN EXISTS (SELECT 1 FROM receipt_erasure_facts WHERE receipt_id = NEW.receipt_id) BEGIN SELECT RAISE(ABORT, 'receipt erasure fact is permanent'); END;
CREATE TRIGGER receipt_erasure_facts_only_marks_conflict BEFORE UPDATE ON receipt_erasure_facts WHEN NEW.receipt_id IS NOT OLD.receipt_id OR NEW.origin_store_id IS NOT OLD.origin_store_id OR NEW.origin_openings_seq IS NOT OLD.origin_openings_seq OR NEW.erased_at IS NOT OLD.erased_at OR NEW.recorded_at IS NOT OLD.recorded_at OR NEW.conflicted < OLD.conflicted BEGIN SELECT RAISE(ABORT, 'receipt erasure fact is permanent'); END;
CREATE TRIGGER receipt_erasure_facts_no_delete BEFORE DELETE ON receipt_erasure_facts BEGIN SELECT RAISE(ABORT, 'receipt erasure fact is permanent'); END;
CREATE TABLE replication_quarantine_erasures (
  quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
  origin_store_id TEXT NOT NULL CHECK (typeof(origin_store_id) = 'text' AND instr(origin_store_id, char(0)) = 0 AND length(CAST(origin_store_id AS BLOB)) = 32 AND origin_store_id NOT GLOB '*[^0-9a-f]*'),
  origin_openings_seq INTEGER NOT NULL CHECK (typeof(origin_openings_seq) = 'integer' AND origin_openings_seq >= 1),
  reason TEXT NOT NULL CHECK (typeof(reason) = 'text' AND reason IN ('erasure_event_conflict', 'erasure_event_conflict_own_origin')),
  hold TEXT NOT NULL CHECK (typeof(hold) = 'text' AND hold IN ('below_watermark', 'origin_frozen', 'own_origin')),
  stored_receipt_id TEXT CHECK (stored_receipt_id IS NULL OR (typeof(stored_receipt_id) = 'text' AND instr(stored_receipt_id, char(0)) = 0 AND length(CAST(stored_receipt_id AS BLOB)) = 64 AND stored_receipt_id NOT GLOB '*[^0-9a-f]*')),
  stored_erased_at INTEGER CHECK (stored_erased_at IS NULL OR (typeof(stored_erased_at) = 'integer' AND stored_erased_at >= 0)),
  incoming_receipt_id TEXT NOT NULL CHECK (typeof(incoming_receipt_id) = 'text' AND instr(incoming_receipt_id, char(0)) = 0 AND length(CAST(incoming_receipt_id AS BLOB)) = 64 AND incoming_receipt_id NOT GLOB '*[^0-9a-f]*'),
  incoming_erased_at INTEGER NOT NULL CHECK (typeof(incoming_erased_at) = 'integer' AND incoming_erased_at >= 0),
  source_node_id TEXT NOT NULL CHECK (typeof(source_node_id) = 'text' AND instr(source_node_id, char(0)) = 0 AND length(CAST(source_node_id AS BLOB)) BETWEEN 1 AND 2048),
  recorded_at INTEGER NOT NULL CHECK (typeof(recorded_at) = 'integer' AND recorded_at >= 0),
  resolved_at INTEGER CHECK (resolved_at IS NULL OR (typeof(resolved_at) = 'integer' AND resolved_at >= recorded_at)),
  CHECK ((hold = 'own_origin') = (reason = 'erasure_event_conflict_own_origin')),
  CHECK ((stored_receipt_id IS NULL) = (stored_erased_at IS NULL)),
  UNIQUE (origin_store_id, origin_openings_seq, incoming_receipt_id, incoming_erased_at)
);
CREATE INDEX replication_quarantine_erasures_unresolved ON replication_quarantine_erasures (origin_store_id, hold) WHERE resolved_at IS NULL;
CREATE TRIGGER replication_quarantine_erasures_no_replace BEFORE INSERT ON replication_quarantine_erasures WHEN EXISTS (SELECT 1 FROM replication_quarantine_erasures WHERE quarantine_id = NEW.quarantine_id OR (origin_store_id = NEW.origin_store_id AND origin_openings_seq = NEW.origin_openings_seq AND incoming_receipt_id = NEW.incoming_receipt_id AND incoming_erased_at = NEW.incoming_erased_at)) BEGIN SELECT RAISE(ABORT, 'erasure conflict record is permanent'); END;
CREATE TRIGGER replication_quarantine_erasures_own_store_is_own_origin BEFORE INSERT ON replication_quarantine_erasures WHEN NEW.hold <> 'own_origin' AND EXISTS (SELECT 1 FROM receipt_store_identity WHERE store_id = NEW.origin_store_id) BEGIN SELECT RAISE(ABORT, 'a conflict naming this store has hold own_origin'); END;
CREATE TRIGGER replication_quarantine_erasures_monotone BEFORE UPDATE ON replication_quarantine_erasures WHEN OLD.resolved_at IS NOT NULL OR NEW.quarantine_id IS NOT OLD.quarantine_id OR NEW.origin_store_id IS NOT OLD.origin_store_id OR NEW.origin_openings_seq IS NOT OLD.origin_openings_seq OR NEW.reason IS NOT OLD.reason OR NEW.stored_receipt_id IS NOT OLD.stored_receipt_id OR NEW.stored_erased_at IS NOT OLD.stored_erased_at OR NEW.incoming_receipt_id IS NOT OLD.incoming_receipt_id OR NEW.incoming_erased_at IS NOT OLD.incoming_erased_at OR NEW.source_node_id IS NOT OLD.source_node_id OR NEW.recorded_at IS NOT OLD.recorded_at OR NOT ((OLD.hold = 'below_watermark' AND NEW.hold = 'origin_frozen' AND NEW.resolved_at IS NULL) OR (NEW.hold IS OLD.hold AND NEW.resolved_at IS NOT NULL)) BEGIN SELECT RAISE(ABORT, 'erasure conflict record is permanent'); END;
CREATE TRIGGER replication_quarantine_erasures_no_delete BEFORE DELETE ON replication_quarantine_erasures BEGIN SELECT RAISE(ABORT, 'erasure conflict record is permanent'); END;
CREATE TABLE receipt_openings_watermarks (
  origin_store_id TEXT NOT NULL CHECK (typeof(origin_store_id) = 'text' AND instr(origin_store_id, char(0)) = 0 AND length(CAST(origin_store_id AS BLOB)) = 32 AND origin_store_id NOT GLOB '*[^0-9a-f]*'),
  applied_through INTEGER NOT NULL CHECK (typeof(applied_through) = 'integer' AND applied_through >= 0),
  gc_horizon INTEGER NOT NULL CHECK (typeof(gc_horizon) = 'integer' AND gc_horizon >= 0),
  CHECK (gc_horizon <= applied_through),
  PRIMARY KEY (origin_store_id)
) WITHOUT ROWID;
CREATE TABLE receipt_openings_member_watermarks (
  member_node_id TEXT NOT NULL CHECK (typeof(member_node_id) = 'text' AND instr(member_node_id, char(0)) = 0 AND length(CAST(member_node_id AS BLOB)) BETWEEN 1 AND 2048),
  origin_store_id TEXT NOT NULL CHECK (typeof(origin_store_id) = 'text' AND instr(origin_store_id, char(0)) = 0 AND length(CAST(origin_store_id AS BLOB)) = 32 AND origin_store_id NOT GLOB '*[^0-9a-f]*'),
  applied_through INTEGER NOT NULL CHECK (typeof(applied_through) = 'integer' AND applied_through >= 0),
  PRIMARY KEY (member_node_id, origin_store_id)
) WITHOUT ROWID;
CREATE TABLE receipt_openings_peer_cursors (
  peer_node_id TEXT NOT NULL CHECK (typeof(peer_node_id) = 'text' AND instr(peer_node_id, char(0)) = 0 AND length(CAST(peer_node_id AS BLOB)) BETWEEN 1 AND 2048),
  after_openings_seq INTEGER NOT NULL CHECK (typeof(after_openings_seq) = 'integer' AND after_openings_seq >= 0),
  PRIMARY KEY (peer_node_id)
) WITHOUT ROWID;
"#;

const IDENTITY_TRIGGERS: [&str; 3] = [
    "receipt_store_identity_no_replace",
    "receipt_store_identity_no_update",
    "receipt_store_identity_no_delete",
];

/// A receipt store's erasure origin: 128 random bits as 32 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreId(String);

impl StoreId {
    fn decode(value: &str) -> Option<Self> {
        let well_formed = value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        well_formed.then(|| Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Mint the store id and its own watermark row in the creating transaction.
pub(crate) fn seed_receipt_store_identity(
    transaction: &Transaction<'_>,
    rng: &dyn Rng,
) -> Result<StoreId, ReceiptStoreError> {
    let mut bytes = [0_u8; 16];
    rng.fill_bytes(&mut bytes).map_err(|error| {
        ReceiptStoreError::Conflict(format!("receipt store identity draw failed: {error}"))
    })?;
    let store_id = StoreId(hex::encode(bytes));
    transaction.execute(
        "INSERT INTO receipt_store_identity (singleton, store_id) VALUES (1, ?1)",
        [store_id.as_str()],
    )?;
    transaction.execute(
        "INSERT INTO receipt_openings_watermarks (origin_store_id, applied_through, gc_horizon) \
         VALUES (?1, 0, 0)",
        [store_id.as_str()],
    )?;
    Ok(store_id)
}

/// Load and check the store id without mutating anything. A layout without the identity
/// table is left to catalog validation.
pub(crate) fn validate_receipt_store_identity(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    let has_table: bool = connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' \
         AND name = 'receipt_store_identity')",
        [],
        |row| row.get(0),
    )?;
    if has_table {
        load_receipt_store_identity(connection)?;
    }
    Ok(())
}

pub(crate) fn load_receipt_store_identity(
    connection: &Connection,
) -> Result<StoreId, ReceiptStoreError> {
    let mut rows = connection
        .prepare("SELECT store_id FROM receipt_store_identity")?
        .query_map([], |row| row.get::<_, rusqlite::types::Value>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let store_id = match (rows.pop(), rows.is_empty()) {
        (Some(rusqlite::types::Value::Text(value)), true) => {
            StoreId::decode(&value).ok_or(ReceiptStoreError::StoreIdMissing)?
        }
        _ => return Err(ReceiptStoreError::StoreIdMissing),
    };
    for trigger in IDENTITY_TRIGGERS {
        let present: bool = connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'trigger' \
             AND name = ?1 AND tbl_name = 'receipt_store_identity')",
            [trigger],
            |row| row.get(0),
        )?;
        if !present {
            return Err(ReceiptStoreError::StoreIdChanged);
        }
    }
    let own_watermark: bool = connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM receipt_openings_watermarks WHERE origin_store_id = ?1)",
        [store_id.as_str()],
        |row| row.get(0),
    )?;
    if !own_watermark {
        return Err(ReceiptStoreError::StoreIdChanged);
    }
    Ok(store_id)
}

fn erased_at(connection: &Connection, receipt_id: &str) -> Result<Option<u64>, ReceiptStoreError> {
    connection
        .query_row(
            "SELECT erased_at FROM receipt_erasure_facts WHERE receipt_id = ?1",
            [receipt_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|value| {
            u64::try_from(value).map_err(|_| {
                ReceiptStoreError::CorruptOpeningRow(format!("{receipt_id} erased_at"))
            })
        })
        .transpose()
}

struct OpeningRow {
    salt_ref: SaltRef,
    salt: Option<Salt>,
}

fn opening_rows(
    connection: &Connection,
    receipt_id: &str,
) -> Result<Vec<OpeningRow>, ReceiptStoreError> {
    let corrupt = || ReceiptStoreError::CorruptOpeningRow(receipt_id.to_owned());
    let mut statement = connection.prepare(
        "SELECT salt_ref, state, salt FROM receipt_openings WHERE receipt_id = ?1 \
         ORDER BY salt_ref",
    )?;
    let raw = statement
        .query_map([receipt_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    raw.into_iter()
        .map(|(salt_ref, state, salt)| {
            let salt_ref = SaltRef::new(salt_ref).map_err(|_| corrupt())?;
            let salt = match (state.as_str(), salt) {
                ("present", Some(bytes)) => {
                    let bytes: [u8; SALT_LEN] = bytes.try_into().map_err(|_| corrupt())?;
                    Some(Salt::from_bytes(bytes))
                }
                ("erased", None) => None,
                _ => return Err(corrupt()),
            };
            Ok(OpeningRow { salt_ref, salt })
        })
        .collect()
}

pub(crate) fn opening_status(
    connection: &Connection,
    receipt_id: &str,
) -> Result<OpeningStatus, ReceiptStoreError> {
    if let Some(erased_at) = erased_at(connection, receipt_id)? {
        return Ok(OpeningStatus::Erased { erased_at });
    }
    let rows = opening_rows(connection, receipt_id)?;
    if rows.is_empty() {
        return Ok(OpeningStatus::Unknown);
    }
    if rows.iter().any(|row| row.salt.is_none()) {
        return Err(ReceiptStoreError::CorruptOpeningRow(format!(
            "{receipt_id} has an erased opening without an erasure fact"
        )));
    }
    Ok(OpeningStatus::Present)
}

/// Salts for exactly the requested refs. A requested ref the store does not hold reads as
/// `Unknown`, never as a partial answer.
pub(crate) fn read_openings(
    connection: &Connection,
    receipt_id: &str,
    scope: &OpeningReadScope,
) -> Result<OpeningState, ReceiptStoreError> {
    if scope.tenant_binding.is_some() {
        return Err(ReceiptStoreError::Unsupported(
            "tenant-scoped opening reads require the committed receipt tenant binding".to_owned(),
        ));
    }
    match opening_status(connection, receipt_id)? {
        OpeningStatus::Erased { erased_at } => return Ok(OpeningState::Erased { erased_at }),
        OpeningStatus::Unknown => return Ok(OpeningState::Unknown),
        OpeningStatus::Present => {}
    }
    let mut held: BTreeMap<SaltRef, Salt> = opening_rows(connection, receipt_id)?
        .into_iter()
        .filter_map(|row| row.salt.map(|salt| (row.salt_ref, salt)))
        .collect();
    let mut salts = BTreeMap::new();
    for salt_ref in &scope.salt_refs {
        let Some(salt) = held.remove(salt_ref) else {
            return Ok(OpeningState::Unknown);
        };
        salts.insert(salt_ref.clone(), salt);
    }
    Ok(OpeningState::Present(OpenedSalts {
        receipt_id: receipt_id.to_owned(),
        salts,
    }))
}

/// Tombstone a published receipt's openings under this store's own origin, in one
/// transaction: the opening rows, the erasure log row, the erasure fact and the watermark.
pub(crate) fn erase_openings(
    transaction: &Transaction<'_>,
    receipt_id: &str,
    erased_at: u64,
    recorded_at: u64,
) -> Result<(), ReceiptStoreError> {
    let published: bool = transaction.query_row(
        "SELECT EXISTS (SELECT 1 FROM chio_tool_receipts WHERE receipt_id = ?1)",
        [receipt_id],
        |row| row.get(0),
    )?;
    if !published {
        return Err(ReceiptStoreError::ReceiptNotPublished(
            receipt_id.to_owned(),
        ));
    }
    if self::erased_at(transaction, receipt_id)?.is_some() {
        return Ok(());
    }
    let to_sql = |value: u64| {
        i64::try_from(value).map_err(|_| {
            ReceiptStoreError::Conflict(format!("erasure time {value} exceeds the store range"))
        })
    };
    let (erased_at, recorded_at) = (to_sql(erased_at)?, to_sql(recorded_at)?);
    let store_id = load_receipt_store_identity(transaction)?;
    let origin_openings_seq: i64 = transaction.query_row(
        "SELECT applied_through + 1 FROM receipt_openings_watermarks WHERE origin_store_id = ?1",
        [store_id.as_str()],
        |row| row.get(0),
    )?;
    transaction.execute(
        "UPDATE receipt_openings SET state = 'erased', salt = NULL, state_at = ?2 \
         WHERE receipt_id = ?1 AND state = 'present'",
        params![receipt_id, erased_at],
    )?;
    transaction.execute(
        "UPDATE receipt_metadata_values SET state = 'erased', value = NULL, state_at = ?2 \
         WHERE receipt_id = ?1 AND state = 'present'",
        params![receipt_id, erased_at],
    )?;
    transaction.execute(
        "INSERT INTO receipt_opening_erasures \
         (receipt_id, origin_store_id, origin_openings_seq, erased_at) VALUES (?1, ?2, ?3, ?4)",
        params![
            receipt_id,
            store_id.as_str(),
            origin_openings_seq,
            erased_at
        ],
    )?;
    transaction.execute(
        "INSERT INTO receipt_erasure_facts \
         (receipt_id, origin_store_id, origin_openings_seq, erased_at, recorded_at, conflicted) \
         VALUES (?1, ?2, ?3, ?4, ?5, 0)",
        params![
            receipt_id,
            store_id.as_str(),
            origin_openings_seq,
            erased_at,
            recorded_at
        ],
    )?;
    transaction.execute(
        "UPDATE receipt_openings_watermarks SET applied_through = ?2 WHERE origin_store_id = ?1",
        params![store_id.as_str(), origin_openings_seq],
    )?;
    Ok(())
}
