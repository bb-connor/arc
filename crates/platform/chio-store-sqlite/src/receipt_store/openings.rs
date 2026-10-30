//! Receipt openings: per-receipt salts and tombstones, the erasure log and facts, erasure
//! conflicts, per-origin watermarks and the store's own erasure origin identity.

use chio_core::receipt::commitment::{Salt, SALT_LEN};
use chio_core::receipt::disclosure::MAX_DISCLOSURE_OPENINGS;
use chio_core::rng::Rng;
use chio_core::root_authority::SaltRef;
use chio_kernel::receipt_store::{
    OpenedSalts, OpeningReadScope, OpeningState, OpeningStatus, ReceiptStoreError,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Fresh-only v1 layout. Catalog validation compares a store against this exact text.
pub(crate) const RECEIPT_OPENINGS_SCHEMA: &str = include_str!("openings.sql");

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
        ReceiptStoreError::Io(std::io::Error::other(format!(
            "receipt store identity draw failed: {error}"
        )))
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

/// At most `MAX_DISCLOSURE_OPENINGS` rows; one more is read so an overflow is refused.
fn opening_rows(
    connection: &Connection,
    receipt_id: &str,
) -> Result<Vec<OpeningRow>, ReceiptStoreError> {
    let corrupt = || ReceiptStoreError::CorruptOpeningRow(receipt_id.to_owned());
    let mut statement = connection.prepare(
        "SELECT salt_ref, state, salt FROM receipt_openings WHERE receipt_id = ?1 \
         ORDER BY salt_ref LIMIT ?2",
    )?;
    let row_limit = i64::try_from(MAX_DISCLOSURE_OPENINGS + 1).map_err(|_| {
        ReceiptStoreError::Conflict("opening row limit exceeds the SQLite integer range".to_owned())
    })?;
    let raw = statement
        .query_map(params![receipt_id, row_limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?.map(Zeroizing::new),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if raw.len() > MAX_DISCLOSURE_OPENINGS {
        return Err(ReceiptStoreError::CorruptOpeningRow(format!(
            "{receipt_id} holds more than {MAX_DISCLOSURE_OPENINGS} openings"
        )));
    }
    raw.into_iter()
        .map(|(salt_ref, state, salt)| {
            let salt_ref = SaltRef::new(salt_ref).map_err(|_| corrupt())?;
            let salt = match (state.as_str(), salt) {
                ("present", Some(bytes)) => {
                    let bytes: [u8; SALT_LEN] =
                        bytes.as_slice().try_into().map_err(|_| corrupt())?;
                    Some(Salt::from_bytes(bytes))
                }
                ("erased", None) => None,
                _ => return Err(corrupt()),
            };
            Ok(OpeningRow { salt_ref, salt })
        })
        .collect()
}

/// The erasure fact and the opening rows, read in one deferred transaction so an erase that
/// commits between the two statements cannot be seen half applied.
fn load_openings(
    connection: &Connection,
    receipt_id: &str,
) -> Result<(OpeningStatus, Vec<OpeningRow>), ReceiptStoreError> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Deferred)?;
    if let Some(erased_at) = erased_at(&transaction, receipt_id)? {
        return Ok((OpeningStatus::Erased { erased_at }, Vec::new()));
    }
    let rows = opening_rows(&transaction, receipt_id)?;
    transaction.finish()?;
    if rows.is_empty() {
        return Ok((OpeningStatus::Unknown, rows));
    }
    if rows.iter().any(|row| row.salt.is_none()) {
        return Err(ReceiptStoreError::CorruptOpeningRow(format!(
            "{receipt_id} has an erased opening without an erasure fact"
        )));
    }
    Ok((OpeningStatus::Present, rows))
}

pub(crate) fn opening_status(
    connection: &Connection,
    receipt_id: &str,
) -> Result<OpeningStatus, ReceiptStoreError> {
    load_openings(connection, receipt_id).map(|(status, _)| status)
}

/// Salts for exactly the requested refs. A requested ref the store does not hold reads as
/// `Unknown`, never as a partial answer. A scope names between one and
/// `MAX_DISCLOSURE_OPENINGS` refs.
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
    if scope.salt_refs.is_empty() || scope.salt_refs.len() > MAX_DISCLOSURE_OPENINGS {
        return Err(ReceiptStoreError::ReadBoundary(format!(
            "an opening read names between 1 and {MAX_DISCLOSURE_OPENINGS} salt_refs, not {}",
            scope.salt_refs.len()
        )));
    }
    let rows = match load_openings(connection, receipt_id)? {
        (OpeningStatus::Erased { erased_at }, _) => return Ok(OpeningState::Erased { erased_at }),
        (OpeningStatus::Unknown, _) => return Ok(OpeningState::Unknown),
        (OpeningStatus::Present, rows) => rows,
    };
    let mut held: BTreeMap<SaltRef, Salt> = rows
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
