//! Closed complete row and index maxima. These descriptors are cost DATA.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessReturnTransactionData {
    Enrollment,
    OriginalNonceCustody,
    UnavailableNotice,
    FinalNativeCustody,
    Reconciliation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessReturnTableData {
    Accounts,
    Notices,
    NonceReceipts,
    FinalFates,
    Reconciliations,
    Events,
    Meta,
    Calls,
    Nonces,
    RecoveryReservations,
    Processes,
    Runtime,
}
impl ProcessReturnTableData {
    pub fn table_name(self) -> &'static str {
        match self {
            Self::Accounts => "process_native_return_accounts",
            Self::Notices => "process_native_return_notices",
            Self::NonceReceipts => "process_native_return_nonce_receipts",
            Self::FinalFates => "process_native_return_fates",
            Self::Reconciliations => "process_native_return_reconciliations",
            Self::Events => "process_native_return_events",
            Self::Meta => "process_native_return_meta",
            Self::Calls => "process_calls",
            Self::Nonces => "process_call_nonces",
            Self::RecoveryReservations => "process_recovery_calls",
            Self::Processes => "processes",
            Self::Runtime => "process_runtime",
        }
    }
}

pub struct ProcessReturnRowEnvelopeData {
    table: ProcessReturnTableData,
    before_record_bytes: Option<u64>,
    maximum_after_record_bytes: u64,
    mutations: u64,
    mutable_indexes: Vec<u64>,
}
impl ProcessReturnRowEnvelopeData {
    pub fn table(&self) -> ProcessReturnTableData {
        self.table
    }
    pub fn before_record_bytes(&self) -> Option<u64> {
        self.before_record_bytes
    }
    pub fn maximum_after_record_bytes(&self) -> u64 {
        self.maximum_after_record_bytes
    }
    pub fn mutations(&self) -> u64 {
        self.mutations
    }
    pub fn mutable_index_record_bytes(&self) -> &[u64] {
        &self.mutable_indexes
    }
}

/// Every purpose owns one full transaction. The shared calculator prices each
/// separately and their checked sum retains every FULL-commit tail.
pub(super) fn describe_finishing_transaction(
    purpose: ProcessReturnTransactionData,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    let mut rows = Vec::new();
    let (table, payload) = match purpose {
        ProcessReturnTransactionData::Enrollment => {
            (ProcessReturnTableData::Accounts, MAX_ACCOUNT_BYTES)
        }
        ProcessReturnTransactionData::OriginalNonceCustody => {
            (ProcessReturnTableData::NonceReceipts, MAX_ACCOUNT_BYTES)
        }
        ProcessReturnTransactionData::UnavailableNotice => {
            (ProcessReturnTableData::Notices, MAX_RECEIPT_BYTES)
        }
        ProcessReturnTransactionData::FinalNativeCustody => {
            (ProcessReturnTableData::FinalFates, MAX_RECEIPT_BYTES)
        }
        ProcessReturnTransactionData::Reconciliation => {
            (ProcessReturnTableData::Reconciliations, MAX_RECEIPT_BYTES)
        }
    };
    let mut indexes = vec![record_bytes(&[64, 8])?];
    let columns = if table == ProcessReturnTableData::Accounts {
        // The actual account has immutable PK, call-attempt unique key and
        // original native-operation unique key. All three are new inserts.
        indexes.push(record_bytes(&[256, 256, 8, 8])?);
        indexes.push(record_bytes(&[64, 8])?);
        vec![
            64,
            256,
            256,
            8,
            64,
            u64::try_from(payload).map_err(|_| ProcessError::Conflict)?,
        ]
    } else {
        vec![
            64,
            u64::try_from(payload).map_err(|_| ProcessError::Conflict)?,
        ]
    };
    rows.push(ProcessReturnRowEnvelopeData {
        table,
        before_record_bytes: None,
        maximum_after_record_bytes: record_bytes(&columns)?,
        mutations: 1,
        mutable_indexes: indexes,
    });
    if purpose == ProcessReturnTransactionData::OriginalNonceCustody {
        rows.extend(describe_original_nonce_transaction()?);
    }
    rows.push(ProcessReturnRowEnvelopeData {
        table: ProcessReturnTableData::Events,
        before_record_bytes: None,
        maximum_after_record_bytes: record_bytes(&[8, 64, 24, 64, 64, 64, MAX_EVENT_BYTES as u64])?,
        mutations: 1,
        mutable_indexes: vec![record_bytes(&[64, 24, 8])?],
    });
    let meta = record_bytes(&[8, 8, 8, 64])?;
    rows.push(ProcessReturnRowEnvelopeData {
        table: ProcessReturnTableData::Meta,
        before_record_bytes: Some(meta),
        maximum_after_record_bytes: meta,
        mutations: 1,
        mutable_indexes: Vec::new(),
    });
    Ok(rows)
}

/// Before a native nonce issuance the complete original Process nonce writer
/// remains a separate owed transaction. The actual source determines whether
/// that original slot is pending; decoded invocation DATA cannot choose it.
pub(super) fn describe_original_nonce_transaction(
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    Ok(vec![ProcessReturnRowEnvelopeData {
        table: ProcessReturnTableData::Nonces,
        before_record_bytes: None,
        maximum_after_record_bytes: record_bytes(&[256, 256, 8, 16_384])?,
        mutations: 1,
        mutable_indexes: vec![record_bytes(&[256, 256, 8, 8])?],
    }])
}

/// Sum the entire observed `processes` record before changing tree_calls.
/// Every retained variable column participates even when SQL updates one int.
/// This is a private source-bound descriptor, not caller-supplied size credit.
pub(super) fn describe_root_debit(
    tx: &Connection,
    root: &str,
) -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    let lengths: Vec<i64> = tx.query_row(
        "SELECT length(CAST(id AS BLOB)),CASE WHEN parent_id IS NULL THEN 0 ELSE length(CAST(parent_id AS BLOB)) END,length(CAST(root_id AS BLOB)),8,length(CAST(capability AS BLOB)),length(CAST(limits AS BLOB)),length(CAST(state AS BLOB)),8,length(CAST(checkpoint AS BLOB)),8 FROM main.processes WHERE id=?1 AND root_id=id",
        [root], |row| (0..10).map(|column| row.get::<_, i64>(column)).collect(),
    )?;
    let lengths = checked_lengths(lengths)?;
    let bytes = record_bytes(&lengths)?;
    Ok(ProcessReturnRowEnvelopeData {
        table: ProcessReturnTableData::Processes,
        before_record_bytes: Some(bytes),
        maximum_after_record_bytes: bytes,
        mutations: 1,
        // Preserve the complete PK/parent/root index envelope too. No pricing
        // credit depends on the engine leaving an unchanged key in place.
        mutable_indexes: vec![record_bytes(&[256, 8])?; 3],
    })
}

pub(super) fn describe_call_admission(
    tx: &Connection,
    root: &str,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    Ok(vec![describe_root_debit(tx, root)?, new_call_row()?])
}

pub(super) fn describe_recovery_reservation(
    tx: &Connection,
    root: &str,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    let mut rows = vec![
        describe_root_debit(tx, root)?,
        ProcessReturnRowEnvelopeData {
            table: ProcessReturnTableData::RecoveryReservations,
            before_record_bytes: None,
            maximum_after_record_bytes: record_bytes(&[256, 256, 256, 4096, 64])?,
            mutations: 1,
            mutable_indexes: vec![record_bytes(&[256, 256, 8])?; 2],
        },
    ];
    let version: i64 = tx.query_row(
        "SELECT version FROM main.process_runtime WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if version == 1 {
        rows.push(runtime_header_transition(tx)?);
    }
    Ok(rows)
}

pub(super) fn describe_recovery_finalization(
    tx: &Connection,
    process: &str,
    operation: &str,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    let lengths: Vec<i64> = tx.query_row(
        "SELECT length(CAST(process_id AS BLOB)),length(CAST(operation_key AS BLOB)),length(CAST(continuation_id AS BLOB)),length(reservation),CASE WHEN final_binding IS NULL THEN 0 ELSE length(CAST(final_binding AS BLOB)) END FROM main.process_recovery_calls WHERE process_id=?1 AND operation_key=?2",
        params![process,operation], |row| (0..5).map(|column| row.get::<_,i64>(column)).collect(),
    )?;
    let lengths = checked_lengths(lengths)?;
    let before = record_bytes(&lengths)?;
    let mut maximum = lengths;
    let binding = maximum.get_mut(4).ok_or(ProcessError::Conflict)?;
    *binding = 64;
    Ok(vec![
        new_call_row()?,
        ProcessReturnRowEnvelopeData {
            table: ProcessReturnTableData::RecoveryReservations,
            before_record_bytes: Some(before),
            maximum_after_record_bytes: record_bytes(&maximum)?,
            mutations: 1,
            mutable_indexes: vec![record_bytes(&[256, 256, 8])?; 2],
        },
    ])
}

fn new_call_row() -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    Ok(ProcessReturnRowEnvelopeData {
        table: ProcessReturnTableData::Calls,
        before_record_bytes: None,
        maximum_after_record_bytes: record_bytes(&[256, 256, 64, 8])?,
        mutations: 1,
        mutable_indexes: vec![record_bytes(&[256, 256, 8])?],
    })
}

pub(super) fn describe_attempt_advance(
    tx: &Connection,
    process: &str,
    operation: &str,
    expected_binding: &str,
    expected_attempt: u32,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    let (process_bytes, operation_bytes, binding_bytes, binding, attempt):
        (i64,i64,i64,String,u32) = tx.query_row(
        "SELECT length(CAST(process_id AS BLOB)),length(CAST(operation_key AS BLOB)),length(CAST(request_hash AS BLOB)),request_hash,attempts FROM main.process_calls WHERE process_id=?1 AND operation_key=?2",
        params![process,operation], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    )?;
    if binding != expected_binding
        || attempt != expected_attempt
        || !(1..crate::MAX_DISPATCH_ATTEMPTS).contains(&attempt)
        || process_bytes > 256
        || operation_bytes > 256
        || binding_bytes != 64
    {
        return Err(ProcessError::Conflict);
    }
    let process_bytes = u64::try_from(process_bytes).map_err(|_| ProcessError::Conflict)?;
    let operation_bytes = u64::try_from(operation_bytes).map_err(|_| ProcessError::Conflict)?;
    let binding_bytes = u64::try_from(binding_bytes).map_err(|_| ProcessError::Conflict)?;
    let full = record_bytes(&[process_bytes, operation_bytes, binding_bytes, 8])?;
    Ok(vec![ProcessReturnRowEnvelopeData {
        table: ProcessReturnTableData::Calls,
        before_record_bytes: Some(full),
        maximum_after_record_bytes: full,
        mutations: 1,
        mutable_indexes: vec![record_bytes(&[process_bytes, operation_bytes, 8])?],
    }])
}

fn runtime_header_transition(
    tx: &Connection,
) -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    let lengths: Vec<i64> = tx.query_row(
        "SELECT 8,8,length(CAST(namespace AS BLOB)),length(CAST(authority AS BLOB)),length(CAST(kernel_key AS BLOB)) FROM main.process_runtime WHERE singleton=1",
        [], |row| (0..5).map(|column| row.get::<_,i64>(column)).collect(),
    )?;
    let lengths = checked_lengths(lengths)?;
    let bytes = record_bytes(&lengths)?;
    Ok(ProcessReturnRowEnvelopeData {
        table: ProcessReturnTableData::Runtime,
        before_record_bytes: Some(bytes),
        maximum_after_record_bytes: bytes,
        mutations: 1,
        mutable_indexes: Vec::new(),
    })
}

// Conservatively bound each serial type and the header-size varint by nine
// bytes. This includes the complete SQLite record header, not only JSON bytes.
fn checked_lengths(values: Vec<i64>) -> Result<Vec<u64>, ProcessError> {
    values
        .into_iter()
        .map(|value| u64::try_from(value).map_err(|_| ProcessError::Conflict))
        .collect()
}

fn record_bytes(columns: &[u64]) -> Result<u64, ProcessError> {
    let count = u64::try_from(columns.len()).map_err(|_| ProcessError::Conflict)?;
    let header = count
        .checked_add(1)
        .and_then(|value| value.checked_mul(9))
        .ok_or(ProcessError::Conflict)?;
    columns.iter().try_fold(header, |total, bytes| {
        total.checked_add(*bytes).ok_or(ProcessError::Conflict)
    })
}
