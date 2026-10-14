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
    Blobs,
    FeatureLevel,
    Schema,
    ArtifactObjects,
    ConfinedReturnSlots,
    ConfinedDeliveryMarkers,
    UnusedRecoveryClosures,
    DelegationKeys,
    ChildWork,
    WorkerWaits,
    SettledWaits,
    WorkerCredentials,
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
            Self::Blobs => "process_state_blobs",
            Self::FeatureLevel => "process_feature_level",
            Self::Schema => "sqlite_schema",
            Self::ArtifactObjects => "process_artifact_objects",
            Self::ConfinedReturnSlots => "process_confined_return_slots",
            Self::ConfinedDeliveryMarkers => "process_confined_delivery_markers",
            Self::UnusedRecoveryClosures => "process_unused_recovery_reservations",
            Self::DelegationKeys => "process_delegation_keys",
            Self::ChildWork => "process_child_work",
            Self::WorkerWaits => "process_worker_waits",
            Self::SettledWaits => "process_settled_waits",
            Self::WorkerCredentials => "worker_credentials",
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
/// separately and their checked sum retains every FULL-commit tail. The
/// enrollment transaction also prices the journal's actual runtime version
/// transition and the fresh retained feature-level row its trigger inserts.
pub(super) fn describe_finishing_transaction(
    tx: &Connection,
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
    if purpose == ProcessReturnTransactionData::Enrollment {
        // The first funded enrollment commits the journal's runtime version
        // transition to eight; the retained-at-cohort trigger inserts exactly
        // one fresh feature-level row in that same transaction. The whole
        // runtime row and the new level row are priced, never only the int.
        rows.push(runtime_header_transition(tx)?);
        rows.push(fresh_feature_level_row()?);
    }
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

/// The first funded enrollment installs its own complete return-bank family.
/// Price that actual catalog delta and the initial frontier insert before
/// funding exists. This describes writes; it neither installs a bank nor
/// authenticates an absent bank as a zero-liability balance.
pub(super) fn describe_return_bank_activation(
    tx: &Connection,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    let source = catalog::actual_catalog(tx)?;
    let target = catalog::expected_cohort_catalog()?;
    // Activation only adds the maintained family to the authenticated base.
    // It cannot repair, replace or delete any existing source catalog row.
    if source.iter().any(|row| !target.contains(row)) {
        return Err(ProcessError::Conflict);
    }
    let guard = catalog::compiled_guard_sql()?;
    if catalog::actual_guard_sql(tx)?.as_deref() != Some(guard.as_str()) {
        return Err(ProcessError::Conflict);
    }
    let mut rows = describe_layout_delta(
        &LayoutDelta {
            source: &source,
            target: &target,
            source_guard: Some(&guard),
            target_guard: &guard,
        },
        None,
        None,
    )?;
    rows.push(envelope(
        ProcessReturnTableData::Meta,
        None,
        &[8, 8, 8, 64],
        &[],
    )?);
    Ok(rows)
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

/// The complete observed `processes` record before a checkpoint transition:
/// the whole row is rewritten, so the entire variable checkpoint column is
/// priced even though SQL updates two ints. Every index envelope of the row
/// participates without unchanged-key credit.
pub(super) fn describe_checkpoint_transition(
    tx: &Connection,
    process: &str,
) -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    let lengths: Vec<i64> = tx.query_row(
        "SELECT length(CAST(id AS BLOB)),CASE WHEN parent_id IS NULL THEN 0 ELSE length(CAST(parent_id AS BLOB)) END,length(CAST(root_id AS BLOB)),8,length(CAST(capability AS BLOB)),length(CAST(limits AS BLOB)),length(CAST(state AS BLOB)),8,length(CAST(checkpoint AS BLOB)),8 FROM main.processes WHERE id=?1",
        [process], |row| (0..10).map(|column| row.get::<_, i64>(column)).collect(),
    )?;
    let lengths = checked_lengths(lengths)?;
    let mut maximum = lengths.clone();
    let checkpoint = maximum.get_mut(8).ok_or(ProcessError::Conflict)?;
    *checkpoint = 1_048_576;
    let bytes = record_bytes(&lengths)?;
    Ok(ProcessReturnRowEnvelopeData {
        table: ProcessReturnTableData::Processes,
        before_record_bytes: Some(bytes),
        maximum_after_record_bytes: record_bytes(&maximum)?,
        mutations: 1,
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

/// A fresh `processes` row at its complete column maxima, with the PK,
/// parent and root index envelopes. Conservative maxima never underprice a
/// new root or child; the actual write is still priced from these bounds.
pub(super) fn new_process_row() -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    Ok(ProcessReturnRowEnvelopeData {
        table: ProcessReturnTableData::Processes,
        before_record_bytes: None,
        maximum_after_record_bytes: record_bytes(&[
            256, 256, 256, 8, 262_144, 4_096, 16, 8, 1_048_576, 8,
        ])?,
        mutations: 1,
        mutable_indexes: vec![record_bytes(&[256, 8])?; 3],
    })
}

/// One whole existing `processes` row rewritten at conservative maxima with
/// every index envelope, used per row for bounded recursive state writes.
pub(super) fn existing_process_row() -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    let bytes = record_bytes(&[256, 256, 256, 8, 262_144, 4_096, 16, 8, 1_048_576, 8])?;
    Ok(ProcessReturnRowEnvelopeData {
        table: ProcessReturnTableData::Processes,
        before_record_bytes: Some(bytes),
        maximum_after_record_bytes: bytes,
        mutations: 1,
        mutable_indexes: vec![record_bytes(&[256, 8])?; 3],
    })
}

/// A fresh immutable state-blob row at its quota maxima with its composite
/// primary-key index envelope.
pub(super) fn new_state_blob_row() -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    Ok(ProcessReturnRowEnvelopeData {
        table: ProcessReturnTableData::Blobs,
        before_record_bytes: None,
        maximum_after_record_bytes: record_bytes(&[256, 64, 1_048_576, 64, 8])?,
        mutations: 1,
        mutable_indexes: vec![record_bytes(&[256, 64, 8])?],
    })
}

/// The fresh retained feature-level row: one singleton integer primary key
/// and one level, no secondary indexes, inserted once by the cohort trigger.
fn fresh_feature_level_row() -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    Ok(ProcessReturnRowEnvelopeData {
        table: ProcessReturnTableData::FeatureLevel,
        before_record_bytes: None,
        maximum_after_record_bytes: record_bytes(&[8, 8])?,
        mutations: 1,
        mutable_indexes: Vec::new(),
    })
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

/// One whole-row envelope: complete maximum columns of the record, and the
/// maximum record of every mutable index, with no credit for unchanged keys.
fn envelope(
    table: ProcessReturnTableData,
    before: Option<&[u64]>,
    after: &[u64],
    indexes: &[&[u64]],
) -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    Ok(ProcessReturnRowEnvelopeData {
        table,
        before_record_bytes: before.map(record_bytes).transpose()?,
        maximum_after_record_bytes: record_bytes(after)?,
        mutations: 1,
        mutable_indexes: indexes
            .iter()
            .map(|columns| record_bytes(columns))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// The runtime version row or the retained feature-level row that one feature
/// activation rewrites, priced whole.
pub(super) fn describe_feature_level_raise(
    tx: &Connection,
) -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    let version: i64 = tx.query_row(
        "SELECT version FROM main.process_runtime WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if version == 8 {
        envelope(
            ProcessReturnTableData::FeatureLevel,
            Some(&[8, 8]),
            &[8, 8],
            &[],
        )
    } else {
        runtime_header_transition(tx)
    }
}

pub(super) fn new_artifact_object_row() -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    envelope(
        ProcessReturnTableData::ArtifactObjects,
        None,
        &[256, 256, 36, 64, 8, 1_048_576],
        &[&[256, 256, 8], &[36, 8]],
    )
}

/// Retiring an object clears its data in place: the whole existing row is
/// priced at the actual retained data length.
pub(super) fn describe_artifact_object_retirement(
    tx: &Connection,
    process: &str,
    object: &str,
) -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    let lengths: Vec<i64> = tx.query_row(
        "SELECT length(CAST(process_id AS BLOB)),length(CAST(object_id AS BLOB)),COALESCE(length(data),0) FROM main.process_artifact_objects WHERE process_id=?1 AND object_id=?2",
        params![process, object],
        |row| (0..3).map(|column| row.get::<_, i64>(column)).collect(),
    )?;
    let lengths = checked_lengths(lengths)?;
    let [process_bytes, object_bytes, data_bytes] = lengths[..] else {
        return Err(ProcessError::Conflict);
    };
    let columns = [process_bytes, object_bytes, 36, 64, 8, data_bytes];
    envelope(
        ProcessReturnTableData::ArtifactObjects,
        Some(&columns),
        &columns,
        &[&[256, 256, 8], &[36, 8]],
    )
}

pub(super) fn new_confined_slot_row() -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    envelope(
        ProcessReturnTableData::ConfinedReturnSlots,
        None,
        &[256, 256, 256, 64, 36, 1, 1],
        &[&[256, 8], &[256, 8], &[36, 8]],
    )
}

/// Filling a slot completes the existing row with its digest and bytes.
pub(super) fn confined_slot_fill_row() -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    envelope(
        ProcessReturnTableData::ConfinedReturnSlots,
        Some(&[256, 256, 256, 64, 36, 1, 1]),
        &[256, 256, 256, 64, 36, 64, 5],
        &[&[256, 8], &[256, 8], &[36, 8]],
    )
}

pub(super) fn describe_confined_delivery_marker(
    tx: &Connection,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    Ok(vec![
        envelope(
            ProcessReturnTableData::ConfinedDeliveryMarkers,
            None,
            &[256, 256, 256, 256, 262_144],
            &[&[256, 8], &[256, 8], &[256, 8]],
        )?,
        describe_feature_level_raise(tx)?,
    ])
}

pub(super) fn describe_unused_recovery_closure(
    tx: &Connection,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    Ok(vec![
        envelope(
            ProcessReturnTableData::UnusedRecoveryClosures,
            None,
            &[256, 256, 256, 16_384],
            &[&[256, 256, 8], &[256, 256, 8]],
        )?,
        describe_feature_level_raise(tx)?,
    ])
}

/// A dynamic child: its process row, its delegation key and its work row.
pub(super) fn describe_child_submission() -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError>
{
    Ok(vec![
        new_process_row()?,
        envelope(
            ProcessReturnTableData::DelegationKeys,
            None,
            &[256, 64],
            &[&[256, 8]],
        )?,
        envelope(
            ProcessReturnTableData::ChildWork,
            None,
            &[8, 256, 64, 256, 256, 256, 131_072],
            &[&[256, 8], &[256, 8]],
        )?,
    ])
}

/// Replacing one wait record and toggling its settled marker.
pub(super) fn describe_worker_wait() -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    Ok(vec![
        envelope(
            ProcessReturnTableData::WorkerWaits,
            Some(&[256, 40_000]),
            &[256, 40_000],
            &[&[256, 8]],
        )?,
        envelope(
            ProcessReturnTableData::SettledWaits,
            Some(&[256]),
            &[256],
            &[&[256, 8]],
        )?,
    ])
}

pub(super) fn delegation_key_rows(
    count: usize,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    (0..count)
        .map(|_| {
            envelope(
                ProcessReturnTableData::DelegationKeys,
                None,
                &[256, 64],
                &[&[256, 8]],
            )
        })
        .collect()
}

#[cfg(feature = "worker-server")]
pub(super) fn new_worker_credential_row() -> Result<ProcessReturnRowEnvelopeData, ProcessError> {
    envelope(
        ProcessReturnTableData::WorkerCredentials,
        None,
        &[64, 256, 8],
        &[&[64, 8], &[256, 8]],
    )
}

/// One whole existing credential row per credential of the process.
#[cfg(feature = "worker-server")]
pub(super) fn describe_worker_credential_revocation(
    tx: &Connection,
    process: &str,
) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError> {
    let count: usize = usize::try_from(tx.query_row(
        "SELECT count(*) FROM main.worker_credentials WHERE process_id=?1",
        [process],
        |row| row.get::<_, i64>(0),
    )?)
    .map_err(|_| ProcessError::Conflict)?;
    (0..count.max(1))
        .map(|_| {
            envelope(
                ProcessReturnTableData::WorkerCredentials,
                Some(&[64, 256, 8]),
                &[64, 256, 8],
                &[&[64, 8], &[256, 8]],
            )
        })
        .collect()
}

/// The actual catalog delta from one supported source layout to the compiled
/// layout, as complete catalog rows of the held file.
pub(super) struct LayoutDelta<'a> {
    pub(super) source: &'a [catalog::CatalogRow],
    pub(super) target: &'a [catalog::CatalogRow],
    pub(super) source_guard: Option<&'a str>,
    pub(super) target_guard: &'a str,
}

/// The state-blob data that a historical source must carry into the
/// compiled table: the actual row count and the largest retained data.
pub(super) struct BlobRebuild {
    pub(super) rows: u64,
    pub(super) largest_data_bytes: u64,
}

/// The identity bytes of the runtime row a genesis writes.
pub(super) struct RuntimeInsert {
    pub(super) authority_bytes: u64,
    pub(super) key_bytes: u64,
}

fn text_bytes(value: &str) -> Result<u64, ProcessError> {
    u64::try_from(value.len()).map_err(|_| ProcessError::Conflict)
}

fn schema_columns(row: &catalog::CatalogRow) -> Priced<[u64; 5]> {
    Ok([
        text_bytes(&row.0)?,
        text_bytes(&row.1)?,
        text_bytes(&row.2)?,
        8,
        row.3.as_deref().map(text_bytes).transpose()?.unwrap_or(0),
    ])
}

type Priced<T> = Result<T, ProcessError>;

fn envelope_n(
    table: ProcessReturnTableData,
    before: Option<&[u64]>,
    after: &[u64],
    indexes: &[&[u64]],
    mutations: u64,
) -> Priced<ProcessReturnRowEnvelopeData> {
    let mut row = envelope(table, before, after, indexes)?;
    row.mutations = mutations;
    Ok(row)
}

/// Every row an installation of the compiled layout writes, derived from the
/// actual source catalog of the held file: a schema row and a fresh tree root
/// for each created object, the old and new image of each rewritten schema
/// row, the old image of each removed one, the version guard replacement, the
/// state-blob data migration and the runtime row of a genesis. Each row is
/// priced whole with no credit for unchanged keys.
pub(super) fn describe_layout_delta(
    delta: &LayoutDelta<'_>,
    blobs: Option<&BlobRebuild>,
    runtime: Option<&RuntimeInsert>,
) -> Priced<Vec<ProcessReturnRowEnvelopeData>> {
    let mut rows = Vec::new();
    for target in delta.target {
        let after = schema_columns(target)?;
        match delta.source.iter().find(|source| source.1 == target.1) {
            None => {
                rows.push(envelope(ProcessReturnTableData::Schema, None, &after, &[])?);
                if matches!(target.0.as_str(), "table" | "index") {
                    rows.push(envelope(ProcessReturnTableData::Schema, None, &[8], &[])?);
                }
            }
            Some(source) if source != target => rows.push(envelope(
                ProcessReturnTableData::Schema,
                Some(&schema_columns(source)?),
                &after,
                &[],
            )?),
            Some(_) => {}
        }
    }
    for source in delta.source {
        if !delta.target.iter().any(|target| target.1 == source.1) {
            let before = schema_columns(source)?;
            rows.push(envelope(
                ProcessReturnTableData::Schema,
                Some(&before),
                &before,
                &[],
            )?);
        }
    }
    if delta.source_guard != Some(delta.target_guard) {
        let after = [9, 64, 64, 8, text_bytes(delta.target_guard)?];
        let before = delta
            .source_guard
            .map(|sql| -> Priced<[u64; 5]> { Ok([9, 64, 64, 8, text_bytes(sql)?]) })
            .transpose()?;
        rows.push(envelope(
            ProcessReturnTableData::Schema,
            before.as_ref().map(|columns| columns.as_slice()),
            &after,
            &[],
        )?);
    }
    if let Some(blobs) = blobs {
        // The staging table is created and dropped, and every retained row is
        // copied out and back into the rebuilt compiled table.
        for _ in 0..2 {
            rows.push(envelope(
                ProcessReturnTableData::Schema,
                None,
                &[9, 64, 64, 8, 512],
                &[],
            )?);
            rows.push(envelope(ProcessReturnTableData::Schema, None, &[8], &[])?);
        }
        if blobs.rows > 0 {
            let old = [256, 64, blobs.largest_data_bytes];
            let new = [256, 64, blobs.largest_data_bytes, 64, 8];
            let index: &[u64] = &[256, 64, 8];
            rows.push(envelope_n(
                ProcessReturnTableData::Blobs,
                Some(&old),
                &old,
                &[index],
                blobs.rows,
            )?);
            rows.push(envelope_n(
                ProcessReturnTableData::Blobs,
                None,
                &old,
                &[],
                blobs.rows,
            )?);
            rows.push(envelope_n(
                ProcessReturnTableData::Blobs,
                None,
                &new,
                &[index],
                blobs.rows,
            )?);
            rows.push(envelope_n(
                ProcessReturnTableData::Blobs,
                Some(&old),
                &old,
                &[],
                blobs.rows,
            )?);
        }
    }
    if let Some(runtime) = runtime {
        // The header page of a file written for the first time, and its
        // single runtime row.
        rows.push(envelope(ProcessReturnTableData::Schema, None, &[8], &[])?);
        rows.push(envelope(
            ProcessReturnTableData::Runtime,
            None,
            &[8, 8, 36, runtime.authority_bytes, runtime.key_bytes],
            &[],
        )?);
    }
    if rows.is_empty() {
        return Err(ProcessError::Conflict);
    }
    Ok(rows)
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
