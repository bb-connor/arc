//! Native row hydration and exact authority-scoped source-fingerprint readback.

use super::*;
use crate::security_state::{
    decode_retained_security_row, encode_retained_security_values, retained_security_columns,
    TableHasher,
};
use rusqlite::{params_from_iter, types::Value};

fn columns(table: &schema::Table) -> Result<String, AdmissionOperationStoreError> {
    Ok(retained_security_columns(table.source)
        .map_err(invalid)?
        .iter()
        .map(|column| format!("\"{column}\""))
        .collect::<Vec<_>>()
        .join(","))
}

fn field<'a>(
    table: &schema::Table,
    values: &'a [Value],
    name: &str,
) -> Result<&'a Value, AdmissionOperationStoreError> {
    let columns = retained_security_columns(table.source).map_err(invalid)?;
    let index = columns
        .iter()
        .position(|column| *column == name)
        .ok_or_else(|| invalid("native hydration column absent"))?;
    values
        .get(index)
        .ok_or_else(|| invalid("native hydration value absent"))
}

fn replace(
    table: &schema::Table,
    values: &mut [Value],
    name: &str,
    value: Value,
) -> Result<(), AdmissionOperationStoreError> {
    let columns = retained_security_columns(table.source).map_err(invalid)?;
    let index = columns
        .iter()
        .position(|column| *column == name)
        .ok_or_else(|| invalid("native hydration column absent"))?;
    *values
        .get_mut(index)
        .ok_or_else(|| invalid("native hydration value absent"))? = value;
    Ok(())
}

fn visit_archive(
    tx: &Transaction<'_>,
    authority: &str,
    table: &schema::Table,
    mut visit: impl FnMut(Vec<Value>) -> Result<(), AdmissionOperationStoreError>,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(
            "SELECT canonical_row FROM security_participant_migration_rows
        WHERE security_authority_id = ?1 AND table_name = ?2 ORDER BY row_index",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![authority, table.source])
        .map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let bytes = row
            .get_ref(0)
            .map_err(sqlite_error)?
            .as_blob()
            .map_err(invalid)?;
        visit(decode_retained_security_row(table.source, bytes).map_err(invalid)?)?;
    }
    Ok(())
}

fn insert(
    tx: &Transaction<'_>,
    authority: &str,
    table: &schema::Table,
    mut values: Vec<Value>,
) -> Result<(), AdmissionOperationStoreError> {
    values.insert(0, Value::Text(authority.to_owned()));
    let parameters = (1..=values.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(",");
    tx.execute(
        &format!(
            "INSERT INTO {} (security_authority_id,{}) VALUES ({parameters})",
            table.native,
            columns(table)?
        ),
        params_from_iter(values),
    )
    .map_err(sqlite_error)?;
    cutpoint(1)
}

pub(super) fn hydrate(
    tx: &Transaction<'_>,
    source: &SecurityParticipantMigrationRecord,
) -> Result<(), AdmissionOperationStoreError> {
    hydrate_at_version(tx, source, 29)
}

pub(super) fn hydrate_at_version(
    tx: &Transaction<'_>,
    source: &SecurityParticipantMigrationRecord,
    version: i32,
) -> Result<(), AdmissionOperationStoreError> {
    if !schema::verify_version(tx, version)? {
        return Err(invalid("native schema is absent"));
    }
    let authority = source.snapshot().binding().security_authority_id().as_str();
    for table in schema::TABLES {
        let exists: bool = tx
            .query_row(
                &format!(
                    "SELECT EXISTS(SELECT 1 FROM {} WHERE security_authority_id = ?1)",
                    table.native
                ),
                [authority],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if exists {
            return Err(invalid("native destination state already exists"));
        }
    }
    for table in schema::TABLES {
        if matches!(
            table.source,
            "security_declassification_uses" | "security_declassification_receipt_outbox"
        ) {
            continue;
        }
        visit_archive(tx, authority, table, |values| {
            insert(tx, authority, table, values)
        })?;
    }
    let uses = schema::TABLES
        .iter()
        .find(|table| table.source == "security_declassification_uses")
        .ok_or_else(|| invalid("native use table absent"))?;
    let outbox = schema::TABLES
        .iter()
        .find(|table| table.source == "security_declassification_receipt_outbox")
        .ok_or_else(|| invalid("native outbox table absent"))?;
    // Only the new, unexposed projection is staged. The immutable archive and
    // committed source are never rewound, pruned or interpreted as fresh use.
    visit_archive(tx, authority, uses, |mut values| {
        replace(
            uses,
            &mut values,
            "state",
            Value::Text("consumed_pending_dispatch".into()),
        )?;
        replace(uses, &mut values, "outcome_binding", Value::Null)?;
        replace(uses, &mut values, "transition_id", Value::Null)?;
        insert(tx, authority, uses, values)
    })?;
    visit_archive(tx, authority, outbox, |values| {
        if field(outbox, &values, "phase")? == &Value::Text("consumption".into()) {
            insert(tx, authority, outbox, values)?;
        }
        Ok(())
    })?;
    visit_archive(tx, authority, uses, |values| {
        let state = field(uses, &values, "state")?;
        if state == &Value::Text("consumed_pending_dispatch".into()) {
            return Ok(());
        }
        let changed = tx.execute("UPDATE security_participant_state_declassification_uses
            SET state = ?4, outcome_binding = ?5, transition_id = ?6
            WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3
              AND state = 'consumed_pending_dispatch' AND outcome_binding IS NULL AND transition_id IS NULL",
            params![authority, field(uses, &values, "tenant_id")?, field(uses, &values, "grant_id")?, state,
                field(uses, &values, "outcome_binding")?, field(uses, &values, "transition_id")?],
        ).map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invalid("native terminal use restoration mismatch"));
        }
        cutpoint(1)
    })?;
    visit_archive(tx, authority, outbox, |values| {
        if field(outbox, &values, "phase")? == &Value::Text("outcome".into()) {
            insert(tx, authority, outbox, values)?;
        }
        Ok(())
    })?;
    verify_rows(tx, source)?;
    // Once during hydration, exercise the same scoped semantic readers that
    // the mutation engine uses. Later inactive readback verifies the exact
    // fingerprints; it need not repeatedly decode shared labels per context.
    crate::security_state::verify_native_flow_state(tx, authority).map_err(invalid)?;
    crate::security_state::verify_native_declassification_state(tx, authority).map_err(invalid)
}

pub(super) fn verify_rows(
    connection: &Connection,
    source: &SecurityParticipantMigrationRecord,
) -> Result<(), AdmissionOperationStoreError> {
    let authority = source.snapshot().binding().security_authority_id().as_str();
    #[cfg(feature = "admission-test-support")]
    let mut current_probe =
        super::image_visit_test_support::ImageVisitProbe::start(connection, "current")?;
    for table in schema::TABLES {
        let expected = source
            .snapshot()
            .tables()
            .iter()
            .find(|fingerprint| fingerprint.table == table.source)
            .ok_or_else(|| invalid("native source fingerprint absent"))?;
        let fields = retained_security_columns(table.source).map_err(invalid)?;
        let row_bytes = fields
            .iter()
            .map(|name| format!("COALESCE(length(CAST(\"{name}\" AS BLOB)), 0)"))
            .collect::<Vec<_>>()
            .join(" + ");
        let (count, bytes, largest): (i64, i64, i64) = connection.query_row(&format!(
            "SELECT COUNT(*), COALESCE(SUM({row_bytes}), 0), COALESCE(MAX({row_bytes}), 0) FROM {} WHERE security_authority_id = ?1", table.native),
            [authority], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).map_err(sqlite_error)?;
        if u64::try_from(count).map_err(invalid)? != expected.row_count
            || u64::try_from(bytes).map_err(invalid)? > expected.encoded_bytes
            || !(0..=2_097_152).contains(&largest)
        {
            return Err(invalid(
                "native inventory count or size differs from source",
            ));
        }
        let columns = columns(table)?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT {columns} FROM {} WHERE security_authority_id = ?1 ORDER BY {columns}",
                table.native
            ))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([authority]).map_err(sqlite_error)?;
        let mut hasher = TableHasher::new(table.source);
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            #[cfg(feature = "admission-test-support")]
            current_probe.advance(connection)?;
            let values = (0..fields.len())
                .map(|index| row.get_ref(index))
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(sqlite_error)?;
            hasher
                .push(&encode_retained_security_values(table.source, &values).map_err(invalid)?)
                .map_err(invalid)?;
        }
        if hasher.finish() != *expected {
            return Err(invalid("native row bytes differ from imported source"));
        }
    }
    Ok(())
}

/// Store-wide budget for authenticated current native rows.
const MAX_CURRENT_ROWS: u64 = 65_536;

#[cfg(test)]
thread_local! {
    static TEST_CURRENT_ROWS: std::cell::Cell<u64> = const { std::cell::Cell::new(MAX_CURRENT_ROWS) };
}

/// Lower, never raise, the current-row budget for one test thread.
#[cfg(test)]
pub(in crate::admission_operation_store) fn with_test_current_rows<T>(
    rows: u64,
    run: impl FnOnce() -> T,
) -> T {
    assert!((1..=MAX_CURRENT_ROWS).contains(&rows));
    struct Reset(u64);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_CURRENT_ROWS.set(self.0);
        }
    }
    let _reset = Reset(TEST_CURRENT_ROWS.replace(rows));
    run()
}

fn current_rows_budget() -> u64 {
    #[cfg(test)]
    return TEST_CURRENT_ROWS.get();
    #[cfg(not(test))]
    MAX_CURRENT_ROWS
}

/// Largest current-row delta one captured native event can introduce.
const EVENT_ROWS: u64 = 4_096;

/// Store-wide current native rows.
fn current_rows(connection: &Connection) -> Result<u64, AdmissionOperationStoreError> {
    let mut total = 0_u64;
    for table in schema::TABLES {
        let count: i64 = connection
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", table.native),
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        total = total
            .checked_add(u64::try_from(count).map_err(invalid)?)
            .ok_or_else(|| invalid("native row count overflow"))?;
    }
    Ok(total)
}

/// Whether one more native event could exceed the store-wide row budget.
pub(super) fn within_event_of_budget(
    connection: &Connection,
) -> Result<bool, AdmissionOperationStoreError> {
    Ok(current_rows(connection)?.saturating_add(EVENT_ROWS) > current_rows_budget())
}

fn capacity(detail: impl std::fmt::Display) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Unavailable(format!(
        "native security current-row capacity is exhausted: {detail}"
    ))
}

/// Largest current-row growth one admitted operation can still cause after
/// its first native write: its dispatch join after a nonce preflight (one
/// transition), one egress fence, a declassified commitment (use, evidence
/// and outbox rows), and one output join (a transition plus declassification
/// evidence and outbox rows). Every other later change rewrites existing rows.
pub(super) const OPERATION_ROWS: u64 = 8;

/// Unfinished operations scanned through the terminal index before the
/// reservation evidence counts as incomplete.
const MAX_UNFINISHED_SCAN: i64 = 65_537;

/// Whether this operation already made its first native write as a nonce
/// preflight, which reserved its later growth.
pub(super) fn preflight_recorded(
    connection: &Connection,
    operation: &AdmissionOperationId,
) -> Result<bool, AdmissionOperationStoreError> {
    if !super::nonce_preflight::exists(connection)? {
        return Ok(false);
    }
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM security_participant_nonce_preflight_events WHERE operation_id = ?1)",
            [operation.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

/// Unfinished operations that already hold native history, through the
/// terminal index and the journals' unique operation indexes.
fn unfinished_operations(connection: &Connection) -> Result<u64, AdmissionOperationStoreError> {
    let scanned: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM (SELECT 1 FROM admission_operations WHERE terminal = 0 LIMIT ?1)",
            [MAX_UNFINISHED_SCAN],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if scanned >= MAX_UNFINISHED_SCAN {
        return Err(capacity(
            "unfinished operations exceed the reservation scan",
        ));
    }
    let preflight = if super::nonce_preflight::exists(connection)? {
        " OR EXISTS(SELECT 1 FROM security_participant_nonce_preflight_events AS preflight
            WHERE preflight.operation_id = operation.operation_id)"
    } else {
        ""
    };
    let unfinished: i64 = connection
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM (SELECT operation_id FROM admission_operations
                 WHERE terminal = 0 LIMIT ?1) AS operation
                 WHERE EXISTS(SELECT 1 FROM security_participant_state_mutations AS joined
                     WHERE joined.operation_id = operation.operation_id){preflight}"
            ),
            [MAX_UNFINISHED_SCAN],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    u64::try_from(unfinished).map_err(invalid)
}

/// Admit a new native admission write after it is applied in the caller's
/// transaction. Every unfinished operation with native history keeps
/// `OPERATION_ROWS` reserved, and so does the admitted operation itself when
/// `operation` is set, so their later egress, commitment and output writes
/// cannot cross the store-wide budget. A write that would leave less room is
/// refused as a retryable operator resource condition, never an integrity
/// verdict, and rolls back.
pub(super) fn admit_operation(
    connection: &Connection,
    operation: bool,
) -> Result<(), AdmissionOperationStoreError> {
    let budget = current_rows_budget();
    let total = current_rows(connection)?;
    let unfinished = unfinished_operations(connection)?
        .checked_add(u64::from(operation))
        .ok_or_else(|| invalid("native reservation overflow"))?;
    let reserved = unfinished
        .checked_mul(OPERATION_ROWS)
        .ok_or_else(|| invalid("native reservation overflow"))?;
    if total
        .checked_add(reserved)
        .ok_or_else(|| invalid("native reservation overflow"))?
        > budget
    {
        return Err(capacity(format_args!(
            "{total} current rows, {reserved} reserved for {unfinished} unfinished operations, \
             budget {budget}"
        )));
    }
    Ok(())
}

pub(super) fn verify_no_orphans(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let budget = current_rows_budget();
    let mut total = 0_u64;
    for table in schema::TABLES {
        let (count, orphan): (i64, bool) = connection.query_row(&format!("SELECT COUNT(*), COALESCE(MAX(NOT EXISTS(
            SELECT 1 FROM security_participant_state_initializations AS initialized
            WHERE initialized.security_authority_id = state.security_authority_id)), 0) FROM {} AS state", table.native),
            [], |row| Ok((row.get(0)?, row.get(1)?))).map_err(sqlite_error)?;
        total = total
            .checked_add(u64::try_from(count).map_err(invalid)?)
            .ok_or_else(|| invalid("native row count overflow"))?;
        if orphan || total > budget {
            return Err(invalid("orphan or excessive native state"));
        }
    }
    Ok(())
}
