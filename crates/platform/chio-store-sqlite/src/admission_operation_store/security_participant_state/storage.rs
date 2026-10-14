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
    hydrate_at_version(tx, source, schema::CURRENT_VERSION)
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

const MAX_TENANT_LIVE_ROWS: u64 = 65_536;
const MAX_TENANT_LIVE_BYTES: u64 = 67_108_864;

/// How a native table's rows are accounted.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum NativeRowClass {
    /// Insert-only identity, read by primary key and never counted as live
    /// custody. Its growth is admitted by the physical intake band.
    RetainedIdentity,
    /// Current custody keyed by identity, counted per (authority, tenant).
    Live,
    /// At most one row per authority.
    AuthoritySingleton,
}

/// Exhaustive over the native catalog; a table without a class refuses.
pub(super) fn row_class(
    table: &schema::Table,
) -> Result<NativeRowClass, AdmissionOperationStoreError> {
    match table.source {
        "security_transitions" => Ok(NativeRowClass::RetainedIdentity),
        "security_declassification_lifecycle" => Ok(NativeRowClass::AuthoritySingleton),
        "security_flow_contexts"
        | "security_flow_sequences"
        | "security_isolation_epochs"
        | "security_lineage_flow_state"
        | "security_principal_flow_state"
        | "security_session_flow_state"
        | "security_session_memberships"
        | "security_egress_fences"
        | "security_declassification_uses"
        | "security_declassification_receipt_outbox"
        | "security_declassification_evidence_identity"
        | "security_declassification_tombstones" => Ok(NativeRowClass::Live),
        _ => Err(invalid("native table has no row class")),
    }
}

fn row_bytes(table: &schema::Table) -> Result<String, AdmissionOperationStoreError> {
    Ok(retained_security_columns(table.source)
        .map_err(invalid)?
        .iter()
        .map(|name| format!("COALESCE(length(CAST(\"{name}\" AS BLOB)), 0)"))
        .collect::<Vec<_>>()
        .join(" + "))
}

/// Live rows and retained bytes of one (authority, tenant).
pub(super) struct TenantLive {
    rows: u64,
    bytes: u64,
}

/// An index range over the (authority, tenant) primary-key prefix of every
/// Live table. Bounded because every writer checks before the bound passes.
pub(super) fn tenant_live(
    connection: &Connection,
    authority: &str,
    tenant: &str,
) -> Result<TenantLive, AdmissionOperationStoreError> {
    let mut live = TenantLive { rows: 0, bytes: 0 };
    for table in schema::TABLES {
        if row_class(table)? != NativeRowClass::Live {
            continue;
        }
        let (rows, bytes): (i64, i64) = connection
            .query_row(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM({}), 0) FROM {}
                     WHERE security_authority_id = ?1 AND tenant_id = ?2",
                    row_bytes(table)?,
                    table.native
                ),
                params![authority, tenant],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sqlite_error)?;
        live.rows = live
            .rows
            .checked_add(u64::try_from(rows).map_err(invalid)?)
            .ok_or_else(|| invalid("native live row count overflow"))?;
        live.bytes = live
            .bytes
            .checked_add(u64::try_from(bytes).map_err(invalid)?)
            .ok_or_else(|| invalid("native live byte count overflow"))?;
    }
    Ok(live)
}

/// Every native writer calls this after its row changes and before its
/// append, for its typed tenant. The refusal is scoped to that tenant: an
/// existing key updates in place and a replay writes nothing, so only new
/// identity keys or growth past the bound refuse.
pub(super) fn require_tenant_live(
    connection: &Connection,
    authority: &str,
    tenant: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let live = tenant_live(connection, authority, tenant)?;
    if live.rows > MAX_TENANT_LIVE_ROWS || live.bytes > MAX_TENANT_LIVE_BYTES {
        return Err(invariant("native tenant live state exhausted"));
    }
    Ok(())
}

/// Open only. Every native row belongs to an initialized authority, with no
/// count bound on retained identity rows; every (authority, tenant) live
/// account is within its bound; the authority singleton holds one row at most.
pub(super) fn verify_native_inventory_cold(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let mut live = Vec::new();
    for table in schema::TABLES {
        let orphan: bool = connection
            .query_row(
                &format!(
                    "SELECT EXISTS(SELECT 1 FROM {} AS state WHERE NOT EXISTS(
                     SELECT 1 FROM security_participant_state_initializations AS initialized
                     WHERE initialized.security_authority_id = state.security_authority_id))",
                    table.native
                ),
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if orphan {
            return Err(invalid("orphan native state"));
        }
        match row_class(table)? {
            NativeRowClass::Live => live.push(format!(
                "SELECT security_authority_id AS authority, tenant_id AS tenant, {} AS bytes FROM {}",
                row_bytes(table)?,
                table.native
            )),
            NativeRowClass::AuthoritySingleton => {
                let repeated: bool = connection
                    .query_row(
                        &format!(
                            "SELECT EXISTS(SELECT 1 FROM {} GROUP BY security_authority_id
                             HAVING COUNT(*) > 1)",
                            table.native
                        ),
                        [],
                        |row| row.get(0),
                    )
                    .map_err(sqlite_error)?;
                if repeated {
                    return Err(invalid("native authority singleton is repeated"));
                }
            }
            NativeRowClass::RetainedIdentity => {}
        }
    }
    let exhausted: bool = connection
        .query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM ({}) GROUP BY authority, tenant
                 HAVING COUNT(*) > ?1 OR SUM(bytes) > ?2)",
                live.join(" UNION ALL ")
            ),
            params![
                i64::try_from(MAX_TENANT_LIVE_ROWS).map_err(invalid)?,
                i64::try_from(MAX_TENANT_LIVE_BYTES).map_err(invalid)?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if exhausted {
        return Err(invalid("native tenant live state exceeds its bound"));
    }
    Ok(())
}
