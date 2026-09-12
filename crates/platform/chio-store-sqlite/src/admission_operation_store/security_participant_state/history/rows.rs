//! Compare current row identities to imported bytes plus anchored row changes.
//! No historical domain command is re-executed or promoted to authority.
use super::*;
use crate::security_state::{
    decode_retained_security_row, encode_retained_security_values, retained_security_columns,
};
use std::collections::BTreeMap;

type Inventory = BTreeMap<(String, String), usize>;

fn apply_image(
    inventory: &mut Inventory,
    table: &str,
    image: &str,
    insert: bool,
) -> Result<(), AdmissionOperationStoreError> {
    decode_retained_security_row(table, image.as_bytes()).map_err(invalid)?;
    let key = (table.to_owned(), sha256_hex(image.as_bytes()));
    if insert {
        if inventory.insert(key, image.len()).is_some() {
            return Err(invalid("native mutation duplicates an existing row"));
        }
    } else if inventory.remove(&key) != Some(image.len()) {
        return Err(invalid(
            "native mutation before-image has no exact predecessor",
        ));
    }
    if inventory.len() > 65_536 {
        return Err(invalid("native current row inventory exceeds bounds"));
    }
    Ok(())
}

pub(in crate::admission_operation_store::security_participant_state) fn verify_rows(
    connection: &Connection,
    source: &SecurityParticipantMigrationRecord,
    initialization: &SecurityParticipantStateInitialization,
) -> Result<(), AdmissionOperationStoreError> {
    let authority = initialization.authority.as_str();
    let head = super::head(connection, authority)?;
    let egress = super::super::egress::exists(connection)?
        && super::super::egress::head(connection, authority)? != 0;
    let output = super::super::output::exists(connection)?
        && super::super::output::head(connection, authority)? != 0;
    let nonce_preflight = super::super::nonce_preflight::exists(connection)?
        && super::super::nonce_preflight::head(connection, authority)? != 0;
    if head == 1 && !egress && !output && !nonce_preflight {
        return super::super::storage::verify_rows(connection, source);
    }
    let mut inventory = Inventory::new();
    let mut statement = connection
        .prepare(
            "SELECT table_name, canonical_row FROM security_participant_migration_rows
         WHERE security_authority_id = ?1 ORDER BY table_name, row_index",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([authority]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let table: String = row.get(0).map_err(sqlite_error)?;
        let bytes = row
            .get_ref(1)
            .map_err(sqlite_error)?
            .as_blob()
            .map_err(invalid)?;
        apply_image(
            &mut inventory,
            &table,
            std::str::from_utf8(bytes).map_err(invalid)?,
            true,
        )?;
    }
    super::ordered::visit(connection, initialization, |event| {
        for change in event.changes() {
            // Each decoded family independently enforces its exact row policy.
            // Join-v1 still cannot remove rows, release fences or spend grants.
            if let Some(before) = &change.before {
                apply_image(&mut inventory, &change.table, before, false)?;
            }
            if let Some(after) = &change.after {
                apply_image(&mut inventory, &change.table, after, true)?;
            }
        }
        let expected = event.totals();
        if u64::try_from(inventory.len()).map_err(invalid)? != expected.0
            || u64::try_from(inventory.values().sum::<usize>()).map_err(invalid)? != expected.1
        {
            return Err(invalid(
                "native current row bounds differ from anchored history",
            ));
        }
        Ok(())
    })?;
    for table in schema::TABLES {
        let fields = retained_security_columns(table.source).map_err(invalid)?;
        let columns = fields
            .iter()
            .map(|field| format!("\"{field}\""))
            .collect::<Vec<_>>()
            .join(",");
        let mut statement = connection
            .prepare(&format!(
                "SELECT {columns} FROM {} WHERE security_authority_id = ?1",
                table.native
            ))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([authority]).map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let values = (0..fields.len())
                .map(|index| row.get_ref(index))
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(sqlite_error)?;
            let bytes = encode_retained_security_values(table.source, &values).map_err(invalid)?;
            let key = (table.source.to_owned(), sha256_hex(&bytes));
            if inventory.remove(&key) != Some(bytes.len()) {
                return Err(invalid("native current row differs from anchored history"));
            }
        }
    }
    if !inventory.is_empty() {
        return Err(invalid("native current rows are missing anchored history"));
    }
    Ok(())
}
