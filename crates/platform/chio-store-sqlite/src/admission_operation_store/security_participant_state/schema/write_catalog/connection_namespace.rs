//! Native source readers and priced callbacks share the actual main namespace.
use super::*;

pub(super) fn require_native_source_namespace(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare("PRAGMA database_list")
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut main = false;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let name: String = row.get(1).map_err(sqlite_error)?;
        match name.as_str() {
            "main" => main = true,
            "temp" => (),
            _ => {
                return Err(invalid(
                    "native write profile has an unpriced attached database",
                ))
            }
        }
    }
    if !main {
        return Err(invalid("native write profile lost its main database"));
    }
    // A source factory reads initialization, immutable import, original,
    // owner, stamp, current heads and protected custody in addition to its
    // fourteen native tables. Refuse a shadow of any actual main source.
    // Unrelated temporary census tables still remain usable.
    let shadow: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema AS temporary
         WHERE temporary.type IN ('table','view') AND (
           EXISTS(SELECT 1 FROM main.sqlite_schema AS source
             WHERE source.type IN ('table','view')
               AND source.name=temporary.name COLLATE NOCASE)
           OR lower(temporary.name) IN ('dbstat','sqlite_schema','sqlite_master')
           OR lower(temporary.name) GLOB 'pragma_*'))",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    // A TEMP trigger may execute on a main-qualified write. This profile has
    // no descriptor for its body, including writes outside the native tables.
    let callback: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema WHERE type='trigger')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let shadowed_dbstat: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema
         WHERE lower(name)='dbstat' OR lower(tbl_name)='dbstat')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if shadow || callback || shadowed_dbstat {
        return Err(invalid(
            "native write profile has an unpriced source shadow or callback",
        ));
    }
    Ok(())
}
