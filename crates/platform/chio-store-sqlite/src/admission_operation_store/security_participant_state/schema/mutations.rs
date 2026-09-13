//! v29 barriers require the affine mutation callback; history remains immutable.
use super::*;

pub(super) fn extend(mut sql: String) -> Result<String, AdmissionOperationStoreError> {
    sql.push_str(include_str!(
        "../../../admission_operation_security_participant_mutations.sql"
    ));
    for (index, table) in TABLES.iter().enumerate() {
        let columns =
            crate::security_state::retained_security_columns(table.source).map_err(invalid)?;
        for (suffix, operation, old, new) in [
            ("insert", "INSERT", false, true),
            ("update", "UPDATE", true, true),
            ("delete", "DELETE", true, false),
        ] {
            let old_authority = if old {
                "OLD.security_authority_id"
            } else {
                "NULL"
            };
            let new_authority = if new {
                "NEW.security_authority_id"
            } else {
                "NULL"
            };
            let mut arguments = vec![
                format!("'{}'", table.source),
                old_authority.into(),
                new_authority.into(),
            ];
            for (present, image) in [(old, "OLD"), (new, "NEW")] {
                if present {
                    arguments.extend(columns.iter().map(|column| format!("{image}.\"{column}\"")));
                }
            }
            sql.push_str(&format!(
                "\nDROP TRIGGER security_participant_state_{index}_inactive_{suffix};\n\
                CREATE TRIGGER security_participant_state_{index}_inactive_{suffix}\n\
                BEFORE {operation} ON {} WHEN EXISTS (SELECT 1 FROM security_participant_state_initializations\n\
                WHERE security_authority_id = {old_authority} OR security_authority_id = {new_authority})\n\
                BEGIN SELECT CASE WHEN chio_native_security_authorize('{}', {old_authority}, {new_authority}) = 1\n\
                THEN NULL ELSE RAISE(ABORT, 'native security state lacks operation custody') END; END;\n\
                DROP TRIGGER IF EXISTS security_participant_state_{index}_capture_{suffix};\n\
                CREATE TRIGGER security_participant_state_{index}_capture_{suffix}\n\
                AFTER {operation} ON {} WHEN EXISTS (SELECT 1 FROM security_participant_state_initializations\n\
                WHERE security_authority_id = {old_authority} OR security_authority_id = {new_authority})\n\
                BEGIN SELECT chio_native_security_change({}); END;\n", table.native, table.source, table.native, arguments.join(",")
            ));
        }
    }
    Ok(sql)
}
