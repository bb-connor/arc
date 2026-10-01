//! Default-off local test controls. No persistent row or authority is fabricated.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeOutputJoinTestFault {
    AfterRows = 17,
    AfterEvent = 18,
    BeforeCommit = 19,
    AfterCommit = 20,
    AfterAnchor = 21,
}

impl SqliteAdmissionOperationStore {
    pub fn inject_native_output_join_failure_for_test(
        &self,
        fault: NativeOutputJoinTestFault,
    ) -> Result<(), AdmissionOperationStoreError> {
        let connection = self.connection()?;
        connection
            .execute_batch("CREATE TEMP TABLE native_output_test_fault (stage INTEGER NOT NULL)")
            .map_err(sqlite_error)?;
        connection
            .execute(
                "INSERT INTO temp.native_output_test_fault(stage) VALUES (?1)",
                [fault as u8],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    pub fn clear_native_output_join_failure_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch("DROP TABLE temp.native_output_test_fault")
            .map_err(sqlite_error)
    }
}

pub(super) fn check(
    connection: &Connection,
    stage: u8,
) -> Result<(), AdmissionOperationStoreError> {
    let installed: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_temp_schema WHERE type = 'table' AND name = 'native_output_test_fault')", [], |row| row.get(0)).map_err(sqlite_error)?;
    if installed {
        let fault: u8 = connection
            .query_row(
                "SELECT stage FROM temp.native_output_test_fault",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if fault == stage {
            return Err(invalid("injected native output journal failure"));
        }
    }
    Ok(())
}
