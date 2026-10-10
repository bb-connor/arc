//! Feature-gated counters observe row verification without changing custody.
use super::*;

const FUNCTION: &str = "native_image_visit_probe";

impl SqliteAdmissionOperationStore {
    /// Observe snapshot, current-image, imported-image and checkpoint-copy row
    /// visits on this store connection, including work performed by another
    /// thread. Zero starts a traversal; positive values count fetched rows.
    /// This test-support observer cannot substitute an image or verification.
    pub fn observe_native_image_visits_for_test(
        &self,
        observer: impl Fn(&'static str, u64) + Send + std::panic::UnwindSafe + 'static,
    ) -> Result<(), AdmissionOperationStoreError> {
        use rusqlite::functions::FunctionFlags;
        let connection = self.connection()?;
        connection
            .create_scalar_function(
                FUNCTION,
                2,
                FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DIRECTONLY,
                move |context| {
                    let input_kind = context.get::<String>(0)?;
                    let kind = match input_kind.as_str() {
                        "snapshot" => "snapshot",
                        "current" => "current",
                        "imported" => "imported",
                        "copy" => "copy",
                        _ => {
                            return Err(rusqlite::Error::UserFunctionError(Box::new(
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "unknown image probe traversal",
                                ),
                            )))
                        }
                    };
                    let visited = u64::try_from(context.get::<i64>(1)?)
                        .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
                    observer(kind, visited);
                    Ok(0_i32)
                },
            )
            .map_err(sqlite_error)
    }
}

pub(super) struct ImageVisitProbe {
    kind: &'static str,
    installed: bool,
    visited: u64,
}

impl ImageVisitProbe {
    pub(super) fn start(
        connection: &Connection,
        kind: &'static str,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let installed = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_function_list WHERE name = ?1)",
                [FUNCTION],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let probe = Self {
            kind,
            installed,
            visited: 0,
        };
        probe.report(connection)?;
        Ok(probe)
    }

    pub(super) fn advance(
        &mut self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.visited = self
            .visited
            .checked_add(1)
            .ok_or_else(|| invalid("native image visit count overflow"))?;
        self.report(connection)
    }

    fn report(&self, connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
        if self.installed {
            let _: i32 = connection
                .query_row(
                    "SELECT native_image_visit_probe(?1, ?2)",
                    params![self.kind, i64::try_from(self.visited).map_err(invalid)?],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
        }
        Ok(())
    }
}
