//! Feature-gated counter of native catalog scans, including reused-read misses.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Observe every native `sqlite_schema` catalog scan on this store
    /// connection, from any thread, with the catalog kind it read. A read that
    /// is reused is not reported. The observer cannot change a catalog result.
    pub fn observe_native_catalog_scans_for_test(
        &self,
        observer: impl Fn(&str) + Send + std::panic::UnwindSafe + 'static,
    ) -> Result<(), AdmissionOperationStoreError> {
        use rusqlite::functions::FunctionFlags;
        self.connection()?
            .create_scalar_function(
                crate::catalog_memo::SCAN_PROBE,
                1,
                FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DIRECTONLY,
                move |context| {
                    observer(&context.get::<String>(0)?);
                    Ok(0_i32)
                },
            )
            .map_err(sqlite_error)
    }
}
