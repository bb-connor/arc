//! Advance the injected authority clock after verification, never a validity witness.
//! The callback is connection-local and compiled only with admission-test-support.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Advance the configured clock at final verification to the original grant expiry.
    pub fn inject_native_capture_declassification_expiry_for_test(
        &self,
        advance: impl Fn(u64) -> Result<(), String> + Send + std::panic::UnwindSafe + 'static,
    ) -> Result<(), AdmissionOperationStoreError> {
        let connection = self.connection()?;
        install_advance(&connection, advance)?;
        connection.execute_batch("CREATE TEMP TABLE native_capture_declassification_expiry_test_fault (singleton INTEGER PRIMARY KEY CHECK(singleton = 1))").map_err(sqlite_error)
    }

    pub fn clear_native_capture_declassification_expiry_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        let connection = self.connection()?;
        connection
            .execute_batch("DROP TABLE temp.native_capture_declassification_expiry_test_fault")
            .map_err(sqlite_error)?;
        connection
            .remove_function("native_capture_expiry_advance", 1)
            .map_err(sqlite_error)
    }

    /// Advance the configured clock at final verification to the original nonce expiry.
    pub fn inject_native_capture_nonce_expiry_for_test(
        &self,
        advance: impl Fn(u64) -> Result<(), String> + Send + std::panic::UnwindSafe + 'static,
    ) -> Result<(), AdmissionOperationStoreError> {
        let connection = self.connection()?;
        install_advance(&connection, advance)?;
        connection.execute_batch("CREATE TEMP TABLE native_capture_nonce_expiry_test_fault (singleton INTEGER PRIMARY KEY CHECK(singleton = 1))").map_err(sqlite_error)
    }

    pub fn clear_native_capture_nonce_expiry_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        let connection = self.connection()?;
        connection
            .execute_batch("DROP TABLE temp.native_capture_nonce_expiry_test_fault")
            .map_err(sqlite_error)?;
        connection
            .remove_function("native_capture_expiry_advance", 1)
            .map_err(sqlite_error)
    }

    /// Advance the configured clock at final verification to the original runtime
    /// expiry. No main table or signed deadline is changed.
    pub fn inject_native_capture_runtime_expiry_for_test(
        &self,
        advance: impl Fn(u64) -> Result<(), String> + Send + std::panic::UnwindSafe + 'static,
    ) -> Result<(), AdmissionOperationStoreError> {
        let connection = self.connection()?;
        install_advance(&connection, advance)?;
        connection.execute_batch("CREATE TEMP TABLE native_capture_runtime_expiry_test_fault (singleton INTEGER PRIMARY KEY CHECK(singleton = 1))").map_err(sqlite_error)
    }

    pub fn clear_native_capture_runtime_expiry_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        let connection = self.connection()?;
        connection
            .execute_batch("DROP TABLE temp.native_capture_runtime_expiry_test_fault")
            .map_err(sqlite_error)?;
        connection
            .remove_function("native_capture_expiry_advance", 1)
            .map_err(sqlite_error)
    }
}

pub(super) fn wait_after_verification(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    runtime_until: Option<u64>,
    nonce_until: Option<u64>,
    declassification_until: Option<u64>,
) -> Result<Option<&'static str>, AdmissionOperationStoreError> {
    let installed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_temp_schema WHERE type = 'table' AND name = 'native_capture_runtime_expiry_test_fault')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    let nonce_installed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_temp_schema WHERE type = 'table' AND name = 'native_capture_nonce_expiry_test_fault')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    let declassification_installed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_temp_schema WHERE type = 'table' AND name = 'native_capture_declassification_expiry_test_fault')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    let (kind, until) = match (installed, nonce_installed, declassification_installed) {
        (false, false, false) => return Ok(None),
        (true, false, false) => ("runtime", runtime_until),
        (false, true, false) => ("nonce", nonce_until),
        (false, false, true) => ("declassification", declassification_until),
        _ => return Err(invalid("expiry cutpoint selects multiple credentials")),
    };
    let until = until.ok_or_else(|| invalid("expiry cutpoint lacks selected credential"))?;
    let before = super::super::super::super::schema::observe_authority_time(tx, owner)?;
    until
        .checked_sub(before)
        .filter(|remaining| (1..60_000).contains(remaining))
        .ok_or_else(|| invalid("expiry cutpoint missed its bounded live credential window"))?;
    let _: i32 = tx
        .query_row(
            "SELECT native_capture_expiry_advance(?1)",
            [i64::try_from(until).map_err(invalid)?],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    // The callback changes only the actual injected clock. The production
    // verification below still samples that owner and decides whether to deny.
    if super::super::super::super::schema::observe_authority_time(tx, owner)? < until {
        return Err(invalid(
            "expiry cutpoint did not advance the authority clock",
        ));
    }
    Ok(Some(kind))
}

pub(super) fn annotate_rejection(
    delayed: Option<&'static str>,
    result: Result<(), AdmissionOperationStoreError>,
) -> Result<(), AdmissionOperationStoreError> {
    // Preserve success: this observation must never manufacture the rejection
    // under test. Its marker distinguishes final expiry from an earlier denial.
    result.map_err(|error| {
        if let Some(kind) = delayed {
            invalid(format!(
                "native capture rejected after {kind} expiry cutpoint: {error}"
            ))
        } else {
            error
        }
    })
}

fn install_advance(
    connection: &Connection,
    advance: impl Fn(u64) -> Result<(), String> + Send + std::panic::UnwindSafe + 'static,
) -> Result<(), AdmissionOperationStoreError> {
    use rusqlite::functions::FunctionFlags;
    connection
        .create_scalar_function(
            "native_capture_expiry_advance",
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DIRECTONLY,
            move |context| {
                let until = u64::try_from(context.get::<i64>(0)?)
                    .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
                advance(until).map_err(|message| {
                    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other(message)))
                })?;
                Ok(0_i32)
            },
        )
        .map_err(sqlite_error)
}
