//! A real-clock pause after verification, never a fabricated validity witness.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Pause at final verification until the original declassification grant expires.
    pub fn inject_native_capture_declassification_expiry_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?.execute_batch("CREATE TEMP TABLE native_capture_declassification_expiry_test_fault (singleton INTEGER PRIMARY KEY CHECK(singleton = 1))").map_err(sqlite_error)
    }

    pub fn clear_native_capture_declassification_expiry_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch("DROP TABLE temp.native_capture_declassification_expiry_test_fault")
            .map_err(sqlite_error)
    }

    /// Pause at the final verified state until the original execution nonce expires.
    pub fn inject_native_capture_nonce_expiry_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?.execute_batch("CREATE TEMP TABLE native_capture_nonce_expiry_test_fault (singleton INTEGER PRIMARY KEY CHECK(singleton = 1))").map_err(sqlite_error)
    }

    pub fn clear_native_capture_nonce_expiry_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch("DROP TABLE temp.native_capture_nonce_expiry_test_fault")
            .map_err(sqlite_error)
    }

    /// Pause native capture at its final verified state until its
    /// original runtime evidence expires. No main table or deadline is changed.
    pub fn inject_native_capture_runtime_expiry_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch("CREATE TEMP TABLE native_capture_runtime_expiry_test_fault (singleton INTEGER PRIMARY KEY CHECK(singleton = 1))")
            .map_err(sqlite_error)
    }

    pub fn clear_native_capture_runtime_expiry_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch("DROP TABLE temp.native_capture_runtime_expiry_test_fault")
            .map_err(sqlite_error)
    }
}

pub(super) fn wait_after_verification(
    tx: &Transaction<'_>,
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
    let remaining = until
        .checked_sub(now()?)
        .filter(|remaining| (1..60_000).contains(remaining))
        .ok_or_else(|| invalid("expiry cutpoint missed its bounded live credential window"))?;
    std::thread::sleep(std::time::Duration::from_millis(remaining));
    if now()? < until {
        return Err(invalid("wall clock regressed during expiry cutpoint"));
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

fn now() -> Result<u64, AdmissionOperationStoreError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(invalid)?
        .as_millis()
        .try_into()
        .map_err(invalid)
}
