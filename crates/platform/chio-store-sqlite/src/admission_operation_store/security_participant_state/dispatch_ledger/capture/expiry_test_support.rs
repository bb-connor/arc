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

impl SqliteAdmissionOperationStore {
    /// Install an exact-operation test marker. It contains no deadline or
    /// authority witness and changes no durable main-table state.
    pub fn inject_native_capture_setup_expiry_for_test(
        &self,
        operation_id: &AdmissionOperationId,
        observed_path: &std::path::Path,
    ) -> Result<(), AdmissionOperationStoreError> {
        let observed_path = observed_path
            .to_str()
            .filter(|path| !path.is_empty() && path.len() <= 4096)
            .ok_or_else(|| invalid("setup final capture observation path is invalid"))?;
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        let original =
            crate::admission_operation_store::load_by_operation_id_tx(&tx, operation_id)?
                .ok_or_else(|| invalid("setup capture test original is absent"))?;
        crate::admission_operation_store::schema::verify_active_owner(
            &tx,
            &self.serving_owner,
            Some(&self.serving_owner.fence),
        )?;
        if original.operation.dispatch_commit().is_some()
            || original.operation.state() != AdmissionOperationState::CapturePending
        {
            return Err(invalid("setup capture test original is not pending"));
        }
        tx.execute_batch(
            "CREATE TEMP TABLE native_capture_setup_expiry_test_fault (
                    operation_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    store_uuid TEXT NOT NULL,
                    observed_path TEXT NOT NULL,
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1))",
        )
        .map_err(sqlite_error)?;
        tx
            .execute(
                "INSERT INTO temp.native_capture_setup_expiry_test_fault
             (operation_id,namespace,request_id,store_uuid,observed_path,singleton) VALUES (?1,?2,?3,?4,?5,1)",
                params![
                    operation_id.as_str(),
                    original
                        .operation
                        .binding()
                        .request_namespace_digest()
                        .as_str(),
                    original.operation.binding().request_id().as_str(),
                    self.serving_owner.fence.store_uuid,
                    observed_path,
                ],
            )
            .map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
    }

    pub fn clear_native_capture_setup_expiry_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch("DROP TABLE temp.native_capture_setup_expiry_test_fault")
            .map_err(sqlite_error)
    }
}

/// Called after genuine credential and policy state verification. The deadline
/// is supplied only by the private verified native capture, never by the marker.
/// Keep the returned guard through commit_now and both final time validators.
pub(super) fn setup_clock_after_state_verification(
    tx: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    owner: &SqliteServingOwner,
    setup_deadline: Option<u64>,
    sampled_at: u64,
    verify_other_deadlines: impl FnOnce(u64) -> Result<(), AdmissionOperationStoreError>,
) -> Result<Option<chio_kernel::FixedRuntimeClockScope>, AdmissionOperationStoreError> {
    let installed: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_temp_schema
         WHERE type='table' AND name='native_capture_setup_expiry_test_fault')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !installed {
        return Ok(None);
    }
    let (selected, namespace, request, store, observed_path): (
        String,
        String,
        String,
        String,
        String,
    ) = tx
        .query_row(
            "SELECT operation_id,namespace,request_id,store_uuid,observed_path
         FROM temp.native_capture_setup_expiry_test_fault WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(sqlite_error)?;
    let deadline = setup_deadline
        .filter(|deadline| sampled_at < *deadline)
        .ok_or_else(|| invalid("setup final capture test missed the live initial window"))?;
    if selected != operation.binding().operation_id().as_str()
        || namespace != operation.binding().request_namespace_digest().as_str()
        || request != operation.binding().request_id().as_str()
        || store != owner.fence.store_uuid
    {
        return Err(invalid(
            "setup final capture test changed its owning original",
        ));
    }
    // This interleaving changes only the existing trusted test clock. It cannot
    // alter credentials, the deadline, the native witness or any main-table row.
    let expired_seconds = deadline
        .checked_div(1_000)
        .and_then(|seconds| seconds.checked_add(1))
        .ok_or_else(|| invalid("setup final capture test clock overflow"))?;
    let expired_unix_ms = expired_seconds
        .checked_mul(1_000)
        .ok_or_else(|| invalid("setup final capture test millisecond clock overflow"))?;
    // The owning verified capture must prove every unchanged participant still
    // covers the final time, so another credential cannot stand in for setup.
    verify_other_deadlines(expired_unix_ms)?;
    // This fixture-only observation follows actual unchanged credential state
    // verification. Its scalars are facts, never inputs to native authority.
    use std::io::Write as _;
    let mut observed = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(observed_path)
        .map_err(|_| invalid("setup final capture cutpoint observation unavailable"))?;
    observed
        .write_all(format!("{sampled_at},{deadline},{expired_unix_ms}").as_bytes())
        .map_err(|_| invalid("setup final capture cutpoint observation incomplete"))?;
    Ok(Some(
        chio_kernel::scope_fixed_runtime_clock_for_current_thread(expired_seconds),
    ))
}
