//! The narrow admission-test-support inspection surface.
//!
//! Production builds never compile this module. It exists only so the
//! journal integration tests can drive the actual production Process
//! library over real native stores from integration targets: the in-crate
//! unit tests were compiled beside a duplicate of the Process crate, so the
//! native store downcast of the concrete journal writer could never see the
//! production writer type. Every operation below delegates to the real
//! production writers and store bodies; nothing here mints funding, proofs,
//! receipts or an alternative write path.
use crate::binding::ProcessCallBinding;
use crate::store::Store;
use crate::{ProcessError, ProcessRuntime, ProcessSnapshot, RecoveryCallReservation};
use chio_kernel::process_return_custody::{
    ProcessReturnFundingDataV1, ProcessReturnInventoryDataV1, ProcessReturnSourceDataV1,
};
use chio_kernel::ToolCallRequest;
use std::path::Path;

/// The complete existing call binding of one operation, wrapped for the
/// admission tests. It grants no authority beyond the hashes it exposes.
#[doc(hidden)]
pub struct AdmissionCallBinding(pub(crate) ProcessCallBinding);

impl AdmissionCallBinding {
    #[doc(hidden)]
    pub fn request_hash(&self) -> &str {
        &self.0.request_hash
    }
    #[doc(hidden)]
    pub fn binding_hash(&self) -> &str {
        &self.0.binding_hash
    }
}

/// The prepared original return source of an admitted call, wrapped for the
/// admission tests. It exposes only the validated DATA projection and the
/// canonical bytes; no pricing, funding or capture authority escapes.
#[doc(hidden)]
pub struct AdmissionPreparedSource(
    pub(crate) crate::store::native_return_custody::PreparedProcessReturnSource,
);

impl AdmissionPreparedSource {
    #[doc(hidden)]
    pub fn data(&self) -> &ProcessReturnSourceDataV1 {
        self.0.data()
    }
    #[doc(hidden)]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.0.canonical_bytes()
    }
}

#[doc(hidden)]
pub const MAX_PREPARED_SOURCE_BYTES: usize = crate::store::native_return_custody::MAX_SOURCE_BYTES;

/// Borrowed inputs for validating an original call's native return source,
/// mirroring the production request for the admission tests.
#[doc(hidden)]
pub struct AdmissionReturnSourceRequest<'a> {
    pub process_id: &'a str,
    pub operation_key: &'a str,
    pub request: &'a ToolCallRequest,
    pub binding: &'a AdmissionCallBinding,
    pub known_outcome_only: bool,
    pub security_context: Option<&'a chio_kernel::SecurityInvocationContext>,
}

/// One locked view of the actual production Store for an admission test
/// inspection. Every method delegates to the production writer body.
#[doc(hidden)]
pub struct AdmissionStore<'a> {
    store: &'a mut Store,
}

impl AdmissionStore<'_> {
    #[doc(hidden)]
    pub fn admit(
        &mut self,
        id: &str,
        key: &str,
        request: &ToolCallRequest,
        request_hash: &str,
    ) -> Result<(), ProcessError> {
        self.store.admit(id, key, request, request_hash)
    }
    #[doc(hidden)]
    pub fn reserve_recovery(
        &mut self,
        reservation: &RecoveryCallReservation,
    ) -> Result<(), ProcessError> {
        self.store.reserve_recovery(reservation)
    }
    #[doc(hidden)]
    pub fn finalize_recovery(
        &mut self,
        reservation: &RecoveryCallReservation,
        request: &ToolCallRequest,
        binding: &str,
    ) -> Result<(), ProcessError> {
        self.store.finalize_recovery(reservation, request, binding)
    }
    #[doc(hidden)]
    pub fn verify_recovery_reservation(
        &mut self,
        reservation: &RecoveryCallReservation,
    ) -> Result<(), ProcessError> {
        self.store.verify_recovery_reservation(reservation)
    }
    #[doc(hidden)]
    pub fn process(&self, id: &str) -> Result<ProcessSnapshot, ProcessError> {
        self.store.process(id)
    }
    #[doc(hidden)]
    pub fn require_raw_knowledge(&mut self) -> Result<(), ProcessError> {
        self.store.require_raw_knowledge()
    }
    #[doc(hidden)]
    pub fn require_enforced_knowledge(&mut self) -> Result<(), ProcessError> {
        self.store.require_enforced_knowledge()
    }
    /// The future finishing prices of a prepared source. Only their presence
    /// or refusal is observable here; no priced transaction is returned.
    #[doc(hidden)]
    pub fn inspect_original_return_finishing_prices(
        &mut self,
        source: &AdmissionPreparedSource,
    ) -> Result<(), ProcessError> {
        self.store
            .inspect_original_return_finishing_prices(&source.0)
            .map(|_| ())
    }
    /// One retained account of the installed bank, by digest. Only its
    /// presence is observable here; the account body stays in the bank.
    #[doc(hidden)]
    pub fn load_native_return_account(
        &mut self,
        account_digest: &str,
    ) -> Result<Option<()>, ProcessError> {
        self.store
            .load_native_return_account(account_digest)
            .map(|account| account.map(|_| ()))
    }
    #[doc(hidden)]
    pub fn native_return_inventory(
        &mut self,
    ) -> Result<ProcessReturnInventoryDataV1, ProcessError> {
        self.store.native_return_inventory()
    }
    #[doc(hidden)]
    pub fn verify_retained_enrollments(
        &mut self,
        inventory: &ProcessReturnInventoryDataV1,
        verify: impl FnMut(
            &ProcessReturnSourceDataV1,
            &ProcessReturnFundingDataV1,
            &str,
            u64,
            &str,
        )
            -> Result<(), chio_kernel::admission_operation::AdmissionOperationStoreError>,
    ) -> Result<u64, chio_kernel::admission_operation::AdmissionOperationStoreError> {
        self.store.verify_retained_enrollments(inventory, verify)
    }
    #[doc(hidden)]
    pub fn prepare_native_return_source(
        &mut self,
        runtime: &ProcessRuntime,
        selection: &AdmissionReturnSourceRequest<'_>,
    ) -> Result<AdmissionPreparedSource, ProcessError> {
        self.store
            .prepare_native_return_source(
                runtime,
                &crate::store::native_return_custody::NativeReturnSourceRequest {
                    process_id: selection.process_id,
                    operation_key: selection.operation_key,
                    request: selection.request,
                    binding: &selection.binding.0,
                    known_outcome_only: selection.known_outcome_only,
                    security_context: selection.security_context,
                },
            )
            .map(AdmissionPreparedSource)
    }
    #[doc(hidden)]
    pub fn startup_pending(&self) -> bool {
        self.store.startup_pending()
    }
    /// Immediate transaction over the actual production connection for the
    /// deliberate corruption controls. Test-only: its writes reach the real
    /// journal under the same SQLite semantics the controls assert against,
    /// and no production build compiles it.
    #[doc(hidden)]
    pub fn corruption_transaction(
        &mut self,
        behavior: rusqlite::TransactionBehavior,
    ) -> rusqlite::Result<rusqlite::Transaction<'_>> {
        self.store
            .inspection_connection_mut()
            .transaction_with_behavior(behavior)
    }
    /// Raw journal handle for the deliberate corruption controls of the
    /// admission tests. This is a test-only surface: it shares the actual
    /// production connection, so SQLite writes through it reach the real
    /// journal, which is exactly what the corruption controls depend on.
    /// No production build compiles it.
    #[doc(hidden)]
    pub fn connection(&self) -> &rusqlite::Connection {
        self.store.inspection_connection()
    }
}

/// A separately opened production journal writer for the admission tests:
/// the same concrete Store, wrapped so only the tested operations surface.
#[doc(hidden)]
pub struct AdmissionJournalWriter {
    store: Store,
}

impl AdmissionJournalWriter {
    #[doc(hidden)]
    pub fn open(path: &Path, authority: &str, kernel_key: &str) -> Result<Self, ProcessError> {
        Ok(Self {
            store: Store::open(path, authority, kernel_key)?,
        })
    }
    #[doc(hidden)]
    pub fn startup_pending(&self) -> bool {
        self.store.startup_pending()
    }
    #[doc(hidden)]
    pub fn admit(
        &mut self,
        id: &str,
        key: &str,
        request: &ToolCallRequest,
        request_hash: &str,
    ) -> Result<(), ProcessError> {
        self.store.admit(id, key, request, request_hash)
    }
    #[doc(hidden)]
    pub fn finalize_recovery(
        &mut self,
        reservation: &RecoveryCallReservation,
        request: &ToolCallRequest,
        binding: &str,
    ) -> Result<(), ProcessError> {
        self.store.finalize_recovery(reservation, request, binding)
    }
    #[doc(hidden)]
    pub fn connection(&self) -> &rusqlite::Connection {
        self.store.inspection_connection()
    }
}

impl ProcessRuntime {
    /// Run one inspection over the actual locked production Store.
    #[doc(hidden)]
    pub fn admission_inspect<T>(
        &self,
        inspect: impl FnOnce(&mut AdmissionStore<'_>) -> Result<T, ProcessError>,
    ) -> Result<T, ProcessError> {
        let mut guard = self.store.lock().map_err(|_| ProcessError::StorePoisoned)?;
        let mut admission = AdmissionStore { store: &mut *guard };
        inspect(&mut admission)
    }
    #[doc(hidden)]
    pub fn admission_derive_call_binding(
        &self,
        process_id: &str,
        operation_key: &str,
        request: &ToolCallRequest,
        known_outcome_only: bool,
    ) -> Result<AdmissionCallBinding, ProcessError> {
        self.derive_call_binding(process_id, operation_key, request, known_outcome_only)
            .map(AdmissionCallBinding)
    }
    #[doc(hidden)]
    pub fn admission_namespace(&self) -> &str {
        &self.namespace
    }
    #[doc(hidden)]
    pub fn admission_knowledge_enforcement(
        &self,
    ) -> &chio_kernel::knowledge::DurableKnowledgeEnforcement {
        &self.enforcement
    }
    #[doc(hidden)]
    pub fn admission_activate_knowledge(&self) -> Result<(), ProcessError> {
        self.writer.activate_knowledge()
    }
    #[doc(hidden)]
    pub fn admission_original_call_key(
        &self,
        process: &str,
        request: &ToolCallRequest,
        bindings: &[String; 2],
    ) -> Result<String, ProcessError> {
        self.original_snapshot
            .original_call_key(process, request, bindings)
    }
}

#[doc(hidden)]
pub fn admission_private_file(path: &Path) -> Result<std::path::PathBuf, ProcessError> {
    crate::store::private_file(path)
}

#[doc(hidden)]
pub fn admission_catalog_sql() -> &'static str {
    crate::store::unused_recovery_reservation::catalog::SQL
}

#[doc(hidden)]
pub fn admission_catalog_verify(connection: &rusqlite::Connection) -> Result<(), ProcessError> {
    crate::store::unused_recovery_reservation::catalog::verify(connection)
}

#[doc(hidden)]
pub fn admission_catalog_family_present(
    connection: &rusqlite::Connection,
) -> Result<bool, ProcessError> {
    crate::store::unused_recovery_reservation::catalog::family_present(connection)
}
