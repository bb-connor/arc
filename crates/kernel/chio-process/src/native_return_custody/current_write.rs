//! The concrete current-write provider of the Process journal.
//!
//! The native Store downcasts the Kernel marker to exactly this type and uses
//! only these methods: it borrows the actual complete file observation to
//! mint its bank proof from its whole retained inverse (including before
//! this file has its first loan), then executes the priced, preconditioned
//! write under that proof. Neither descriptive DATA, a cloned proof, another
//! provider implementation nor a trusted-looking marker can stand in for it.
//! The provider never takes a Process lock while the caller holds one; the
//! Kernel holds the native mutation sequencer first, so every Process lock
//! taken inside `inventory` and `execute` follows the Native-then-Process
//! order.
use super::*;
use crate::store::Store;
use chio_kernel::native_finishing::{
    NativeProcessCurrentWriteEnforcement, NativeProcessCurrentWriteProvider,
};
use chio_kernel::process_return_custody::{
    ProcessReturnInventoryDataV1, VerifiedProcessReturnBank,
};
use rusqlite::Transaction;
use std::sync::{Arc, Mutex};

/// One priced, preconditioned write body. The boxed value is the write's
/// committed result, taken exactly once after the Kernel scope returned.
type WriteBody = Box<
    dyn FnOnce(&Transaction<'_>) -> Result<Box<dyn std::any::Any + Send>, ProcessError>
        + Send
        + Sync,
>;

/// One read-only pricer of the actual complete rows the body will write.
type WriteDescribe = Box<
    dyn Fn(&rusqlite::Connection) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError>
        + Send
        + Sync,
>;

enum CurrentWritePlan {
    CallAdmission {
        process_id: String,
        operation_key: String,
        request: chio_kernel::ToolCallRequest,
        binding_hash: String,
    },
    Checkpoint {
        process_id: String,
        expected_revision: u64,
        value: serde_json::Value,
    },
    /// The startup write of a new or supported journal layout, derived by the
    /// Store from its own authenticated plan.
    Startup,
    Routed {
        describe: WriteDescribe,
        body: Mutex<Option<WriteBody>>,
    },
}

/// One priced, preconditioned Process mutation carried through the Kernel's
/// original current-write scope. It is minted only by the owning runtime
/// after a read-only preparation priced the actual rows from the live
/// journal; it exposes no SQL, census, quantity or financial authority, and
/// it is not clonable or decodable.
pub struct ProcessNativeCurrentWrite {
    store: Arc<Mutex<Store>>,
    plan: CurrentWritePlan,
    outcome: Mutex<Option<Box<dyn std::any::Any + Send>>>,
    failure: Mutex<Option<ProcessError>>,
}

impl NativeProcessCurrentWriteProvider for ProcessNativeCurrentWrite {
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

impl core::fmt::Debug for ProcessNativeCurrentWrite {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProcessNativeCurrentWrite([redacted])")
    }
}

impl ProcessNativeCurrentWrite {
    /// The actual complete current file observation consumed by the native
    /// bank readback. Both real states are authenticated from actual file
    /// content: an installed cohort verifies its complete frontier and
    /// canonical rows, while an exact supported predecessor layout
    /// authenticates through its profile and reports proven zero counts as
    /// measured DATA. Missing tables, torn state or family loss with
    /// retained history refuses; the native owner proves these zeros against
    /// its whole inverse before minting any proof.
    pub fn inventory(&self) -> Result<ProcessReturnInventoryDataV1, ProcessError> {
        self.with_store(|store| store.native_return_inventory())
    }

    /// Execute the priced write under the native Store's minted bank proof.
    /// The proof is revalidated against this exact file inside the write's
    /// own transaction, the write is priced again from the live journal, and
    /// the capacity equation preserves every outstanding funded liability
    /// through the commit. There is no bankless path and no absence
    /// exemption.
    pub fn execute(&self, bank: &VerifiedProcessReturnBank) -> Result<(), ProcessError> {
        match self.execute_plan(bank) {
            Ok(outcome) => {
                *self
                    .outcome
                    .lock()
                    .map_err(|_| ProcessError::StorePoisoned)? = Some(outcome);
                Ok(())
            }
            Err(error) => {
                // The scope reports only its own refusal; the write's exact
                // error is kept so the caller observes the real fate.
                let reported = ProcessError::Conflict;
                *self
                    .failure
                    .lock()
                    .map_err(|_| ProcessError::StorePoisoned)? = Some(error);
                Err(reported)
            }
        }
    }

    fn execute_plan(
        &self,
        bank: &VerifiedProcessReturnBank,
    ) -> Result<Box<dyn std::any::Any + Send>, ProcessError> {
        self.with_store(|store| match &self.plan {
            CurrentWritePlan::CallAdmission {
                process_id,
                operation_key,
                request,
                binding_hash,
            } => store
                .admit_current_write(bank, process_id, operation_key, request, binding_hash)
                .map(|()| Box::new(()) as Box<dyn std::any::Any + Send>),
            CurrentWritePlan::Checkpoint {
                process_id,
                expected_revision,
                value,
            } => store
                .checkpoint_current_write(bank, process_id, *expected_revision, value.clone())
                .map(|checkpoint| Box::new(checkpoint) as Box<dyn std::any::Any + Send>),
            CurrentWritePlan::Startup => store
                .startup_current_write(bank)
                .map(|()| Box::new(()) as Box<dyn std::any::Any + Send>),
            CurrentWritePlan::Routed { describe, body } => {
                let body = body
                    .lock()
                    .map_err(|_| ProcessError::StorePoisoned)?
                    .take()
                    .ok_or(ProcessError::Conflict)?;
                store.run_current_write(bank, describe.as_ref(), body)
            }
        })
    }

    /// Run this write through the Kernel's original current-write scope. A
    /// refusal of the write itself returns its exact error; any other
    /// refusal is the native scope's.
    pub(crate) fn enforce(
        &self,
        enforcement: &NativeProcessCurrentWriteEnforcement,
    ) -> Result<(), ProcessError> {
        match enforcement.run(self) {
            Ok(()) => Ok(()),
            Err(scope) => Err(self
                .failure
                .lock()
                .map_err(|_| ProcessError::StorePoisoned)?
                .take()
                .unwrap_or_else(|| ProcessError::from(scope))),
        }
    }

    /// Stream every retained enrollment to the native whole-inverse verifier
    /// under the actual Process lock, in one read transaction that
    /// revalidates the exact inventory first. Every authenticated canonical
    /// account and its enrolled event coordinates flow to the callback one
    /// row at a time, including settled historical accounts; the returned
    /// count is the streamed total and must equal the inventory's account
    /// count. Read-only data inspection: no financial or invocation
    /// authority, no lifetime collection, no new state machine.
    pub fn verify_retained_enrollments(
        &self,
        inventory: &ProcessReturnInventoryDataV1,
        verify: impl FnMut(
            &chio_kernel::process_return_custody::ProcessReturnSourceDataV1,
            &chio_kernel::process_return_custody::ProcessReturnFundingDataV1,
            &str, // account digest
            u64,  // enrollment event sequence
            &str, // enrollment event digest
        )
            -> Result<(), chio_kernel::admission_operation::AdmissionOperationStoreError>,
    ) -> Result<u64, chio_kernel::admission_operation::AdmissionOperationStoreError> {
        let mut store = self.store.lock().map_err(|_| {
            chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
                "Process journal lock is poisoned".to_owned(),
            )
        })?;
        store.verify_retained_enrollments(inventory, verify)
    }

    fn with_store<T>(
        &self,
        operation: impl FnOnce(&mut Store) -> Result<T, ProcessError>,
    ) -> Result<T, ProcessError> {
        let mut store = self.store.lock().map_err(|_| ProcessError::StorePoisoned)?;
        operation(&mut store)
    }

    fn startup(store: Arc<Mutex<Store>>) -> Self {
        Self {
            store,
            plan: CurrentWritePlan::Startup,
            outcome: Mutex::new(None),
            failure: Mutex::new(None),
        }
    }

    fn routed<T: std::any::Any + Send>(
        store: Arc<Mutex<Store>>,
        describe: impl Fn(&rusqlite::Connection) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError>
            + Send
            + Sync
            + 'static,
        body: impl FnOnce(&Transaction<'_>) -> Result<T, ProcessError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            store,
            plan: CurrentWritePlan::Routed {
                describe: Box::new(describe),
                body: Mutex::new(Some(Box::new(move |tx: &Transaction<'_>| {
                    body(tx).map(|value| Box::new(value) as Box<dyn std::any::Any + Send>)
                }) as WriteBody)),
            },
            outcome: Mutex::new(None),
            failure: Mutex::new(None),
        }
    }

    /// Take the executed write's committed value exactly once after the
    /// Kernel scope returned. No value exists before a genuine commit.
    pub fn take_outcome<T: std::any::Any + Send>(&self) -> Result<T, ProcessError> {
        let value = self
            .outcome
            .lock()
            .map_err(|_| ProcessError::StorePoisoned)?
            .take()
            .ok_or(ProcessError::Conflict)?;
        let value = value.downcast::<T>().map_err(|_| ProcessError::Conflict)?;
        Ok(*value)
    }
}

impl ProcessRuntime {
    /// Price the admission of one logical call from its actual journal state
    /// and prepare its routed current write. Read-only; the caller must not
    /// hold the Process writer lock when handing this to the Kernel scope.
    pub fn prepare_native_current_call_admission(
        &self,
        process_id: &str,
        operation_key: &str,
        request: &chio_kernel::ToolCallRequest,
        binding_hash: &str,
    ) -> Result<ProcessNativeCurrentWrite, ProcessError> {
        self.with_store(|store| {
            store.prepare_call_admission(process_id, operation_key, request, binding_hash)
        })?;
        Ok(ProcessNativeCurrentWrite {
            store: self.store.clone(),
            plan: CurrentWritePlan::CallAdmission {
                process_id: process_id.to_owned(),
                operation_key: operation_key.to_owned(),
                request: request.clone(),
                binding_hash: binding_hash.to_owned(),
            },
            outcome: Mutex::new(None),
            failure: Mutex::new(None),
        })
    }

    /// Price one checkpoint transition from its actual journal row and
    /// prepare its routed current write. Read-only.
    pub fn prepare_native_current_checkpoint(
        &self,
        process_id: &str,
        expected_revision: u64,
        value: serde_json::Value,
    ) -> Result<ProcessNativeCurrentWrite, ProcessError> {
        self.with_store(|store| store.prepare_checkpoint(process_id, expected_revision))?;
        Ok(ProcessNativeCurrentWrite {
            store: self.store.clone(),
            plan: CurrentWritePlan::Checkpoint {
                process_id: process_id.to_owned(),
                expected_revision,
                value,
            },
            outcome: Mutex::new(None),
            failure: Mutex::new(None),
        })
    }

    /// Run one generic Process current write through the Kernel's original
    /// current-write scope. `describe` prices the actual complete rows from
    /// the live journal read-only inside the routed transaction; `body` is
    /// the existing write body, executed only after the minted bank proof is
    /// revalidated against this exact file and the physical capacity
    /// equation preserves every outstanding funded liability. No routed
    /// write bypasses enforcement, and no Process lock is held across the
    /// native scope.
    pub(crate) fn run_current_write<T: std::any::Any + Send>(
        &self,
        describe: impl Fn(&rusqlite::Connection) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError>
            + Send
            + Sync
            + 'static,
        body: impl FnOnce(&Transaction<'_>) -> Result<T, ProcessError> + Send + Sync + 'static,
    ) -> Result<T, ProcessError> {
        self.writer.run(describe, body)
    }
}

/// The owning handle of every write to one Process journal: the shared
/// store plus the Kernel's cloneable current-write enforcement of the same
/// durable runtime. The runtime and the registry hold the same writer, so a
/// registry without a Kernel reference preserves the same native bank before
/// it changes a row. It cannot construct a loan or choose a write price.
#[derive(Clone)]
pub(crate) struct CurrentWriter {
    store: Arc<Mutex<Store>>,
    enforcement: NativeProcessCurrentWriteEnforcement,
}

impl CurrentWriter {
    pub(crate) fn new(
        store: Arc<Mutex<Store>>,
        enforcement: NativeProcessCurrentWriteEnforcement,
    ) -> Self {
        Self { store, enforcement }
    }

    /// Run one priced, preconditioned write through the native scope. The
    /// caller must not hold the Process store lock.
    pub(crate) fn run<T: std::any::Any + Send>(
        &self,
        describe: impl Fn(&rusqlite::Connection) -> Result<Vec<ProcessReturnRowEnvelopeData>, ProcessError>
            + Send
            + Sync
            + 'static,
        body: impl FnOnce(&Transaction<'_>) -> Result<T, ProcessError> + Send + Sync + 'static,
    ) -> Result<T, ProcessError> {
        let write = ProcessNativeCurrentWrite::routed(self.store.clone(), describe, body);
        write.enforce(&self.enforcement)?;
        write.take_outcome::<T>()
    }

    /// Authenticate the journal against its native bank on every open. Ready
    /// journals remain read-only; the native owner may still need to confirm
    /// an enrollment committed just before a previous process stopped.
    pub(crate) fn complete_startup(&self) -> Result<(), ProcessError> {
        let write = ProcessNativeCurrentWrite::startup(self.store.clone());
        write.enforce(&self.enforcement)?;
        self.with_store(|store| {
            store.startup_complete();
            Ok(())
        })
    }

    /// Run a prepared admission or checkpoint plan.
    pub(crate) fn enforce(&self, write: &ProcessNativeCurrentWrite) -> Result<(), ProcessError> {
        write.enforce(&self.enforcement)
    }

    pub(crate) fn with_store<T>(
        &self,
        operation: impl FnOnce(&mut Store) -> Result<T, ProcessError>,
    ) -> Result<T, ProcessError> {
        let mut store = self.store.lock().map_err(|_| ProcessError::StorePoisoned)?;
        operation(&mut store)
    }
}
