//! Process-table operations for trusted native services without retaining a kernel Arc.

use std::path::Path;
use std::sync::{Arc, Mutex};

use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::crypto::Keypair;
use chio_kernel::admission_operation::DurableAdmissionMode;
use chio_kernel::{ChioKernel, ToolInvocationContext};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::native_return_custody::CurrentWriter;
use crate::store::Store;
use crate::{ProcessError, ProcessSnapshot};

/// Shared process-table handle. It cannot execute tools or reconcile kernel admission.
#[derive(Clone)]
pub struct ProcessRegistry {
    pub(crate) store: Arc<Mutex<Store>>,
    pub(crate) writer: CurrentWriter,
    pub(crate) namespace: String,
    pub(crate) enforcement: chio_kernel::knowledge::DurableKnowledgeEnforcement,
}

/// Committed child work. Executable selection remains with the trusted host.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildWork {
    pub process: String,
    pub parent: String,
    pub template: String,
    pub input: Value,
}

/// One coherent snapshot of a parent's durable worker join.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerWait {
    pub children: Vec<String>,
    /// Await terminal outcomes, including failures, instead of successful completion.
    pub settled: bool,
}

/// A native spawn's guarded input and kernel-selected identity.
pub struct ChildSubmission<'a> {
    pub context: &'a ToolInvocationContext,
    pub template: &'a str,
    pub input: &'a Value,
    pub budget_share_bps: u16,
    /// Host-selected ceiling for dynamic workers in this pinned run profile.
    pub max_submissions: u32,
}

impl ProcessRegistry {
    /// Open the same qualified process table used by ProcessRuntime. Native
    /// services keep this handle instead of creating a kernel reference cycle.
    pub fn open(path: impl AsRef<Path>, kernel: &ChioKernel) -> Result<Self, ProcessError> {
        if kernel.durable_admission_mode() != DurableAdmissionMode::All {
            return Err(ProcessError::Configuration(
                "durable admission mode must be all",
            ));
        }
        let authority =
            kernel
                .durable_admission_store_uuid()
                .ok_or(ProcessError::Configuration(
                    "a qualified durable admission store is required",
                ))?;
        let kernel_key = kernel.public_key().to_hex();
        let store = Store::open(path.as_ref(), authority, &kernel_key)?;
        let enforcement = kernel.durable_knowledge_enforcement()?;
        let namespace = store.namespace.clone();
        let store = Arc::new(Mutex::new(store));
        // Every write to this journal, including its open-time layout
        // installation and knowledge activation, runs through the Kernel's
        // current-write scope of the same durable runtime.
        let writer = CurrentWriter::new(
            store.clone(),
            kernel.original_process_current_write_enforcement()?,
        );
        writer.complete_startup()?;
        if enforcement.enforced(&namespace)? {
            writer.activate_knowledge()?;
        }
        Ok(Self {
            store,
            writer,
            namespace,
            enforcement,
        })
    }

    /// Persistent namespace shared with authenticated worker request identities.
    pub fn runtime_id(&self) -> &str {
        &self.namespace
    }

    pub fn process(&self, id: &str) -> Result<ProcessSnapshot, ProcessError> {
        self.with_public_store(|store| store.public_process(id))
    }

    /// Install private subject keys for an explicitly enabled native delegation
    /// service. Existing key bindings cannot change. Never expose them to guests.
    pub fn provision_signers(&self, keys: &[(String, &Keypair)]) -> Result<(), ProcessError> {
        self.writer.provision_signers(keys)
    }

    /// Use a persisted process key inside the trusted host. The callback is
    /// never exposed through the worker protocol and grants no dispatch right.
    pub fn with_process_signer<T>(
        &self,
        process: &str,
        sign: impl FnOnce(&CapabilityToken, &Keypair) -> T,
    ) -> Result<T, ProcessError> {
        self.with_store(|store| store.with_process_signer(process, sign))
    }

    /// Resolve an admitted call to exactly one live persisted process.
    pub fn caller(&self, context: &ToolInvocationContext) -> Result<ProcessSnapshot, ProcessError> {
        self.with_public_store(|store| {
            let process = store.caller(context)?;
            store.public_process(&process.id)
        })
    }

    fn with_public_store<T>(
        &self,
        read: impl FnOnce(&mut Store) -> Result<T, ProcessError>,
    ) -> Result<T, ProcessError> {
        if self.enforcement.enforced(&self.namespace)? {
            self.writer.activate_knowledge()?;
        }
        self.with_store(read)
    }

    /// Commit a signed child, its key and work binding in one transaction.
    /// Issuance must use the supplied parent and subject keys and the host's
    /// selected scope. The existing child-attachment checks remain mandatory.
    pub fn submit_child(
        &self,
        submission: ChildSubmission<'_>,
        issue: impl FnOnce(
            &CapabilityToken,
            &Keypair,
            &Keypair,
        ) -> Result<CapabilityToken, ProcessError>,
    ) -> Result<ChildWork, ProcessError> {
        self.writer.submit_child(submission, issue)
    }

    pub fn child_work(&self) -> Result<Vec<ChildWork>, ProcessError> {
        self.with_store(|store| store.child_work())
    }

    pub fn worker_waits(
        &self,
    ) -> Result<std::collections::BTreeMap<String, Vec<String>>, ProcessError> {
        self.with_store(|store| store.worker_waits())
    }

    /// Read a parent's child list and join mode in the same SQLite snapshot.
    pub fn worker_wait(&self, process_id: &str) -> Result<Option<WorkerWait>, ProcessError> {
        self.with_store(|store| store.worker_wait(process_id))
    }

    /// Record a direct-child terminal join. The host must validate scheduling and
    /// opt-in supervision authority; this store does not own worker exit outcomes.
    pub fn wait_for_settled_children(
        &self,
        context: &ToolInvocationContext,
        children: &[String],
        validate: impl FnOnce(
            &str,
            &std::collections::BTreeMap<String, Vec<String>>,
        ) -> Result<(), ProcessError>,
    ) -> Result<String, ProcessError> {
        self.writer
            .wait_for_settled_children(context, children, validate)
    }

    /// Record direct-child dependencies after host validation of the complete
    /// proposed wait graph. Validation and cancellation serialize with this write.
    pub fn wait_for_children(
        &self,
        context: &ToolInvocationContext,
        children: &[String],
        validate: impl FnOnce(
            &str,
            &std::collections::BTreeMap<String, Vec<String>>,
        ) -> Result<(), ProcessError>,
    ) -> Result<String, ProcessError> {
        self.writer.wait_for_children(context, children, validate)
    }

    fn with_store<T>(
        &self,
        operation: impl FnOnce(&mut Store) -> Result<T, ProcessError>,
    ) -> Result<T, ProcessError> {
        let mut store = self.store.lock().map_err(|_| ProcessError::StorePoisoned)?;
        operation(&mut store)
    }
}
