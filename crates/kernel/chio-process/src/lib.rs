//! Durable agent process trees over Chio's existing admission coordinator.
//!
//! The core API is for trusted hosts. The optional `worker-server` feature
//! binds authenticated guests to process ids. The kernel remains responsible
//! for every tool dispatch, including recovery, budgets, guards and receipts.

#![forbid(unsafe_code)]

mod store;
mod types;
#[cfg(feature = "worker-server")]
pub mod worker;

use std::path::Path;
use std::sync::{Arc, Mutex};

use chio_core_types::capability::attenuation::{scope_hash, validate_attenuation};
use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use chio_kernel::admission_operation::DurableAdmissionMode;
use chio_kernel::{ChioKernel, ToolCallRequest, ToolCallResponse};
use serde::Serialize;
use serde_json::{json, Value};

use store::Store;
pub use types::{Checkpoint, ProcessError, ProcessLimits, ProcessSnapshot, ProcessState};

/// A persistent process namespace bound to one durable kernel authority.
/// Clones share a connection; separate opens serialize mutations in SQLite.
#[derive(Clone)]
pub struct ProcessRuntime {
    kernel: Arc<ChioKernel>,
    store: Arc<Mutex<Store>>,
    namespace: String,
}

impl ProcessRuntime {
    /// Open a process journal. The containing directory must be private to the
    /// trusted host: it stores capabilities and agent checkpoints.
    /// All calls, including reads, must use durable kernel admission.
    pub fn open(path: impl AsRef<Path>, kernel: Arc<ChioKernel>) -> Result<Self, ProcessError> {
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
        let store = Store::open(path.as_ref(), authority, &kernel.public_key().to_hex())?;
        let namespace = store.namespace.clone();
        Ok(Self {
            kernel,
            store: Arc::new(Mutex::new(store)),
            namespace,
        })
    }

    /// Register a root with a fixed capability and a tree-wide call ceiling.
    /// Repeating the same registration is idempotent; rebinding is rejected.
    pub fn create_root(
        &self,
        id: &str,
        capability: &CapabilityToken,
        limits: ProcessLimits,
    ) -> Result<ProcessSnapshot, ProcessError> {
        validate_id(id)?;
        limits.validate()?;
        verify_capability(capability)?;
        if !capability.delegation_chain.is_empty() {
            return Err(ProcessError::Invalid(
                "a root process requires a root capability",
            ));
        }
        self.with_store(|store| store.create_root(id, capability, limits))
    }

    /// Attach a child using a capability already issued by the authority.
    /// It must extend this parent's signed delegation chain by exactly one hop,
    /// retain its issuer and budget family, and narrow scope and validity.
    pub fn spawn(
        &self,
        parent_id: &str,
        child_id: &str,
        capability: &CapabilityToken,
    ) -> Result<ProcessSnapshot, ProcessError> {
        validate_id(child_id)?;
        verify_capability(capability)?;
        self.with_store(|store| store.spawn(parent_id, child_id, capability, validate_child))
    }

    pub fn process(&self, id: &str) -> Result<ProcessSnapshot, ProcessError> {
        self.with_store(|store| store.process(id))
    }

    /// Stable request identity, scoped to the persistent runtime and process.
    /// Operation keys name logical effects (for example `publish-report`), not
    /// attempts. Changing arguments under the same key is rejected.
    pub fn request_id(
        &self,
        process_id: &str,
        operation_key: &str,
    ) -> Result<String, ProcessError> {
        validate_id(process_id)?;
        validate_id(operation_key)?;
        Ok(format!(
            "process:{}",
            digest(&(&self.namespace, process_id, operation_key))?
        ))
    }

    /// Construct a kernel request with the process's persisted capability.
    /// Hosts may attach DPoP or governed authorization before invoking it.
    pub fn tool_request(
        &self,
        process_id: &str,
        operation_key: &str,
        server_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> Result<ToolCallRequest, ProcessError> {
        let process = self.process(process_id)?;
        Ok(ToolCallRequest {
            request_id: self.request_id(process_id, operation_key)?,
            agent_id: process.capability.subject.to_hex(),
            capability: process.capability,
            server_id: server_id.to_owned(),
            tool_name: tool_name.to_owned(),
            arguments,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
    }

    /// Admit or recover a logical tool call through the kernel. No tool output
    /// cache bypasses the admission coordinator. A crash after dispatch uses
    /// the same kernel operation on restart; unknown outcomes stay fail-closed.
    ///
    /// Cancellation stops new admissions. Calls admitted before cancellation
    /// may finish their side effect; their output is withheld from the caller.
    pub async fn invoke(
        &self,
        process_id: &str,
        operation_key: &str,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, ProcessError> {
        if request.request_id != self.request_id(process_id, operation_key)? {
            return Err(ProcessError::Invalid(
                "request id does not match the logical operation",
            ));
        }
        // Freeze the entire request, including signed authorization extensions.
        // Transport-specific refresh/rebinding is deliberately not implicit.
        let request_hash = digest(request)?;
        // Restore verified ancestor snapshots and budget-parent registrations
        // root-first. A child can run even if its parent has never invoked a
        // tool, including after the kernel's in-memory registry is recreated.
        let lineage = self.with_store(|store| store.lineage(process_id))?;
        for capability in &lineage {
            self.kernel.register_delegation_parent(capability)?;
        }
        self.with_store(|store| store.admit(process_id, operation_key, request, &request_hash))?;
        let result = self
            .kernel
            .evaluate_tool_call_with_metadata(
                request,
                Some(json!({
                    "chio_process": {"runtime_id": self.namespace, "process_id": process_id,
                        "operation_key": operation_key, "request_sha256": request_hash}
                })),
            )
            .await;
        // Even an error can follow a committed side effect. Keep the operation
        // identity and call reservation forever; recovery belongs to the kernel.
        self.with_store(|store| store.require_running(process_id))?;
        Ok(result?)
    }

    /// Compare-and-swap checkpoint. Returns the new revision. Competing
    /// workers cannot silently overwrite one another's progress.
    pub fn checkpoint(
        &self,
        process_id: &str,
        expected_revision: u64,
        value: Value,
    ) -> Result<Checkpoint, ProcessError> {
        let bytes = canonical_json_bytes(&value)?;
        if bytes.len() > 1_048_576 {
            return Err(ProcessError::Invalid("checkpoint exceeds one MiB"));
        }
        self.with_store(|store| store.checkpoint(process_id, expected_revision, value))
    }

    /// Permanently stop admissions and checkpoints for this process and every
    /// descendant. It does not undo tool effects already admitted.
    pub fn cancel(&self, process_id: &str) -> Result<usize, ProcessError> {
        self.with_store(|store| store.cancel(process_id))
    }

    fn with_store<T>(
        &self,
        f: impl FnOnce(&mut Store) -> Result<T, ProcessError>,
    ) -> Result<T, ProcessError> {
        let mut store = self.store.lock().map_err(|_| ProcessError::StorePoisoned)?;
        f(&mut store)
    }
}

fn digest(value: &impl Serialize) -> Result<String, ProcessError> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

fn validate_id(id: &str) -> Result<(), ProcessError> {
    if id.is_empty() || id.len() > 256 || id.trim() != id || id.chars().any(char::is_control) {
        return Err(ProcessError::Invalid(
            "identifiers must be 1..256 bytes without edge whitespace or control characters",
        ));
    }
    Ok(())
}

fn verify_capability(capability: &CapabilityToken) -> Result<(), ProcessError> {
    capability.validate_schema()?;
    if !capability.verify_signature()? {
        return Err(ProcessError::Invalid("invalid capability signature"));
    }
    Ok(())
}

fn validate_child(parent: &CapabilityToken, child: &CapabilityToken) -> Result<(), ProcessError> {
    validate_attenuation(&parent.scope, &child.scope)?;
    if child.issuer != parent.issuer
        || child.issued_at < parent.issued_at
        || child.expires_at > parent.expires_at
        || child.issued_at >= child.expires_at
        || digest(&child.aggregate_invocation_budget)?
            != digest(&parent.aggregate_invocation_budget)?
        || child.budget_share_bps.unwrap_or(10_000) > parent.budget_share_bps.unwrap_or(10_000)
        || child.delegation_chain.len() != parent.delegation_chain.len() + 1
    {
        return Err(ProcessError::Invalid(
            "child capability widens or changes its parent authority",
        ));
    }
    let (link, prefix) = child
        .delegation_chain
        .split_last()
        .ok_or(ProcessError::Invalid("missing delegation hop"))?;
    if digest(&prefix)? != digest(&parent.delegation_chain)?
        || link.capability_id != parent.id
        || link.delegator != parent.subject
        || link.delegatee != child.subject
        || link.scope_hash.as_ref() != Some(&scope_hash(&parent.scope)?)
        || !link.verify_signature()?
    {
        return Err(ProcessError::Invalid(
            "child is not a signed direct delegation of this parent",
        ));
    }
    Ok(())
}
