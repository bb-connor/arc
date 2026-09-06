//! Durable agent process trees over Chio's existing admission coordinator.
//!
//! The core API is for trusted hosts. The optional `worker-server` feature
//! binds authenticated guests to process ids. The kernel remains responsible
//! for every tool dispatch, including recovery, budgets, guards and receipts.

#![forbid(unsafe_code)]

#[cfg(feature = "mailboxes")]
pub mod mailboxes;
mod registry;
mod store;
mod types;
#[cfg(feature = "worker-server")]
pub mod worker;

use std::path::Path;
use std::sync::{Arc, Mutex};

use chio_core_types::capability::attenuation::{scope_hash, validate_attenuation};
use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use chio_kernel::{ChioKernel, ToolCallRequest, ToolCallResponse, Verdict};
use serde::Serialize;
use serde_json::{json, Value};

pub use registry::{ChildSubmission, ChildWork, ProcessRegistry};
use store::Store;
pub use types::{
    Checkpoint, ProcessError, ProcessLimits, ProcessSnapshot, ProcessState, ProcessStateLimits,
    ProcessStorage, StateBlobRef, MAX_STATE_BLOB_BYTES, STATE_BLOB_PROTOCOL,
};

/// Dispatch attempts one logical operation may consume: the first, plus a bounded
/// number of fresh dispatches after the kernel reports an unknown outcome for a
/// tool declared free of side effects.
const MAX_DISPATCH_ATTEMPTS: u32 = 3;

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
        let registry = ProcessRegistry::open(path, &kernel)?;
        let namespace = registry.namespace.clone();
        Ok(Self {
            kernel,
            store: registry.store,
            namespace,
        })
    }

    pub fn registry(&self) -> ProcessRegistry {
        ProcessRegistry {
            store: self.store.clone(),
            namespace: self.namespace.clone(),
        }
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

    /// Store immutable, process-owned bytes. Identical content reuses its quota slot.
    pub fn put_blob(&self, id: &str, bytes: &[u8]) -> Result<StateBlobRef, ProcessError> {
        if bytes.len() > MAX_STATE_BLOB_BYTES {
            return Err(ProcessError::Invalid("state blob is too large"));
        }
        self.with_store(|store| store.put_blob(id, bytes))
    }

    /// Read only blobs owned by this running process, verifying their content hash.
    pub fn read_blob(&self, id: &str, sha256: &str) -> Result<Vec<u8>, ProcessError> {
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ProcessError::Invalid("invalid state blob digest"));
        }
        self.with_store(|store| store.read_blob(id, sha256))
    }

    /// Report immutable state capability, quotas and current process/tree usage.
    pub fn storage(&self, id: &str) -> Result<ProcessStorage, ProcessError> {
        self.with_store(|store| store.storage(id))
    }

    /// Stable request identity of a logical operation's first dispatch, scoped
    /// to the persistent runtime and process. Operation keys name logical
    /// effects (for example `publish-report`), not attempts. Changing arguments
    /// under the same key is rejected.
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

    /// Request identity of a later dispatch attempt. The first attempt keeps
    /// the original derivation so existing journals retain their identities.
    fn request_id_for_attempt(
        &self,
        process_id: &str,
        operation_key: &str,
        attempt: u32,
    ) -> Result<String, ProcessError> {
        if attempt <= 1 {
            return self.request_id(process_id, operation_key);
        }
        validate_id(process_id)?;
        validate_id(operation_key)?;
        Ok(format!(
            "process:{}",
            digest(&(&self.namespace, process_id, operation_key, attempt))?
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
        let attempt = self.with_store(|store| store.call_attempt(process_id, operation_key))?;
        Ok(ToolCallRequest {
            request_id: self.request_id_for_attempt(process_id, operation_key, attempt)?,
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
    /// the same kernel operation on restart; an unknown outcome stays
    /// fail-closed for every side-effecting tool. When the tool's server
    /// declares it free of side effects and the request carries no
    /// authorization artifact bound to its request id, the runtime records a
    /// further attempt and dispatches a fresh kernel operation, at most
    /// `MAX_DISPATCH_ATTEMPTS` times in total. The earlier unknown operation
    /// keeps its receipt in the kernel journal.
    ///
    /// Cancellation stops new admissions. Calls admitted before cancellation
    /// may finish their side effect; their output is withheld from the caller.
    pub async fn invoke(
        &self,
        process_id: &str,
        operation_key: &str,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, ProcessError> {
        let mut attempt = self.with_store(|store| store.call_attempt(process_id, operation_key))?;
        if request.request_id != self.request_id_for_attempt(process_id, operation_key, attempt)? {
            return Err(ProcessError::Invalid(
                "request id does not match the logical operation",
            ));
        }
        // Freeze the entire request, including signed authorization extensions,
        // under its first attempt's identity: every dispatch attempt of one key
        // carries the same content. Transport-specific refresh/rebinding is
        // deliberately not implicit.
        let mut binding = request.clone();
        binding.request_id = self.request_id(process_id, operation_key)?;
        let request_hash = digest(&binding)?;
        // Restore verified ancestor snapshots and budget-parent registrations
        // root-first. A child can run even if its parent has never invoked a
        // tool, including after the kernel's in-memory registry is recreated.
        let lineage = self.with_store(|store| store.lineage(process_id))?;
        for capability in &lineage {
            self.kernel.register_delegation_parent(capability)?;
        }
        self.with_store(|store| store.admit(process_id, operation_key, request, &request_hash))?;
        let mut current = request.clone();
        loop {
            let result = self
                .kernel
                .evaluate_tool_call_with_metadata(
                    &current,
                    Some(json!({
                        "chio_process": {"runtime_id": self.namespace, "process_id": process_id,
                            "operation_key": operation_key, "request_sha256": request_hash,
                            "attempt": attempt}
                    })),
                )
                .await;
            // Even an error can follow a committed side effect. Keep the operation
            // identity and call reservation forever; recovery belongs to the kernel.
            self.with_store(|store| store.require_running(process_id))?;
            let response = result?;
            if attempt >= MAX_DISPATCH_ATTEMPTS
                || !outcome_unknown(&response)
                || !self.redispatchable(&current)
            {
                return Ok(response);
            }
            attempt = self.with_store(|store| {
                store.advance_attempt(
                    process_id,
                    operation_key,
                    &request_hash,
                    attempt,
                    MAX_DISPATCH_ATTEMPTS,
                )
            })?;
            current.request_id = self.request_id_for_attempt(process_id, operation_key, attempt)?;
        }
    }

    /// A fresh dispatch is safe only for a tool its registered server declares
    /// free of side effects, and only when no authorization artifact in the
    /// request is bound to the request id that would change.
    fn redispatchable(&self, request: &ToolCallRequest) -> bool {
        self.kernel
            .tool_is_read_only(&request.server_id, &request.tool_name)
            && request.dpop_proof.is_none()
            && request.execution_nonce.is_none()
            && request.governed_intent.is_none()
            && request.approval_token.is_none()
            && request.approval_tokens.is_empty()
            && request.threshold_approval_proposal.is_none()
            && request.supplemental_authorization.is_none()
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

/// The kernel retains this operation as dispatched without a recorded outcome,
/// so the denial describes uncertainty rather than a policy decision.
fn outcome_unknown(response: &ToolCallResponse) -> bool {
    response.verdict == Verdict::Deny
        && response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.pointer("/admission_operation/retained_state"))
            .and_then(Value::as_str)
            == Some("outcome_unknown_after_dispatch")
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
