//! Durable agent process trees over Chio's existing admission coordinator.
//!
//! The core API is for trusted hosts. The optional `worker-server` feature
//! binds authenticated guests to process ids. The kernel remains responsible
//! for every tool dispatch, including recovery, budgets, guards and receipts.

#![forbid(unsafe_code)]

mod binding;
#[cfg(test)]
mod integrity_tests;
#[cfg(feature = "mailboxes")]
pub mod mailboxes;
pub mod native_return_custody;
mod recovery;
mod registry;
pub use recovery::{
    ClosedUnusedRecoveryReservation, RecoveryCallReservation, UnusedRecoveryReservationClosureData,
};
#[cfg(feature = "admission-test-support")]
#[doc(hidden)]
pub mod admission_test_support;
mod routes;
mod security;
mod state_reader;
mod store;
mod types;
#[cfg(feature = "worker-server")]
pub mod worker;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use chio_core_types::capability::attenuation::{scope_hash, validate_attenuation};
use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use chio_kernel::{ChioKernel, ToolCallRequest, ToolCallResponse, Verdict};
use serde::Serialize;
use serde_json::{json, Value};

pub use registry::{ChildSubmission, ChildWork, ProcessRegistry, WorkerWait};
pub use routes::{ProcessLaunchReceipt, ProcessRoute};
pub use security::ProcessSecurityProfile;
pub use state_reader::ProcessStateReader;
use store::Store;
pub use types::{
    Checkpoint, ProcessError, ProcessLimits, ProcessSnapshot, ProcessState, ProcessStateLimits,
    ProcessStorage, StateBlobRef, MAX_STATE_BLOB_BYTES, STATE_BLOB_PROTOCOL,
};

/// The process ABI this crate and the hosts built on it speak. It names one
/// compatibility contract over every durable and wire surface an application
/// or a host depends on: the process journal schema and its checkpoint and
/// blob bounds, the worker protocol and its bootstrap and connection
/// descriptors, the host configuration, run plan, status, log and report
/// documents, and the relocation manifest. A host records the ABI it was
/// initialized under and refuses to serve, run or import state recorded under
/// another; an incompatible change to any covered surface is a new ABI.
pub const PROCESS_ABI: &str = "chio.process.abi.v3";

/// Dispatch attempts one logical operation may consume: the first, plus a bounded
/// number of fresh dispatches after the kernel reports an unknown outcome for a
/// tool classified by the kernel as read-only and free of stateful authority.
/// Retained-response verifiers must use this same bound when checking attempts.
pub const MAX_DISPATCH_ATTEMPTS: u32 = 3;

/// Test-only acknowledgement boundaries. Production builds have no observer.
#[cfg(feature = "admission-test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryProcessTestCutpoint {
    NativeFinishingPrepared,
    NativeFinishingEnrolled,
    NativeNonceIssued,
    ProcessNonceRetained,
}

/// A persistent process namespace bound to one durable kernel authority.
/// Clones share a connection; separate opens serialize mutations in SQLite.
#[derive(Clone)]
pub struct ProcessRuntime {
    kernel: Arc<ChioKernel>,
    store: Arc<Mutex<Store>>,
    writer: native_return_custody::CurrentWriter,
    original_snapshot: Arc<store::OriginalProcessSnapshot>,
    namespace: String,
    enforcement: chio_kernel::knowledge::DurableKnowledgeEnforcement,
    routes: Arc<BTreeMap<String, ProcessRoute>>,
    launch_receipts: Arc<BTreeMap<String, ProcessLaunchReceipt>>,
    security_profile: Option<ProcessSecurityProfile>,
    supplemental_route: Option<(String, String)>,
    #[cfg(feature = "admission-test-support")]
    recovery_test_cutpoint: Option<Arc<dyn Fn(RecoveryProcessTestCutpoint) + Send + Sync>>,
}

impl ProcessRuntime {
    /// Open a process journal. The containing directory must be private to the
    /// trusted host: it stores capabilities and agent checkpoints.
    /// Tool dispatch, including read-only tools, uses durable kernel admission.
    pub fn open(path: impl AsRef<Path>, kernel: Arc<ChioKernel>) -> Result<Self, ProcessError> {
        let registry = ProcessRegistry::open(path, &kernel)?;
        let namespace = registry.namespace.clone();
        let original_snapshot = {
            let authority =
                kernel
                    .durable_admission_store_uuid()
                    .ok_or(ProcessError::Configuration(
                        "a qualified durable admission store is required",
                    ))?;
            let store = registry
                .store
                .lock()
                .map_err(|_| ProcessError::StorePoisoned)?;
            Arc::new(store.original_snapshot(authority, &kernel.public_key().to_hex()))
        };
        let runtime = Self {
            kernel,
            store: registry.store,
            writer: registry.writer,
            original_snapshot,
            namespace,
            enforcement: registry.enforcement,
            routes: Arc::new(BTreeMap::new()),
            launch_receipts: Arc::new(BTreeMap::new()),
            security_profile: None,
            supplemental_route: None,
            #[cfg(feature = "admission-test-support")]
            recovery_test_cutpoint: None,
        };
        // Restore settled native owed work before any liveness is served:
        // retained custody and reconciliation never need a new authorized
        // invoke. Per-account proof unavailability leaves the debt open.
        runtime.reconcile_retained_native_returns()?;
        Ok(runtime)
    }

    #[cfg(feature = "admission-test-support")]
    #[must_use]
    pub fn with_recovery_test_cutpoint(
        mut self,
        observer: Arc<dyn Fn(RecoveryProcessTestCutpoint) + Send + Sync>,
    ) -> Self {
        self.recovery_test_cutpoint = Some(observer);
        self
    }

    /// Install the host's persistent flow identity. Its digest is part of
    /// every operation binding, so changing or removing it cannot recover an
    /// already admitted call under another tenant or isolation generation.
    pub fn with_security_profile(
        mut self,
        profile: ProcessSecurityProfile,
    ) -> Result<Self, ProcessError> {
        profile.validate()?;
        self.security_profile = Some(profile);
        Ok(self)
    }

    /// Present the exact signed argument envelope to the kernel's independently
    /// installed supplemental verifier on this selected route. This conveys no
    /// authority by itself; malformed or unsigned envelopes still fail there.
    pub fn with_supplemental_authorization_route(
        mut self,
        server: String,
        tool: String,
    ) -> Result<Self, ProcessError> {
        validate_id(&server)?;
        validate_id(&tool)?;
        self.supplemental_route = Some((server, tool));
        Ok(self)
    }

    /// Install the trusted host's route for each registered tool server.
    ///
    /// The host must derive these selections from its actual connections. The
    /// kernel still verifies signed route authority; this API grants none.
    /// Each routed operation freezes the selected route in its existing journal
    /// binding. Reopening with a changed or missing route cannot redirect or
    /// recover that operation. Unrouted legacy operations keep their binding.
    pub fn with_routes(
        mut self,
        routes: impl IntoIterator<Item = (String, ProcessRoute)>,
    ) -> Result<Self, ProcessError> {
        let mut selected = BTreeMap::new();
        for (server_id, route) in routes {
            validate_id(&server_id)?;
            if selected.insert(server_id, route).is_some() {
                return Err(ProcessError::Configuration("duplicate host process route"));
            }
        }
        self.routes = Arc::new(selected);
        Ok(self)
    }

    pub fn registry(&self) -> ProcessRegistry {
        ProcessRegistry {
            store: self.store.clone(),
            writer: self.writer.clone(),
            namespace: self.namespace.clone(),
            enforcement: self.enforcement.clone(),
        }
    }

    /// Attach the launch receipts verified by the trusted host for its actual
    /// connections. Workers cannot select these observations. A restarted tool
    /// has a new launch receipt, while recovery returns the original call's
    /// receipt unchanged. Launch observations do not alter logical call identity.
    pub fn with_launch_receipts(
        mut self,
        receipts: impl IntoIterator<Item = (String, ProcessLaunchReceipt)>,
    ) -> Result<Self, ProcessError> {
        let mut selected = BTreeMap::new();
        for (server_id, receipt) in receipts {
            validate_id(&server_id)?;
            if selected.insert(server_id, receipt).is_some() {
                return Err(ProcessError::Configuration("duplicate host launch receipt"));
            }
        }
        self.launch_receipts = Arc::new(selected);
        Ok(self)
    }

    /// Persistent namespace used to bind logical operation and receipt identities.
    pub fn runtime_id(&self) -> &str {
        &self.namespace
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
        // Route the root registration through the kernel's original
        // current-write scope so the native bank proof and physical capacity
        // are preserved before the row changes.
        let routed_id = id.to_owned();
        let routed_capability = capability.clone();
        self.run_current_write(
            move |_| store::native_return_custody::price_new_process_rows(),
            move |tx| {
                store::create_root_call(tx, &routed_id, &routed_capability, limits)?;
                Ok(())
            },
        )?;
        self.with_public_store(|store| store.public_process(id))
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
        let (parent, lineage) =
            self.with_store(|store| Ok((store.process(parent_id)?, store.lineage(parent_id)?)))?;
        self.enforcement.verify_confined_attachment(
            chio_kernel::admission_operation::ConfinedProcessAttachment {
                runtime: &self.namespace,
                root_process: &parent.root_id,
                parent_process: parent_id,
                child_process: child_id,
                parent_lineage: &lineage,
                child_capability: capability,
            },
        )?;
        // Route the child attachment through the kernel's original
        // current-write scope so the native bank proof and physical capacity
        // are preserved before the row changes.
        let routed_parent = parent_id.to_owned();
        let routed_child = child_id.to_owned();
        let routed_capability = capability.clone();
        self.run_current_write(
            move |_| store::native_return_custody::price_new_process_rows(),
            move |tx| {
                store::attach_child(
                    tx,
                    &routed_parent,
                    &routed_child,
                    &routed_capability,
                    validate_child,
                )?;
                Ok(())
            },
        )?;
        self.with_public_store(|store| store.public_process(child_id))
    }

    pub fn process(&self, id: &str) -> Result<ProcessSnapshot, ProcessError> {
        self.with_public_store(|store| store.public_process(id))
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

    /// Store immutable, process-owned bytes. Identical content reuses its quota slot.
    pub fn put_blob(&self, id: &str, bytes: &[u8]) -> Result<StateBlobRef, ProcessError> {
        if bytes.len() > MAX_STATE_BLOB_BYTES {
            return Err(ProcessError::Invalid("state blob is too large"));
        }
        self.require_raw_knowledge()?;
        self.with_store(|store| store.require_raw_knowledge())?;
        // Route the insert through the kernel's original current-write scope
        // so the native bank proof and physical capacity are preserved.
        let routed_id = id.to_owned();
        let routed_bytes = bytes.to_vec();
        self.run_current_write(
            move |_| store::native_return_custody::price_state_blob_rows(),
            move |tx| store::put_blob_call(tx, &routed_id, &routed_bytes),
        )
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
        self.with_store(|store| {
            self.require_raw_knowledge()?;
            store.require_raw_knowledge()?;
            store.read_blob(id, sha256)
        })
    }

    /// Report immutable state capability, quotas and current process/tree usage.
    pub fn storage(&self, id: &str) -> Result<ProcessStorage, ProcessError> {
        self.with_store(|store| {
            self.require_raw_knowledge()?;
            store.require_raw_knowledge()?;
            store.storage(id)
        })
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
        let supplemental_authorization = if self
            .supplemental_route
            .as_ref()
            .is_some_and(|(server, tool)| server == server_id && tool == tool_name)
        {
            Some(serde_json::from_value(json!({
                "signed_extension": String::from_utf8(canonical_json_bytes(&arguments)?).map_err(|_| ProcessError::Invalid("supplemental authorization is not UTF-8"))?,
            }))?)
        } else {
            None
        };
        Ok(ToolCallRequest {
            request_id: self.request_id_for_attempt(process_id, operation_key, attempt)?,
            agent_id: process.capability.subject.to_hex(),
            capability: process.capability,
            server_id: server_id.to_owned(),
            tool_name: tool_name.to_owned(),
            arguments,
            dpop_proof: None,
            execution_nonce: None,
            declassification_grant: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
    }

    /// Admit or recover a logical tool call through the kernel. No tool output
    /// cache bypasses the admission coordinator. A crash after dispatch uses
    /// the same kernel operation on restart; an unknown outcome stays
    /// fail-closed for every side-effecting tool. When the tool's server
    /// declares it free of side effects and the kernel excludes all matching
    /// stateful authority and request-id-bound artifacts, the runtime records a
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
        self.invoke_with_recovery(process_id, operation_key, request, false)
            .await
    }

    /// Dispatch a new logical operation or replay its completed outcome, but
    /// never redispatch an unknown outcome, even for a read-only tool. The
    /// stricter policy is bound durably to the operation key and cannot be
    /// changed when the caller retries it.
    pub async fn invoke_known_only(
        &self,
        process_id: &str,
        operation_key: &str,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, ProcessError> {
        self.invoke_with_recovery(process_id, operation_key, request, true)
            .await
    }

    async fn invoke_with_recovery(
        &self,
        process_id: &str,
        operation_key: &str,
        request: &ToolCallRequest,
        known_outcome_only: bool,
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
        let binding::ProcessCallBinding {
            request_hash,
            binding_hash,
        } = self.derive_call_binding(process_id, operation_key, request, known_outcome_only)?;
        let route = self.routes.get(&request.server_id);
        // Validate the persisted process identity and immutable request binding
        // before any kernel receipt attributes this attempt to the process,
        // and route the admission through the kernel's original current-write
        // scope so the native bank proof and physical capacity are preserved
        // for this file and the same volume before any Process row changes.
        // The Process writer lock is not held across the native scope.
        {
            let admission = self.prepare_native_current_call_admission(
                process_id,
                operation_key,
                request,
                &binding_hash,
            )?;
            self.writer.enforce(&admission)?;
        }
        // Restore verified ancestor snapshots and budget-parent registrations
        // root-first. A child can run even if its parent has never invoked a
        // tool, including after the kernel's in-memory registry is recreated.
        let (process, lineage) =
            self.with_store(|store| Ok((store.process(process_id)?, store.lineage(process_id)?)))?;
        let ordinary_context = self
            .security_profile
            .as_ref()
            .map(|profile| {
                let root = lineage
                    .first()
                    .ok_or(ProcessError::Invalid("missing process lineage"))?;
                profile.context(
                    &self.namespace,
                    request.capability.subject.to_hex(),
                    &root.id,
                )
            })
            .transpose()?;
        let security_context = self
            .enforcement
            .confined_context(&self.namespace, &process.root_id, &process.id, &lineage)?
            .or(ordinary_context);
        let mut ancestor_refusal = None;
        for capability in lineage.iter().take(lineage.len().saturating_sub(1)) {
            if let Err(error) = self.kernel.register_delegation_parent(capability) {
                match error {
                    chio_kernel::KernelError::GuardDenied(_)
                    | chio_kernel::KernelError::CapabilityRevoked(_)
                    | chio_kernel::KernelError::DelegationChainRevoked(_)
                    | chio_kernel::KernelError::DelegationInvalid(_)
                    | chio_kernel::KernelError::SubjectMismatch { .. } => {
                        ancestor_refusal = Some(error.to_string());
                        break;
                    }
                    // Storage, unknown outcomes and infrastructure failures retain
                    // their owning error. Incomplete ancestry never reaches dispatch.
                    _ => return Err(error.into()),
                }
            }
        }
        let mut current = request.clone();
        // One concrete finishing source per attempt: each attempt is its own
        // original native operation with its own Process account.
        let mut native_source: Option<native_return_custody::ProcessNativeFinishingSource> = None;
        loop {
            if current.execution_nonce.is_none() && self.kernel.execution_nonce_required() {
                current.execution_nonce = self
                    .with_store(|store| store.retained_nonce(process_id, operation_key, attempt))?;
            }
            let mut attribution = json!({
                "chio_process": {"runtime_id": self.namespace, "process_id": process_id,
                    "operation_key": operation_key, "request_sha256": request_hash,
                    "attempt": attempt}
            });
            if known_outcome_only {
                attribution["chio_process"]["recovery_policy"] = json!("known_outcome_only");
            }
            if let Some(route) = route {
                attribution["route"] = serde_json::to_value(route)?;
            }
            if let Some(receipt) = self.launch_receipts.get(&request.server_id) {
                attribution["native_launch"] = serde_json::to_value(receipt)?;
            }
            // Keep the kernel evaluation frame out of every enclosing worker
            // future. Durable nonce verification adds a deep synchronous path;
            // embedding its state inline can exhaust ordinary executor stacks.
            let result = if let Some(reason) = &ancestor_refusal {
                self.kernel
                    .sign_planned_deny_response(&current, reason, Some(attribution))
            } else if let Some(context) = &security_context {
                let context = self.kernel.refresh_native_security_context(context)?;
                if native_source.is_none() && self.kernel.native_output_retention_is_selected() {
                    let mut original = request.clone();
                    original.request_id = current.request_id.clone();
                    native_source = Some(self.native_finishing_source(
                        process_id,
                        operation_key,
                        &original,
                        known_outcome_only,
                        Some(&context),
                    )?);
                }
                match &native_source {
                    Some(source) => {
                        Box::pin(
                            self.kernel
                                .evaluate_tool_call_with_metadata_and_native_finishing_provider(
                                    &current,
                                    Some(attribution),
                                    &context,
                                    source,
                                ),
                        )
                        .await
                    }
                    None => {
                        Box::pin(
                            self.kernel
                                .evaluate_tool_call_with_metadata_and_security_context(
                                    &current,
                                    Some(attribution),
                                    &context,
                                ),
                        )
                        .await
                    }
                }
            } else {
                Box::pin(
                    self.kernel
                        .evaluate_tool_call_with_metadata(&current, Some(attribution)),
                )
                .await
            };
            // Strict nonce preflight: no effect has happened yet, so no custody
            // is due. Retain the original issuance and dispatch once more.
            #[cfg(feature = "admission-test-support")]
            eprintln!(
                "native Process evaluation: {:?}",
                result.as_ref().map(|response| (
                    response.verdict,
                    response.output.is_some(),
                    response.execution_nonce.is_some(),
                    &response.terminal_state,
                    &response.reason,
                    response
                        .receipt
                        .metadata
                        .as_ref()
                        .and_then(|m| m.get("admission_operation"))
                ))
            );
            let result = match result {
                Ok(response)
                    if self.kernel.execution_nonce_required()
                        && current.execution_nonce.is_none()
                        && response.verdict == Verdict::Allow
                        && response.output.is_none() =>
                {
                    let mut response = response;
                    let nonce = response
                        .execution_nonce
                        .take()
                        .ok_or(ProcessError::Invalid(
                            "strict nonce preflight returned no execution nonce",
                        ))?;
                    #[cfg(feature = "admission-test-support")]
                    if let Some(observer) = &self.recovery_test_cutpoint {
                        observer(RecoveryProcessTestCutpoint::NativeNonceIssued);
                    }
                    // Save the original issuance before dispatch, inside the
                    // kernel's original current-write scope so the native
                    // bank proof and physical capacity are preserved. A
                    // restart can only re-present this nonce to the original
                    // admission authority.
                    {
                        let routed_process = process_id.to_owned();
                        let routed_operation = operation_key.to_owned();
                        let routed_binding = binding_hash.clone();
                        let routed_nonce = (*nonce).clone();
                        self.run_current_write(
                            move |_| store::native_return_custody::price_original_nonce_rows(),
                            move |tx| {
                                store::retain_nonce_call(
                                    tx,
                                    &routed_process,
                                    &routed_operation,
                                    attempt,
                                    &routed_binding,
                                    &routed_nonce,
                                )
                            },
                        )
                        .map_err(|error| {
                            #[cfg(feature = "admission-test-support")]
                            eprintln!("native Process nonce current write: {error:?}");
                            error
                        })?;
                    }
                    if let Some(source) = &native_source {
                        if source.has_account()? {
                            self.retain_original_native_nonce(source).map_err(|error| {
                                #[cfg(feature = "admission-test-support")]
                                eprintln!("native Process nonce custody: {error:?}");
                                error
                            })?;
                        }
                    }
                    #[cfg(feature = "admission-test-support")]
                    if let Some(observer) = &self.recovery_test_cutpoint {
                        observer(RecoveryProcessTestCutpoint::ProcessNonceRetained);
                    }
                    current.execution_nonce = Some(*nonce);
                    continue;
                }
                result => result,
            };
            // Even an error can follow a committed side effect, and a
            // terminal or captured native fate outranks present-time Process
            // liveness and any returned Kernel error: retain the account's
            // custody and its reconciliation before either is consulted. The
            // operation identity and call reservation are kept forever;
            // recovery belongs to the kernel.
            let unknown = match &result {
                Ok(response) => outcome_unknown(response),
                Err(_) => true,
            };
            #[cfg(feature = "admission-test-support")]
            if let Err(error) = &result {
                eprintln!("native Process Kernel result before custody: {error:?}");
            }
            if let Some(source) = &native_source {
                if source.has_account()? {
                    if unknown {
                        self.retain_original_native_uncertainty(source)
                            .map_err(|error| {
                                #[cfg(feature = "admission-test-support")]
                                eprintln!("native Process unavailable custody: {error:?}");
                                error
                            })?;
                        if result.is_ok() {
                            // A verified typed Unknown response names the
                            // immutable native terminal. It may prove no future
                            // raw return without claiming a known external effect.
                            // The native owner must mint that exact fate before
                            // any finishing reserve can be released.
                            self.finish_original_native_return(source)?;
                        }
                    } else {
                        self.finish_original_native_return(source)
                            .map_err(|error| {
                                #[cfg(feature = "admission-test-support")]
                                eprintln!("native Process terminal custody: {error:?}");
                                error
                            })?;
                    }
                }
            }
            self.with_store(|store| store.require_running(process_id))?;
            let mut response = result?;
            // Returning historical nonce material never grants a new dispatch.
            // In particular an unknown outcome still returns its signed refusal.
            if response.execution_nonce.is_none() {
                response.execution_nonce = current.execution_nonce.clone().map(Box::new);
            }
            if attempt >= MAX_DISPATCH_ATTEMPTS
                || known_outcome_only
                || !unknown
                || !self.kernel.can_redispatch_unknown_read(&current)
            {
                return Ok(response);
            }
            native_source = None;
            // The attempt advance runs inside the kernel's original
            // current-write scope so the native bank proof and physical
            // capacity are preserved before the journal moves ahead of the
            // kernel.
            {
                let routed_process = process_id.to_owned();
                let routed_operation = operation_key.to_owned();
                let routed_binding = binding_hash.clone();
                let priced = (
                    routed_process.clone(),
                    routed_operation.clone(),
                    routed_binding.clone(),
                );
                let expected_attempt = attempt;
                attempt = self.run_current_write(
                    move |tx| {
                        store::native_return_custody::price_attempt_advance_rows(
                            tx,
                            &priced.0,
                            &priced.1,
                            &priced.2,
                            expected_attempt,
                        )
                    },
                    move |tx| {
                        store::advance_attempt_call(
                            tx,
                            &routed_process,
                            &routed_operation,
                            &routed_binding,
                            expected_attempt,
                            MAX_DISPATCH_ATTEMPTS,
                        )
                    },
                )?;
            }
            current.request_id = self.request_id_for_attempt(process_id, operation_key, attempt)?;
        }
    }

    /// Compare-and-swap checkpoint. Returns the new revision. Competing
    /// workers cannot silently overwrite one another's progress. The write
    /// runs inside the kernel's original current-write scope so the native
    /// bank proof and physical capacity are preserved before the row changes.
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
        self.require_raw_knowledge()?;
        self.with_store(|store| store.require_raw_knowledge())?;
        let write = self.prepare_native_current_checkpoint(process_id, expected_revision, value)?;
        self.writer.enforce(&write)?;
        write.take_outcome::<Checkpoint>()
    }

    /// Permanently stop admissions and checkpoints for this process and every
    /// descendant. It does not undo tool effects already admitted. The
    /// recursive state rewrite runs inside the kernel's original
    /// current-write scope so the native bank proof and physical capacity
    /// are preserved, keeping the original commit-then-report semantics for
    /// an ordered confined return.
    pub fn cancel(&self, process_id: &str) -> Result<usize, ProcessError> {
        let routed_id = process_id.to_owned();
        let priced_id = routed_id.clone();
        let (count, ordered) = self.run_current_write(
            move |tx| store::native_return_custody::price_cancel_rows(tx, &priced_id),
            move |tx| store::cancel_call(tx, &routed_id),
        )?;
        if ordered {
            return Err(ProcessError::ConfinedReturnAlreadyOrdered);
        }
        Ok(count)
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
    if response.verdict != Verdict::Deny {
        return false;
    }
    let Some(metadata) = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("admission_operation"))
    else {
        return false;
    };
    // Old thin or unrecognized markers remain signed evidence, but cannot
    // authorize fresh dispatch. Never rewrite their bytes into the new schema.
    let Ok(projection) = serde_json::from_value::<
        chio_kernel::admission_operation::AdmissionReceiptMetadataV1,
    >(metadata.clone()) else {
        return false;
    };
    projection.projected_state
        == chio_kernel::admission_operation::AdmissionOperationState::OutcomeUnknownAfterDispatch
        && projection.request_id.as_str() == response.request_id
        && projection.retained_dispatch_commit.is_some()
        && projection.tool_outcome_id.is_none()
        && projection.tool_outcome_version.is_none()
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
    if !parent.scope.authorizes_delegation() {
        return Err(ProcessError::Invalid("parent lacks delegation authority"));
    }
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

mod knowledge;
pub use knowledge::ProcessArtifactBroker;
