//! Model-free setup proves native custody and a fresh writer, without granting authority.
use super::{RecoveryRuntime, RecoveryRuntimeError};
use crate::knowledge::NativeKnowledgeRuntime;
use chio_core_types::{
    capability::token::CapabilityToken, recovery::*, Keypair, StoreMutationFence,
};
use chio_kernel::recovery::{
    AuthenticatedRecoveryActor, RecoveryAuthorityPort, RecoveryPermission,
};
use chio_security_types::recovery::*;
use chio_store_sqlite::admission_operation_store::{
    NativeSetupProbeEvidenceV1, SqliteAdmissionOperationStore,
};
use std::sync::Arc;
use std::{future::Future, pin::Pin};

type SetupFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RecoveryRuntimeError>> + Send + 'a>>;

#[cfg(test)]
mod error_categories;
mod transport;
#[cfg(test)]
pub(super) use transport::call_with_occupied_setup_capacity;
pub use transport::protected_recovery_router;
/// Trusted local host composition. It cannot be decoded from an agent request.
pub struct RecoverySetupHost {
    pub runtime: Arc<RecoveryRuntime>,
    pub store: Arc<SqliteAdmissionOperationStore>,
    pub fence: StoreMutationFence,
    pub knowledge: Option<Arc<NativeKnowledgeRuntime>>,
    pub operator: Keypair,
}
impl core::fmt::Debug for RecoverySetupHost {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoverySetupHost([redacted])")
    }
}
pub struct RecoverySetupService {
    runtime: Arc<RecoveryRuntime>,
    store: Arc<SqliteAdmissionOperationStore>,
    fence: StoreMutationFence,
    knowledge: Arc<NativeKnowledgeRuntime>,
    operator: Keypair,
    workflow: WorkflowId,
}
impl core::fmt::Debug for RecoverySetupService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoverySetupService([redacted])")
    }
}
impl RecoverySetupService {
    /// Operator-only bootstrap after initial installation, expiry or a profile
    /// reload. Pinning the exact self-test and its authorized creation is atomic.
    /// Every other workflow stays closed until benign/denied/restart qualification.
    pub fn for_creation<'a>(
        host: RecoverySetupHost,
        capability: &'a CapabilityToken,
        command: &'a RecoveryCommandV1,
    ) -> SetupFuture<'a, Self> {
        Box::pin(Self::for_creation_inner(host, capability, command))
    }
    async fn for_creation_inner(
        host: RecoverySetupHost,
        capability: &CapabilityToken,
        command: &RecoveryCommandV1,
    ) -> Result<Self, RecoveryRuntimeError> {
        let knowledge = host
            .knowledge
            .ok_or(RecoveryRuntimeError::UncoveredMediation)?;
        let selected = host
            .runtime
            .kernel
            .recovery_deployment(host.runtime.scope())
            .map_err(super::authentication_error)?;
        knowledge
            .validate_setup_binding(host.runtime.scope(), &selected.native_authority)
            .map_err(super::authentication_error)?;
        let actor = host
            .runtime
            .kernel
            .authenticate_recovery_actor(
                host.runtime.scope(),
                capability,
                RecoveryPermission::Create,
            )
            .map_err(super::authentication_error)?;
        let workflow = host
            .store
            .pin_setup_creation(
                &actor,
                command,
                chio_store_sqlite::admission_operation_store::NativeSetupCreationHost {
                    receipt_key: &host.runtime.kernel.receipt_signing_public_key(),
                    operator: &host.operator.public_key(),
                    process: &host.runtime.process,
                },
                &host.fence,
                now()?,
            )
            .map_err(super::native_store_errors::store_error)?;
        let service = Self::new(
            host.runtime,
            host.store,
            host.fence,
            Some(knowledge),
            host.operator,
            workflow,
        )?;
        service.runtime.execute_command(capability, command).await?;
        Ok(service)
    }
    pub fn workflow(&self) -> &WorkflowId {
        &self.workflow
    }
    /// Trusted host composition pins the exact unfinished self-test and all required mediators.
    pub fn new(
        runtime: Arc<RecoveryRuntime>,
        store: Arc<SqliteAdmissionOperationStore>,
        fence: StoreMutationFence,
        knowledge: Option<Arc<NativeKnowledgeRuntime>>,
        operator: Keypair,
        workflow: WorkflowId,
    ) -> Result<Self, RecoveryRuntimeError> {
        let knowledge = knowledge.ok_or(RecoveryRuntimeError::UncoveredMediation)?;
        let profile = store
            .deployment(runtime.scope(), &fence, now()?)
            .map_err(super::native_store_errors::store_error)?;
        let selected = runtime
            .kernel
            .recovery_deployment(runtime.scope())
            .map_err(super::authentication_error)?;
        if chio_core_types::canonical_json_bytes(&profile).map_err(refused)?
            != chio_core_types::canonical_json_bytes(&selected).map_err(refused)?
        {
            return Err(RecoveryRuntimeError::UnsupportedProfile);
        }
        knowledge
            .validate_setup_binding(runtime.scope(), &profile.native_authority)
            .map_err(super::authentication_error)?;
        store
            .configure_protected_setup(
                runtime.scope(),
                &workflow,
                &runtime.kernel.receipt_signing_public_key(),
                &operator.public_key(),
                &fence,
                now()?,
            )
            .map_err(super::native_store_errors::store_error)?;
        if let Some(existing) = runtime.protected_mediator.get() {
            if !existing.same_setup_mediator(&knowledge).map_err(refused)? {
                return Err(RecoveryRuntimeError::UnsupportedProfile);
            }
        } else {
            runtime
                .protected_mediator
                .set(knowledge.clone())
                .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?;
        }
        Ok(Self {
            runtime,
            store,
            fence,
            knowledge,
            operator,
            workflow,
        })
    }
    fn actor(
        &self,
        capability: &CapabilityToken,
    ) -> Result<AuthenticatedRecoveryActor, RecoveryRuntimeError> {
        let profile = self
            .store
            .deployment(self.runtime.scope(), &self.fence, now()?)
            .map_err(super::native_store_errors::store_error)?;
        self.knowledge
            .validate_setup_binding(self.runtime.scope(), &profile.native_authority)
            .map_err(super::authentication_error)?;
        self.runtime
            .kernel
            .authenticate_recovery_actor(
                self.runtime.scope(),
                capability,
                RecoveryPermission::Inspect,
            )
            .map_err(super::authentication_error)
    }
    async fn benign(
        &self,
        capability: &CapabilityToken,
        command: &RecoveryCommandV1,
    ) -> Result<chio_core_types::receipt::body::ChioReceipt, RecoveryRuntimeError> {
        let result = self.runtime.execute_command(capability, command).await?;
        let receipt = result
            .original_response
            .ok_or(RecoveryRuntimeError::Unavailable)?
            .receipt;
        if !receipt.is_allowed() || !receipt.verify_signature().map_err(refused)? {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        Ok(receipt)
    }
    /// Keep the native effect driver off caller stacks, including HTTP workers.
    pub fn probe<'a>(
        &'a self,
        capability: &'a CapabilityToken,
        workflow: &'a WorkflowId,
    ) -> SetupFuture<'a, SignedRecoverySetupProbeV1> {
        Box::pin(self.probe_inner(capability, workflow))
    }
    async fn probe_inner(
        &self,
        capability: &CapabilityToken,
        workflow: &WorkflowId,
    ) -> Result<SignedRecoverySetupProbeV1, RecoveryRuntimeError> {
        if workflow != &self.workflow {
            return Err(RecoveryRuntimeError::InvalidCommand);
        }
        let actor = self.actor(capability)?;
        let preparation = self
            .store
            .setup_preparation(&actor, &self.fence, now()?)
            .map_err(preparation_error)?;
        if let Some(probe) = preparation.signed_probe {
            return Ok(probe);
        }
        let benign = Box::pin(self.benign(capability, &preparation.command)).await?;
        let record = self
            .runtime
            .kernel
            .read_recovery_workflow(&actor, workflow)
            .map_err(super::authentication_error)?;
        let mut denied_request = record.seed;
        denied_request.request_id = preparation.probe.denied_command.as_str().into();
        denied_request.declassification_grant = None;
        denied_request.execution_nonce = None;
        let current = self
            .runtime
            .kernel
            .recovery_deployment(self.runtime.scope())
            .map_err(super::authentication_error)?;
        // Select only the current mutable observation from the original
        // fenced native authority. Stable caller and isolation identity stay
        // unchanged, and the native input writer still checks freshness.
        let denied_context = self
            .runtime
            .kernel
            .refresh_native_security_context(&current.security_context)
            .map_err(super::authentication_error)?;
        let denied = Box::pin(
            self.runtime
                .kernel
                .evaluate_tool_call_with_security_context(&denied_request, &denied_context),
        )
        .await
        .map_err(super::authentication_error)?;
        if !denied.receipt.is_denied() {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        let signed =
            SignedRecoverySetupProbeV1::sign(preparation.probe, &self.operator).map_err(refused)?;
        self.store
            .commit_setup_probe(
                &actor,
                &NativeSetupProbeEvidenceV1 {
                    probe: &signed,
                    benign: &benign,
                    denied_request: &denied_request,
                    denied: &denied.receipt,
                },
                &self.fence,
                now()?,
            )
            .map_err(super::native_store_errors::store_error)
    }
    pub fn qualify<'a>(
        &'a self,
        capability: &'a CapabilityToken,
        probe: &'a SignedRecoverySetupProbeV1,
    ) -> SetupFuture<'a, SignedRecoverySetupReportV1> {
        Box::pin(self.qualify_inner(capability, probe))
    }
    async fn qualify_inner(
        &self,
        capability: &CapabilityToken,
        probe: &SignedRecoverySetupProbeV1,
    ) -> Result<SignedRecoverySetupReportV1, RecoveryRuntimeError> {
        let actor = self.actor(capability)?;
        let preparation = self
            .store
            .setup_preparation(&actor, &self.fence, now()?)
            .map_err(preparation_error)?;
        if preparation.signed_probe.as_ref() != Some(probe) {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        let current_fence = SourceDigest::from_bytes(
            chio_kernel::recovery::recovery_digest(RecoveryDigestDomain::ServingFence, &self.fence)
                .map_err(refused)?,
        );
        if current_fence == preparation.previous_serving_fence {
            return Err(RecoveryRuntimeError::RestartRequired);
        }
        if let Some(report) = preparation.report {
            if report.body().current_serving_fence == current_fence {
                return self
                    .store
                    .accept_setup_report(&report, &self.fence, now()?)
                    .map_err(super::native_store_errors::store_error);
            }
        }
        let benign = self
            .runtime
            .kernel
            .replay_recovery_result(&actor, &self.workflow)
            .map_err(super::authentication_error)?
            .receipt;
        let body = self
            .store
            .prepare_setup_report(&actor, probe, &benign, &self.fence, now()?)
            .map_err(super::native_store_errors::store_error)?;
        let signed = SignedRecoverySetupReportV1::sign(body, &self.operator).map_err(refused)?;
        self.store
            .accept_setup_report(&signed, &self.fence, now()?)
            .map_err(super::native_store_errors::store_error)
    }
}
fn preparation_error(
    error: chio_store_sqlite::admission_operation_store::NativeSetupPreparationError,
) -> RecoveryRuntimeError {
    use chio_store_sqlite::admission_operation_store::NativeSetupPreparationError;
    match error {
        NativeSetupPreparationError::Expired => RecoveryRuntimeError::ProbeExpired,
        NativeSetupPreparationError::WriterChanged => RecoveryRuntimeError::RestartRequired,
        NativeSetupPreparationError::StaleSource => RecoveryRuntimeError::Conflict,
        NativeSetupPreparationError::Store(error) => super::native_store_errors::store_error(error),
    }
}
fn refused(_: impl core::fmt::Display) -> RecoveryRuntimeError {
    RecoveryRuntimeError::Unavailable
}
fn now() -> Result<u64, RecoveryRuntimeError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(refused)?
        .as_millis()
        .try_into()
        .map_err(refused)
}
