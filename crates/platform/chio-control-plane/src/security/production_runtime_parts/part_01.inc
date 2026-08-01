use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chio_core::canonical_json_bytes;
use chio_core::capability::caveat::CapabilitySecurityBinding;
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::{sha256_hex, PublicKey, SigningBackend};
use chio_core::receipt::security::ActiveDefensePolicyBinding;
use chio_core::session::{OperationContext, ToolCallOperation};
use chio_data_guards::{RegexClassificationRule, RegexStructuredClassifier};
use chio_decoy::{
    DecoyDetector, PrivateDecoyRegistry, PrivilegedExportCredential, RegistryError,
    RegistryExportAuthorizer, RegistryExportGrant, RegistryKey, RegistryKeyProvider,
    TrustedWatermarkKey, WatermarkKeyResolver, WatermarkKeyStatus, WatermarkSourceContext,
    WatermarkSourceContextResolver, WatermarkVerifier, WatermarkVerifierDependencies,
    MAX_IJSON_INTEGER,
};
use chio_flow::{CategoryLabelMap, DeclassificationDispatchOutcome, FlowDenial};
use chio_kernel::security_admission_operation::AdmissionOperationStore;
use chio_kernel::approval::ApprovalStore;
use chio_kernel::budget_store::BudgetStore;
use chio_kernel::{
    ActiveResponseCommittedDispatch, ActiveResponseExecutionEvidence,
    ActiveResponseExecutionRequest,
    ActiveResponseExecutorAuthority, ActiveResponseExecutorAuthorityIdentity,
    ActiveResponseExecutorError, ActiveResponsePolicyRequest, ActiveResponsePolicyResolutionError,
    ActiveResponseRequirement, AutomaticActiveResponseDispatchFenceOutcome, ChioKernel, Guard,
    GuardContext, GuardDecision,
    IndexedSecurityEvidenceStore, KernelError, PostInvocationContext, PostInvocationHook,
    PostInvocationInspection,
    PostInvocationVerdict, SecurityInvocationContext, SecurityInvocationContextAuthority,
    SecurityInvocationContextV1, SecurityRequestLifecyclePermit,
};
use chio_quarantine::CausalBlastRadiusResolver;
use chio_security_kernel::{
    ContainmentGuard, DecoyTripwireDetectorPort, EngineFlowPostInvocationPort,
    FlowDispatchOutcomeRecorder, FlowPostInvocationHook, FlowPostInvocationResolver,
    FlowPreDispatchHook, FlowPreDispatchInput, FlowPreDispatchPort, FlowPreInvocationGuard,
    FlowPreInvocationPort, MissingContextPolicy, RawOutputTripwireHook, SecurityClock,
    SessionThrottleGuard, SystemSecurityClock, TripwireEventPublisher, TripwireGuard,
};
use chio_security_types::ports::{
    BlastRadiusPort, ClassificationPort, ClassifierId, ClassifierVersion, ContainmentOverlayStore,
    DeclassificationEvidenceCommitStore, ExactSecurityReceiptSink, FlowJoinRequest, FlowStateKey,
    FlowStateSnapshot, FlowStateStore, IsolationEpochId, LeaseOwnerId, LineageId, PortError,
    PortResult, PreparedActiveResponseDispatchBinding, ProducerId, RecordId, SchedulerHealthPort,
    SecurityReceiptSink, SessionId,
    SessionThrottleStore, TenantId, TripwireDetectorPort,
};
use chio_security_types::{
    InformationLabel, PrincipalId, ResponseApprovalRequirement, ResponseEffectKind, ResponsePlan,
};
use chio_siem::{Alert, AlertBackend, ExportError};
use chio_store_sqlite::security_state::{
    SecurityStateLifecycleOwnerProof, SqliteSecurityStateStore,
};
use chio_store_sqlite::{
    SqliteSecurityAdmissionOperationStore, SqliteApprovalStore, SqliteReceiptStore,
    SqliteSealedDecoyRegistryStore,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::active_response::DurableActiveResponseExecutor;
use super::adapters::effect_port::ActiveResponseEffectPort;
use super::adapters::{
    AlertOutboxConfig, FlowResolverConfig, PersistentFlowResolver, SqliteSiemOutbox,
    StructuredClassificationAdapter,
};
use super::broker::BrokerIntegrationError;
use super::broker_composition::RetainedSecurityStateLifecycleLease;
use super::event_consumer::{
    AttestedFindingResponseCoordinator, AttestedFindingResponsePolicyPlanner,
    KernelAttestedFindingResponseCoordinator, NativeSecurityEventVerifier,
    TrustedSecurityEventProducer, VerifiedSecurityEventIngress,
};
use super::orchestration::{
    ProductionActiveDefenseConfig, ProductionActiveDefenseHostConfig,
    ProductionDeclassificationReceiptLifecycle, ProductionDispatchRecorderLease,
    ProductionRuntimeLease, ProductionSecurityStateAuthority,
    ProductionSecurityStateLifecycleOwner,
};
use super::runtime::{
    SecurityDurability, SecurityRuntime, SecurityRuntimeAuthorityBundleBuilder,
    SecurityRuntimeParts,
};
use super::scheduler_worker::{ProductionResponseWorkerLoopConfig, ResponseWorkerTickError};

const REGISTRY_ENCRYPTION_DOMAIN: &[u8] = b"chio.production-decoy-encryption.v1\0";
const REGISTRY_INDEX_DOMAIN: &[u8] = b"chio.production-decoy-index.v1\0";
const RUNTIME_ADMISSION_CLOSED_REASON: &str = "production security runtime admission is closed";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionClassificationRuleConfig {
    pub category: String,
    pub expression: String,
    pub confidence_basis_points: u16,
    pub label: InformationLabel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionTrustedWatermarkKeyConfig {
    pub tenant_id: String,
    pub key_id: String,
    pub public_key: PublicKey,
    pub status: WatermarkKeyStatus,
    pub not_before_unix_ms: u64,
    pub signing_cutoff_unix_ms: u64,
    pub verify_until_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionWatermarkSourceContextConfig {
    pub tenant_id: String,
    pub application_id: String,
    pub session_id: String,
    pub source_receipt_id: String,
    pub tool_id: String,
    pub issued_at_unix_ms: u64,
    pub not_after_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionSecurityRuntimeFileConfig {
    pub security_state_database_path: PathBuf,
    pub decoy_registry_database_path: PathBuf,
    pub approval_database_path: PathBuf,
    pub alert_outbox_database_path: PathBuf,
    pub alert_archive_path: PathBuf,
    pub classifier_id: String,
    pub classifier_version: String,
    pub classification_rules: Vec<ProductionClassificationRuleConfig>,
    pub operator_input_floor: InformationLabel,
    pub trusted_declassification_authorities: BTreeMap<String, PublicKey>,
    pub trusted_watermark_keys: Vec<ProductionTrustedWatermarkKeyConfig>,
    pub trusted_watermark_source_contexts: Vec<ProductionWatermarkSourceContextConfig>,
    pub flow_fence_ttl_ms: u64,
    pub tripwire_producer_id: String,
    pub tripwire_producer_key_id: String,
    pub tripwire_policy_version: String,
    pub tripwire_max_event_age_ms: u64,
    pub tripwire_max_future_skew_ms: u64,
    pub active_response_executor_generation: u64,
    /// Stable across restarts and unique among simultaneously live executor workers.
    pub active_response_executor_lease_owner_id: String,
    pub active_response_execution_lease_ms: u64,
    pub active_response_policy_version: String,
    pub active_response_approval_policy_id: String,
    pub active_response_allowed_effects: BTreeSet<ResponseEffectKind>,
    pub active_response_automatic_ttl_ceiling_ms: u64,
    pub active_response_max_finding_age_ms: u64,
}

pub(super) struct ProductionSecurityRuntimeFactoryConfig {
    pub(super) runtime: ProductionSecurityRuntimeFileConfig,
    pub(super) admission_operation_database_path: PathBuf,
    pub(super) budget_database_path: PathBuf,
    pub(super) native_receipt_database_path: PathBuf,
    pub(super) tripwire_tenant_id: TenantId,
}

pub(super) struct ProductionSecurityRuntimeFactory {
    security_state_authority: ProductionSecurityStateAuthority,
    security_store: Arc<SqliteSecurityStateStore>,
    admission_operation_store: Arc<SqliteSecurityAdmissionOperationStore>,
    approval_store: Arc<SqliteApprovalStore>,
    budget_store: Arc<dyn BudgetStore>,
    receipt_store: Arc<SqliteReceiptStore>,
    classifier: Arc<dyn ClassificationPort>,
    flow_config: FlowResolverConfig,
    declassification_lifecycle: Mutex<Option<ProductionDeclassificationReceiptLifecycle>>,
    active_response_coordinator:
        Mutex<Option<Arc<KernelAttestedFindingResponseCoordinator>>>,
    tripwire_detector: Arc<dyn TripwireDetectorPort>,
    tripwire_producer_id: ProducerId,
    tripwire_producer_key_id: RecordId,
    tripwire_policy_version: RecordId,
    tripwire_tenant_id: TenantId,
    tripwire_max_event_age_ms: u64,
    tripwire_max_future_skew_ms: u64,
    alert_outbox: Arc<SqliteSiemOutbox>,
    blast_radius: Arc<dyn BlastRadiusPort>,
    effects: Arc<ActiveResponseEffectPort>,
    clock: Arc<dyn SecurityClock>,
    executor_generation: u64,
    executor_lease_owner_id: LeaseOwnerId,
    executor_lease_ms: u64,
    response_policy_version: RecordId,
    response_approval_policy_id: RecordId,
    response_allowed_effects: BTreeSet<ResponseEffectKind>,
    response_automatic_ttl_ceiling_ms: u64,
    response_max_finding_age_ms: u64,
}

struct RetainedProductionSecurityStateLifecycleOwner {
    path_custody: Arc<RetainedSecurityStateLifecycleLease>,
    store: Arc<SqliteSecurityStateStore>,
    proof: SecurityStateLifecycleOwnerProof,
}

impl ProductionSecurityStateLifecycleOwner for RetainedProductionSecurityStateLifecycleOwner {
    fn ensure_owned(&self) -> Result<(), ResponseWorkerTickError> {
        self.path_custody
            .ensure_owned()
            .map_err(|_| ResponseWorkerTickError::Port(PortError::integrity_failure()))
    }

    fn reset_for_startup_takeover(&self) -> Result<(), ResponseWorkerTickError> {
        self.ensure_owned()?;
        self.store
            .reset_declassification_lifecycle_for_owner_takeover(&self.proof)?;
        self.ensure_owned()
    }
}

impl ProductionSecurityStateAuthority {
    #[cfg(test)]
    pub(crate) fn open_with_trusted_clock(
        path: impl AsRef<Path>,
        clock: Arc<dyn chio_store_sqlite::security_state::SecurityStateClock>,
    ) -> Result<Self, BrokerIntegrationError> {
        open_security_state_store_with_lifecycle_lease_and_clock(path.as_ref(), clock)
    }
}

struct RetainedProductionRuntimeLeaseGuard {
    inner: Box<dyn Guard>,
    lease: ProductionRuntimeLease,
}

impl RetainedProductionRuntimeLeaseGuard {
    fn new(inner: Box<dyn Guard>, lease: ProductionRuntimeLease) -> Self {
        Self { inner, lease }
    }
}

impl Guard for RetainedProductionRuntimeLeaseGuard {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn evaluate(&self, context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        if !self.lease.admission_is_open() {
            return Err(KernelError::GuardDenied(
                RUNTIME_ADMISSION_CLOSED_REASON.to_string(),
            ));
        }
        let decision = self.inner.evaluate(context)?;
        if !self.lease.admission_is_open() {
            return Err(KernelError::GuardDenied(
                RUNTIME_ADMISSION_CLOSED_REASON.to_string(),
            ));
        }
        Ok(decision)
    }
}

struct LifecycleCheckedProductionGuard {
    inner: Box<dyn Guard>,
    lifecycle: ProductionDeclassificationReceiptLifecycle,
}

impl LifecycleCheckedProductionGuard {
    fn new(inner: Box<dyn Guard>, lifecycle: ProductionDeclassificationReceiptLifecycle) -> Self {
        Self { inner, lifecycle }
    }
}

impl Guard for LifecycleCheckedProductionGuard {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn evaluate(&self, context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        self.lifecycle
            .ensure_runtime_admission_open()
            .map_err(|_| KernelError::GuardDenied(RUNTIME_ADMISSION_CLOSED_REASON.to_string()))?;
        let decision = self.inner.evaluate(context)?;
        self.lifecycle
            .ensure_runtime_admission_open()
            .map_err(|_| KernelError::GuardDenied(RUNTIME_ADMISSION_CLOSED_REASON.to_string()))?;
        Ok(decision)
    }
}

struct LeasedProductionFlowPreDispatchPort {
    inner: Arc<dyn FlowPreDispatchPort>,
    lifecycle: ProductionDeclassificationReceiptLifecycle,
}

impl LeasedProductionFlowPreDispatchPort {
    fn new(
        inner: Arc<dyn FlowPreDispatchPort>,
        lifecycle: ProductionDeclassificationReceiptLifecycle,
    ) -> Self {
        Self { inner, lifecycle }
    }
}

impl FlowPreDispatchPort for LeasedProductionFlowPreDispatchPort {
    fn acquire_request_lifecycle(
        &self,
        input: &FlowPreDispatchInput<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, FlowDenial> {
        let lease = self
            .lifecycle
            .acquire_dispatch_recorder_lease()
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
        let inner = self.inner.acquire_request_lifecycle(input)?;
        if self.lifecycle.ensure_runtime_admission_open().is_err() {
            drop(inner);
            drop(lease);
            return Err(FlowDenial::DeclassificationStoreFailure);
        }
        Ok(Some(Box::new(ProductionSecurityRequestLifecyclePermit {
            inner,
            lease,
        })))
    }

    fn commit(
        &self,
        input: &FlowPreDispatchInput<'_>,
    ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial> {
        let lease = self
            .lifecycle
            .acquire_dispatch_recorder_lease()
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
        let recorder = match self.inner.commit(input) {
            Ok(recorder) => recorder,
            Err(error) => {
                if input.request.declassification_grant.is_some() {
                    let _ = self.lifecycle.close_runtime_admission();
                }
                drop(lease);
                return Err(error);
            }
        };
        if self.lifecycle.ensure_runtime_admission_open().is_err() {
            let record_result = match recorder {
                Some(mut recorder) => {
                    recorder.record(DeclassificationDispatchOutcome::DispatchFailed)
                }
                None => Ok(()),
            };
            drop(lease);
            record_result?;
            return Err(FlowDenial::DeclassificationStoreFailure);
        }
        Ok(recorder.map(|inner| {
            Box::new(LeasedProductionFlowDispatchOutcomeRecorder {
                inner,
                lease: Some(lease),
                lifecycle: self.lifecycle.clone(),
            }) as Box<dyn FlowDispatchOutcomeRecorder>
        }))
    }
}

struct ProductionSecurityRequestLifecyclePermit {
    inner: Option<Box<dyn SecurityRequestLifecyclePermit>>,
    lease: ProductionDispatchRecorderLease,
}

impl SecurityRequestLifecyclePermit for ProductionSecurityRequestLifecyclePermit {
    fn ensure_final_release(self: Box<Self>) -> Result<(), KernelError> {
        let Self { inner, lease } = *self;
        if let Some(inner) = inner {
            inner.ensure_final_release()?;
        }
        lease
            .consume_final_release()
            .map_err(|_| KernelError::GuardDenied(RUNTIME_ADMISSION_CLOSED_REASON.to_string()))
    }
}

struct LeasedProductionFlowDispatchOutcomeRecorder {
    inner: Box<dyn FlowDispatchOutcomeRecorder>,
    lease: Option<ProductionDispatchRecorderLease>,
    lifecycle: ProductionDeclassificationReceiptLifecycle,
}

impl FlowDispatchOutcomeRecorder for LeasedProductionFlowDispatchOutcomeRecorder {
    fn record(&mut self, outcome: DeclassificationDispatchOutcome) -> Result<(), FlowDenial> {
        if let Err(error) = self.inner.record(outcome) {
            let _ = self.lifecycle.close_runtime_admission();
            return Err(error);
        }
        self.lease = None;
        Ok(())
    }
}

struct LifecycleCheckedProductionActiveResponseExecutorAuthority {
    inner: Arc<dyn ActiveResponseExecutorAuthority>,
    lifecycle: ProductionDeclassificationReceiptLifecycle,
    identity: ActiveResponseExecutorAuthorityIdentity,
}

impl LifecycleCheckedProductionActiveResponseExecutorAuthority {
    fn new(
        inner: Arc<dyn ActiveResponseExecutorAuthority>,
        lifecycle: ProductionDeclassificationReceiptLifecycle,
    ) -> Self {
        let identity = inner.identity();
        Self {
            inner,
            lifecycle,
            identity,
        }
    }

    fn ensure_lifecycle_ready(&self) -> Result<(), ActiveResponseExecutorError> {
        self.lifecycle.ensure_runtime_admission_open().map_err(|_| {
            ActiveResponseExecutorError::NotReady(RUNTIME_ADMISSION_CLOSED_REASON.to_string())
        })
    }

    fn ensure_identity_exact(&self) -> Result<(), ActiveResponseExecutorError> {
        if self.inner.identity() == self.identity {
            Ok(())
        } else {
            Err(ActiveResponseExecutorError::NotReady(
                "production active-response executor identity changed".to_string(),
            ))
        }
    }

    fn execute_with_lifecycle<T>(
        &self,
        execute: impl FnOnce(
            &dyn ActiveResponseExecutorAuthority,
        ) -> Result<T, ActiveResponseExecutorError>,
    ) -> Result<T, ActiveResponseExecutorError> {
        let _operation_lease = self.lifecycle.acquire_consumer_lease().map_err(|_| {
            ActiveResponseExecutorError::RejectedBeforeCommit(
                RUNTIME_ADMISSION_CLOSED_REASON.to_string(),
            )
        })?;
        self.ensure_identity_exact().map_err(|error| {
            ActiveResponseExecutorError::RejectedBeforeCommit(error.to_string())
        })?;
        self.inner.ensure_ready()?;
        self.ensure_identity_exact().map_err(|error| {
            ActiveResponseExecutorError::RejectedBeforeCommit(error.to_string())
        })?;
        self.ensure_lifecycle_ready().map_err(|error| {
            ActiveResponseExecutorError::RejectedBeforeCommit(error.to_string())
        })?;

        let result = execute(self.inner.as_ref());
        let lifecycle_ready = self.ensure_lifecycle_ready().is_ok();
        let executor_ready = self.inner.ensure_ready().is_ok();
        let identity_exact = self.inner.identity() == self.identity;
        if !lifecycle_ready || !executor_ready || !identity_exact {
            return Err(ActiveResponseExecutorError::OutcomeUnknown(
                "production active-response lifecycle changed during execution".to_string(),
            ));
        }
        result
    }
}

impl ActiveResponseExecutorAuthority for LifecycleCheckedProductionActiveResponseExecutorAuthority {
    fn identity(&self) -> ActiveResponseExecutorAuthorityIdentity {
        self.identity.clone()
    }

    fn ensure_ready(&self) -> Result<(), ActiveResponseExecutorError> {
        self.ensure_lifecycle_ready()?;
        self.ensure_identity_exact()?;
        self.inner.ensure_ready()?;
        self.ensure_identity_exact()?;
        self.ensure_lifecycle_ready()
    }

    fn load_committed_active_response_dispatch(
        &self,
        tenant_id: &TenantId,
        dispatch_id: &RecordId,
    ) -> Result<Option<ActiveResponseCommittedDispatch>, ActiveResponseExecutorError> {
        self.execute_with_lifecycle(|inner| {
            inner.load_committed_active_response_dispatch(tenant_id, dispatch_id)
        })
    }

    fn fence_uncommitted_automatic_dispatch(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<AutomaticActiveResponseDispatchFenceOutcome, ActiveResponseExecutorError> {
        self.execute_with_lifecycle(|inner| {
            inner.fence_uncommitted_automatic_dispatch(response_plan, binding)
        })
    }

    fn execute_active_response(
        &self,
        request: &ActiveResponseExecutionRequest,
    ) -> Result<ActiveResponseExecutionEvidence, ActiveResponseExecutorError> {
        self.execute_with_lifecycle(|inner| inner.execute_active_response(request))
    }
}

struct LifecycleCheckedProductionPostInvocationHook {
    inner: Box<dyn PostInvocationHook>,
    lifecycle: ProductionDeclassificationReceiptLifecycle,
}

impl LifecycleCheckedProductionPostInvocationHook {
    fn new(
        inner: Box<dyn PostInvocationHook>,
        lifecycle: ProductionDeclassificationReceiptLifecycle,
    ) -> Self {
        Self { inner, lifecycle }
    }

    fn blocked() -> PostInvocationInspection {
        PostInvocationInspection::without_evidence(PostInvocationVerdict::Block(
            RUNTIME_ADMISSION_CLOSED_REASON.to_string(),
        ))
    }
}

impl PostInvocationHook for LifecycleCheckedProductionPostInvocationHook {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn inspect(
        &self,
        context: &PostInvocationContext<'_>,
        response: &serde_json::Value,
    ) -> PostInvocationVerdict {
        self.inspect_with_evidence(context, response).verdict
    }

    fn inspect_with_evidence(
        &self,
        context: &PostInvocationContext<'_>,
        response: &serde_json::Value,
    ) -> PostInvocationInspection {
        if self.lifecycle.ensure_runtime_admission_open().is_err() {
            return Self::blocked();
        }
        let inspection = self.inner.inspect_with_evidence(context, response);
        if self.lifecycle.ensure_runtime_admission_open().is_err() {
            return Self::blocked();
        }
        inspection
    }
}

struct ProductionCapabilityFlowBinding {
    canonical_capability: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductionSecurityContextBinding {
    tenant_id: TenantId,
    session_id: SessionId,
    principal_id: PrincipalId,
    isolation_epoch_id: IsolationEpochId,
    lineage_id: LineageId,
    context_generation: u64,
}

/// Broker-owned resolver for authoritative per-dispatch flow identity and
/// generation state. The resolver retains only server-issued capabilities and
/// the durable security state authority owned by the published runtime.
struct ProductionSecurityInvocationContextAuthority {
    security_store: Arc<SqliteSecurityStateStore>,
    agent_id: String,
    agent_public_key: PublicKey,
    security_binding: ProductionSecurityContextBinding,
    capabilities: BTreeMap<String, ProductionCapabilityFlowBinding>,
}

impl ProductionSecurityInvocationContextAuthority {
    fn new(
        security_store: Arc<SqliteSecurityStateStore>,
        tenant_id: TenantId,
        agent_id: &str,
        issued_capabilities: &[CapabilityToken],
    ) -> Result<Self, BrokerIntegrationError> {
        let agent_public_key = PublicKey::from_hex(agent_id).map_err(|error| {
            invalid(format!(
                "security invocation agent binding is invalid: {error}"
            ))
        })?;
        if issued_capabilities.is_empty() {
            return Err(invalid(
                "security invocation authority requires server-issued capabilities",
            ));
        }
        let mut capabilities = BTreeMap::new();
        let mut exact_security_binding = None::<CapabilitySecurityBinding>;
        for capability in issued_capabilities {
            if capability.subject != agent_public_key {
                return Err(invalid(
                    "security invocation capability subject does not match the bound agent",
                ));
            }
            let security_binding = capability
                .security_binding()
                .map_err(|error| {
                    invalid(format!(
                        "server-issued capability security binding is invalid: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    invalid("server-issued capability has no signed security binding")
                })?;
            match exact_security_binding.as_ref() {
                Some(expected) if expected != &security_binding => {
                    return Err(invalid(
                        "server-issued capability set has inconsistent security bindings",
                    ));
                }
                Some(_) => {}
                None => exact_security_binding = Some(security_binding),
            }
            let canonical_capability = canonical_json_bytes(capability).map_err(|error| {
                invalid(format!(
                    "server-issued capability binding could not be canonicalized: {error}"
                ))
            })?;
            if capabilities
                .insert(
                    capability.id.clone(),
                    ProductionCapabilityFlowBinding {
                        canonical_capability,
                    },
                )
                .is_some()
            {
                return Err(invalid(
                    "security invocation authority received duplicate capability ids",
                ));
            }
        }
        let exact_security_binding = exact_security_binding.ok_or_else(|| {
            invalid("security invocation authority requires a signed security binding")
        })?;
        let security_binding = ProductionSecurityContextBinding {
            tenant_id: TenantId::new(exact_security_binding.tenant_id).map_err(|error| {
                invalid(format!("capability tenant binding is invalid: {error}"))
            })?,
            session_id: SessionId::new(exact_security_binding.session_id).map_err(|error| {
                invalid(format!("capability session binding is invalid: {error}"))
            })?,
            principal_id: PrincipalId::new(exact_security_binding.principal_id).map_err(|error| {
                invalid(format!("capability principal binding is invalid: {error}"))
            })?,
            isolation_epoch_id: IsolationEpochId::new(exact_security_binding.isolation_epoch_id)
                .map_err(|error| {
                    invalid(format!("capability isolation binding is invalid: {error}"))
                })?,
            lineage_id: LineageId::new(exact_security_binding.lineage_id).map_err(|error| {
                invalid(format!("capability lineage binding is invalid: {error}"))
            })?,
            context_generation: exact_security_binding.context_generation,
        };
        if security_binding.tenant_id != tenant_id {
            return Err(invalid(
                "capability security binding tenant does not match the production security tenant",
            ));
        }
        Ok(Self {
            security_store,
            agent_id: agent_id.to_string(),
            agent_public_key,
            security_binding,
            capabilities,
        })
    }

    fn load_or_initialize_snapshot(
        &self,
        key: &FlowStateKey,
    ) -> Result<FlowStateSnapshot, KernelError> {
        if let Some(snapshot) = self.security_store.load(key).map_err(|error| {
            KernelError::Internal(format!(
                "authoritative flow state could not be loaded: {error:?}"
            ))
        })? {
            return validate_authoritative_flow_snapshot(key, snapshot);
        }
        let transition_id = RecordId::new(format!(
            "mcp-flow-init-{}",
            stable_security_identifier(
                "chio.production-mcp-flow-init.v1",
                &[
                    key.tenant_id.as_str(),
                    key.principal_id.as_str(),
                    key.lineage_id.as_str(),
                    key.session_id.as_str(),
                    key.isolation_epoch_id.as_str(),
                ]
            )
        ))
        .map_err(|error| {
            KernelError::Internal(format!(
                "authoritative flow transition id is invalid: {error}"
            ))
        })?;
        let snapshot = self
            .security_store
            .join(&FlowJoinRequest {
                key: key.clone(),
                principal_join: InformationLabel::bottom(),
                lineage_join: InformationLabel::bottom(),
                session_join: InformationLabel::bottom(),
                transition_id,
            })
            .map_err(|error| {
                KernelError::Internal(format!(
                    "authoritative flow state could not be initialized: {error:?}"
                ))
            })?;
        validate_authoritative_flow_snapshot(key, snapshot)
    }
}

impl SecurityInvocationContextAuthority for ProductionSecurityInvocationContextAuthority {
    fn resolve_security_invocation_context(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError> {
        if context.agent_id != self.agent_id {
            return Err(KernelError::GuardDenied(
                "security invocation principal does not match the bound agent".to_string(),
            ));
        }
        if operation.capability.subject != self.agent_public_key {
            return Err(KernelError::GuardDenied(
                "security invocation capability subject does not match the bound principal"
                    .to_string(),
            ));
        }
        let binding = self
            .capabilities
            .get(&operation.capability.id)
            .ok_or_else(|| {
                KernelError::GuardDenied(
                    "security invocation capability is not in the server-issued set".to_string(),
                )
            })?;
        let observed_capability = canonical_json_bytes(&operation.capability).map_err(|error| {
            KernelError::GuardDenied(format!(
                "security invocation capability is not canonicalizable: {error}"
            ))
        })?;
        if observed_capability != binding.canonical_capability {
            return Err(KernelError::GuardDenied(
                "security invocation capability does not match the server-issued token".to_string(),
            ));
        }
        if context.session_id.as_str() != self.security_binding.session_id.as_str() {
            return Err(KernelError::GuardDenied(
                "security invocation context does not match its signed kernel session"
                    .to_string(),
            ));
        }
        let key = FlowStateKey {
            tenant_id: self.security_binding.tenant_id.clone(),
            principal_id: self.security_binding.principal_id.clone(),
            lineage_id: self.security_binding.lineage_id.clone(),
            session_id: self.security_binding.session_id.clone(),
            isolation_epoch_id: self.security_binding.isolation_epoch_id.clone(),
        };
        let snapshot = self.load_or_initialize_snapshot(&key)?;
        Ok(SecurityInvocationContext::v1(
            SecurityInvocationContextV1::new(
                snapshot.key.tenant_id,
                snapshot.key.session_id,
                snapshot.key.principal_id,
                snapshot.key.isolation_epoch_id,
                snapshot.key.lineage_id,
                self.security_binding.context_generation,
            )
            .with_flow_state_generation(snapshot.context_generation),
        ))
    }
}

fn validate_authoritative_flow_snapshot(
    expected: &FlowStateKey,
    snapshot: FlowStateSnapshot,
) -> Result<FlowStateSnapshot, KernelError> {
    if &snapshot.key != expected {
        return Err(KernelError::GuardDenied(
            "authoritative flow state tenant, principal, session, capability lineage, or isolation epoch does not match"
                .to_string(),
        ));
    }
    Ok(snapshot)
}

fn stable_security_identifier(domain: &str, parts: &[&str]) -> String {
    let mut material = Vec::new();
    material.extend_from_slice(domain.as_bytes());
    material.push(0);
    for part in parts {
        let length = u64::try_from(part.len()).unwrap_or(u64::MAX);
        material.extend_from_slice(&length.to_be_bytes());
        material.extend_from_slice(part.as_bytes());
    }
    sha256_hex(&material)
}

impl ProductionSecurityRuntimeFactory {
    pub(super) fn open(
        config: ProductionSecurityRuntimeFactoryConfig,
        decoy_registry_master_key: [u8; 32],
        budget_store: Arc<dyn BudgetStore>,
    ) -> Result<Self, BrokerIntegrationError> {
        let executor_lease_owner_id = validate_factory_config(&config)?;
        if !budget_store
            .authority_profile()
            .supports_dispatch_workers(1)
        {
            return Err(invalid(
                "production security runtime requires a durable shared budget authority",
            ));
        }
        let (classification_rules, category_labels) = compile_classifier_policy(&config.runtime)?;
        let classifier = RegexStructuredClassifier::new(
            config.runtime.classifier_id.clone(),
            config.runtime.classifier_version.clone(),
            classification_rules,
        )
        .map_err(|error| invalid(format!("production classifier is invalid: {error}")))?;
        let classifier: Arc<dyn ClassificationPort> =
            Arc::new(StructuredClassificationAdapter::new(Arc::new(classifier)));
        let category_labels = CategoryLabelMap::new(
            ClassifierId::new(config.runtime.classifier_id.clone())
                .map_err(|error| invalid(format!("classifier id is invalid: {error}")))?,
            ClassifierVersion::new(config.runtime.classifier_version.clone())
                .map_err(|error| invalid(format!("classifier version is invalid: {error}")))?,
            category_labels,
        )
        .map_err(|error| invalid(format!("classifier label policy is invalid: {error}")))?;
        let trusted_declassification_authorities = config
            .runtime
            .trusted_declassification_authorities
            .iter()
            .map(|(id, key)| {
                RecordId::new(id.clone())
                    .map(|id| (id, key.clone()))
                    .map_err(|error| {
                        invalid(format!("declassification authority id is invalid: {error}"))
                    })
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let watermark_keys = Arc::new(ProductionWatermarkKeyResolver::new(
            &config.runtime.trusted_watermark_keys,
        )?);
        let watermark_contexts = Arc::new(ProductionWatermarkSourceContextResolver::new(
            &config.runtime.trusted_watermark_source_contexts,
        )?);

        let security_state_authority = open_security_state_store_with_lifecycle_lease(
            &config.runtime.security_state_database_path,
        )?;
        let security_store = Arc::clone(security_state_authority.store());
        let flow_config = FlowResolverConfig::new(
            config.runtime.operator_input_floor.clone(),
            category_labels,
            trusted_declassification_authorities,
            config.runtime.flow_fence_ttl_ms,
        )
        .map_err(|error| invalid(format!("flow resolver config is invalid: {error}")))?;

        let sealed_decoys = Arc::new(
            SqliteSealedDecoyRegistryStore::open(&config.runtime.decoy_registry_database_path)
                .map_err(|error| {
                    invalid(format!("decoy registry store is unavailable: {error}"))
                })?,
        );
        let decoy_registry = PrivateDecoyRegistry::new(
            sealed_decoys.clone(),
            Arc::new(DerivedRegistryKeyProvider::new(decoy_registry_master_key)),
            Arc::new(DenyRegistryExport),
        );
        let clock: Arc<dyn SecurityClock> = Arc::new(SystemSecurityClock);
        let watermark = Arc::new(WatermarkVerifier::new(WatermarkVerifierDependencies {
            keys: watermark_keys,
            contexts: watermark_contexts,
            registry: decoy_registry.clone(),
            observations: sealed_decoys,
        }));
        let native_detector = DecoyTripwireDetectorPort::new(
            Arc::new(DecoyDetector::new(Arc::new(decoy_registry))),
            watermark,
            Arc::clone(&clock),
        );
        let tripwire_detector: Arc<dyn TripwireDetectorPort> = Arc::new(native_detector);

        let admission_operation_store = Arc::new(
            SqliteSecurityAdmissionOperationStore::open(&config.admission_operation_database_path)
                .map_err(|error| {
                    invalid(format!("admission operation store is unavailable: {error}"))
                })?,
        );
        let approval_store = Arc::new(
            SqliteApprovalStore::open(&config.runtime.approval_database_path)
                .map_err(|error| invalid(format!("approval store is unavailable: {error}")))?,
        );
        let receipt_store = Arc::new(
            SqliteReceiptStore::open_existing_strict(&config.native_receipt_database_path)
                .map_err(|error| {
                    invalid(format!("native receipt store is unavailable: {error}"))
                })?,
        );
        let alert_backend: Arc<dyn AlertBackend> = Arc::new(DurableFileAlertBackend::open(
            &config.runtime.alert_archive_path,
        )?);
        let alert_outbox = Arc::new(
            SqliteSiemOutbox::open(
                &config.runtime.alert_outbox_database_path,
                vec![alert_backend],
                AlertOutboxConfig::default(),
            )
            .map_err(|error| invalid(format!("security alert outbox is unavailable: {error}")))?,
        );
        let blast_radius: Arc<dyn BlastRadiusPort> = Arc::new(CausalBlastRadiusResolver::new(
            Arc::clone(&receipt_store),
            Arc::clone(&receipt_store),
        ));
        let effects = Arc::new(
            ActiveResponseEffectPort::production(
                Arc::clone(&security_store),
                Arc::clone(&alert_outbox),
                Arc::clone(&blast_radius),
            )
            .map_err(|error| {
                invalid(format!("active response effects are unavailable: {error}"))
            })?,
        );

        Ok(Self {
            security_state_authority,
            security_store,
            admission_operation_store,
            approval_store,
            budget_store,
            receipt_store,
            classifier,
            flow_config,
            declassification_lifecycle: Mutex::new(None),
            active_response_coordinator: Mutex::new(None),
            tripwire_detector,
            tripwire_producer_id: ProducerId::new(config.runtime.tripwire_producer_id)
                .map_err(|error| invalid(format!("tripwire producer id is invalid: {error}")))?,
            tripwire_producer_key_id: RecordId::new(config.runtime.tripwire_producer_key_id)
                .map_err(|error| {
                    invalid(format!("tripwire producer key id is invalid: {error}"))
                })?,
            tripwire_policy_version: RecordId::new(config.runtime.tripwire_policy_version)
                .map_err(|error| invalid(format!("tripwire policy version is invalid: {error}")))?,
            tripwire_tenant_id: config.tripwire_tenant_id,
            tripwire_max_event_age_ms: config.runtime.tripwire_max_event_age_ms,
            tripwire_max_future_skew_ms: config.runtime.tripwire_max_future_skew_ms,
            alert_outbox,
            blast_radius,
            effects,
            clock,
            executor_generation: config.runtime.active_response_executor_generation,
            executor_lease_owner_id,
            executor_lease_ms: config.runtime.active_response_execution_lease_ms,
            response_policy_version: RecordId::new(config.runtime.active_response_policy_version)
                .map_err(|error| {
                invalid(format!("response policy version is invalid: {error}"))
            })?,
            response_approval_policy_id: RecordId::new(
                config.runtime.active_response_approval_policy_id,
            )
            .map_err(|error| invalid(format!("response approval policy id is invalid: {error}")))?,
            response_allowed_effects: config.runtime.active_response_allowed_effects,
            response_automatic_ttl_ceiling_ms: config
                .runtime
                .active_response_automatic_ttl_ceiling_ms,
            response_max_finding_age_ms: config.runtime.active_response_max_finding_age_ms,
        })
    }

    pub(super) fn security_invocation_context_authority(
        &self,
        authenticated_tenant_id: Option<&str>,
        agent_id: &str,
        issued_capabilities: &[CapabilityToken],
    ) -> Result<Arc<dyn SecurityInvocationContextAuthority>, BrokerIntegrationError> {
        if authenticated_tenant_id
            .is_some_and(|tenant_id| tenant_id != self.tripwire_tenant_id.as_str())
        {
            return Err(invalid(
                "authenticated tenant does not match the configured production security tenant",
            ));
        }
        Ok(Arc::new(ProductionSecurityInvocationContextAuthority::new(
            Arc::clone(&self.security_store),
            self.tripwire_tenant_id.clone(),
            agent_id,
            issued_capabilities,
        )?))
    }

    pub(super) fn install_kernel_authorities_before_publication(
        &self,
        kernel: &mut chio_kernel::ChioKernel,
    ) -> Result<(), BrokerIntegrationError> {
        kernel.set_budget_store_handle(Arc::clone(&self.budget_store))?;
        kernel.set_approval_store_handle(self.approval_store.clone() as Arc<dyn ApprovalStore>)?;
        kernel.set_admission_operation_store_handle(
            self.admission_operation_store.clone() as Arc<dyn AdmissionOperationStore>
        )?;
        Ok(())
    }

    fn declassification_lifecycle(
        &self,
        signer: Arc<dyn SigningBackend>,
    ) -> Result<ProductionDeclassificationReceiptLifecycle, BrokerIntegrationError> {
        let indexed_evidence_store: Arc<dyn IndexedSecurityEvidenceStore> =
            self.receipt_store.clone();
        let mut lifecycle = self.declassification_lifecycle.lock().map_err(|_| {
            invalid("production declassification receipt lifecycle lock is unavailable")
        })?;
        if let Some(existing) = lifecycle.as_ref() {
            existing
                .ensure_authority(
                    &self.security_state_authority,
                    &indexed_evidence_store,
                    &signer,
                    &self.clock,
                )
                .map_err(|error| {
                    invalid(format!(
                        "production declassification receipt authority changed: {error}"
                    ))
                })?;
            return Ok(existing.clone());
        }
        let created = ProductionDeclassificationReceiptLifecycle::new(
            self.security_state_authority.clone(),
            indexed_evidence_store,
            signer,
            Arc::clone(&self.clock),
        )
        .map_err(|error| {
            invalid(format!(
                "production declassification receipt lifecycle is unavailable: {error}"
            ))
        })?;
        *lifecycle = Some(created.clone());
        Ok(created)
    }

    pub(super) fn active_defense_host_config(
        &self,
        signer: Arc<dyn SigningBackend>,
        response_policy_planner: Arc<dyn AttestedFindingResponsePolicyPlanner>,
        active_defense: ProductionActiveDefenseConfig,
        worker_loop: ProductionResponseWorkerLoopConfig,
    ) -> Result<
        (
            ProductionActiveDefenseHostConfig,
            ProductionDeclassificationReceiptLifecycle,
        ),
        BrokerIntegrationError,
    > {
        let declassification_lifecycle = self.declassification_lifecycle(Arc::clone(&signer))?;
        let indexed_evidence_store: Arc<dyn IndexedSecurityEvidenceStore> =
            self.receipt_store.clone();
        let scheduler_health: Arc<dyn SchedulerHealthPort> = self.alert_outbox.clone();
        let executor_authority = ActiveResponseExecutorAuthorityIdentity::new(
            signer.public_key(),
            self.executor_generation,
        )
        .map_err(|error| {
            invalid(format!(
                "active-response executor identity is invalid: {error}"
            ))
        })?;
        let response_coordinator = {
            let mut retained = self.active_response_coordinator.lock().map_err(|_| {
                invalid("active-response kernel coordinator lock is unavailable")
            })?;
            if let Some(existing) = retained.as_ref() {
                if !existing.expects_authority(&executor_authority) {
                    return Err(invalid(
                        "active-response kernel coordinator authority changed",
                    ));
                }
                Arc::clone(existing)
            } else {
                let created = Arc::new(
                    KernelAttestedFindingResponseCoordinator::new_unbound(
                        executor_authority,
                        Arc::clone(&self.clock),
                    ),
                );
                *retained = Some(Arc::clone(&created));
                created
            }
        };
        Ok((
            ProductionActiveDefenseHostConfig {
                durability: SecurityDurability::persistent(),
                security_state_authority: self.security_state_authority.clone(),
                indexed_evidence_store,
                signer,
                alert_outbox: Arc::clone(&self.alert_outbox),
                blast_radius: Arc::clone(&self.blast_radius),
                scheduler_health,
                response_policy_planner,
                response_coordinator,
                clock: Arc::clone(&self.clock),
                active_defense,
                worker_loop,
            },
            declassification_lifecycle,
        ))
    }

    pub(super) fn bind_active_response_kernel(
        &self,
        kernel: Arc<ChioKernel>,
    ) -> Result<(), BrokerIntegrationError> {
        let coordinator = self
            .active_response_coordinator
            .lock()
            .map_err(|_| invalid("active-response kernel coordinator lock is unavailable"))?
            .as_ref()
            .cloned()
            .ok_or_else(|| invalid("active-response kernel coordinator is not configured"))?;
        coordinator.bind_kernel(kernel).map_err(|error| {
            invalid(format!(
                "active-response kernel coordinator binding failed: {error}"
            ))
        })
    }

    pub(super) fn ensure_active_response_kernel_bound(
        &self,
    ) -> Result<(), BrokerIntegrationError> {
        let coordinator = self
            .active_response_coordinator
            .lock()
            .map_err(|_| invalid("active-response kernel coordinator lock is unavailable"))?
            .as_ref()
            .cloned()
            .ok_or_else(|| invalid("active-response kernel coordinator is not configured"))?;
        coordinator.ensure_ready().map_err(|error| {
            invalid(format!(
                "active-response kernel coordinator is unavailable: {error}"
            ))
        })
    }

    pub(super) fn build(
        &self,
        manifests: Arc<chio_manifest::VerifiedManifestRegistry>,
        signer: Arc<dyn SigningBackend>,
        runtime_policy_hash: &str,
    ) -> Result<SecurityRuntime, BrokerIntegrationError> {
        let runtime_policy_digest = decode_runtime_policy_digest(runtime_policy_hash)?;
        let indexed_store: Arc<dyn IndexedSecurityEvidenceStore> = self.receipt_store.clone();
        let declassification_lifecycle = self.declassification_lifecycle(Arc::clone(&signer))?;
        let runtime_lease =
            declassification_lifecycle
                .acquire_runtime_lease()
                .map_err(|error| {
                    invalid(format!(
                        "production security runtime admission is unavailable: {error}"
                    ))
                })?;
        let receipt_sink = declassification_lifecycle.receipt_sink();
        let active_response_receipt_sink =
            declassification_lifecycle.active_response_receipt_sink();
        receipt_sink.ensure_receipts_ready().map_err(|error| {
            invalid(format!(
                "native security receipt sink is unavailable: {error}"
            ))
        })?;
        declassification_lifecycle
            .drain_to_zero()
            .map_err(|error| {
                invalid(format!(
                    "pending declassification receipt evidence blocks runtime publication: {error}"
                ))
            })?;
        let receipt_policy = ActiveDefensePolicyBinding {
            policy_version: self.tripwire_policy_version.clone(),
            policy_hash: runtime_policy_digest,
        };
        let declassification_store: Arc<dyn DeclassificationEvidenceCommitStore> =
            self.security_store.clone();
        let exact_receipt_sink: Arc<dyn ExactSecurityReceiptSink> =
            declassification_lifecycle.exact_receipt_sink();
        let flow_config = self
            .flow_config
            .clone()
            .with_declassification_evidence(
                declassification_store,
                exact_receipt_sink,
                receipt_policy.clone(),
            )
            .map_err(|error| {
                invalid(format!(
                    "production declassification evidence authority is unavailable: {error}"
                ))
            })?
            .with_receipt_evidence(
                receipt_sink.clone() as Arc<dyn SecurityReceiptSink>,
                receipt_policy.clone(),
            );
        let state: Arc<dyn FlowStateStore> = self.security_store.clone();
        let resolver = Arc::new(PersistentFlowResolver::new(
            Arc::clone(&manifests),
            state,
            Arc::clone(&self.classifier),
            Arc::clone(&self.clock),
            flow_config,
        ));
        let post_resolver: Arc<dyn FlowPostInvocationResolver> = resolver.clone();
        let dispatch_resolver: Arc<dyn FlowPreDispatchPort> =
            Arc::new(LeasedProductionFlowPreDispatchPort::new(
                resolver.clone(),
                declassification_lifecycle.clone(),
            ));
        let pre_flow: Arc<dyn FlowPreInvocationPort> = resolver;
        let post_flow = Arc::new(EngineFlowPostInvocationPort::new(post_resolver));
        let event_verifier = Arc::new(
            NativeSecurityEventVerifier::new(
                Arc::clone(&self.clock),
                vec![TrustedSecurityEventProducer {
                    tenant_id: self.tripwire_tenant_id.clone(),
                    producer_id: self.tripwire_producer_id.clone(),
                    producer_key_id: self.tripwire_producer_key_id.clone(),
                    policy_version: self.tripwire_policy_version.clone(),
                    producer_key: signer.public_key(),
                }],
                Vec::new(),
                self.tripwire_max_event_age_ms,
                self.tripwire_max_future_skew_ms,
            )
            .map_err(|error| invalid(format!("tripwire event verifier is invalid: {error}")))?,
        );
        let event_ingress = Arc::new(
            VerifiedSecurityEventIngress::new(event_verifier, Arc::clone(&self.security_store))
                .map_err(|error| {
                    invalid(format!("tripwire event ingress is unavailable: {error}"))
                })?,
        );
        let event_ingress: Arc<dyn chio_security_kernel::SecurityEventIngress> = event_ingress;
        let tripwire_publisher = Arc::new(
            TripwireEventPublisher::new(
                event_ingress,
                Arc::clone(&self.clock),
                Arc::clone(&signer),
                self.tripwire_producer_id.clone(),
                self.tripwire_producer_key_id.clone(),
                self.tripwire_policy_version.clone(),
            )
            .and_then(|publisher| {
                publisher.with_receipt_evidence(
                    receipt_sink.clone() as Arc<dyn SecurityReceiptSink>,
                    receipt_policy.policy_hash,
                )
            })
            .map_err(|error| invalid(format!("tripwire event publisher is invalid: {error}")))?,
        );
        let throttles: Arc<dyn SessionThrottleStore> = self.security_store.clone();
        let overlays: Arc<dyn ContainmentOverlayStore> = self.security_store.clone();
        let parts = SecurityRuntimeParts::new(
            Box::new(LifecycleCheckedProductionGuard::new(
                Box::new(SessionThrottleGuard::new(
                    throttles,
                    Arc::clone(&self.clock),
                    MissingContextPolicy::Deny,
                )),
                declassification_lifecycle.clone(),
            )),
            Box::new(LifecycleCheckedProductionGuard::new(
                Box::new(TripwireGuard::new(
                    Arc::clone(&self.tripwire_detector),
                    Arc::clone(&tripwire_publisher),
                    MissingContextPolicy::Deny,
                )),
                declassification_lifecycle.clone(),
            )),
            Box::new(LifecycleCheckedProductionGuard::new(
                Box::new(ContainmentGuard::new(overlays, MissingContextPolicy::Deny)),
                declassification_lifecycle.clone(),
            )),
            Box::new(RetainedProductionRuntimeLeaseGuard::new(
                Box::new(FlowPreInvocationGuard::new(
                    pre_flow,
                    MissingContextPolicy::Deny,
                )),
                runtime_lease,
            )),
            Arc::new(FlowPreDispatchHook::new(dispatch_resolver)),
            Box::new(LifecycleCheckedProductionPostInvocationHook::new(
                Box::new(RawOutputTripwireHook::new(
                    Arc::clone(&self.tripwire_detector),
                    tripwire_publisher,
                    MissingContextPolicy::Deny,
                )),
                declassification_lifecycle.clone(),
            )),
            Box::new(LifecycleCheckedProductionPostInvocationHook::new(
                Box::new(FlowPostInvocationHook::new(
                    post_flow,
                    MissingContextPolicy::Deny,
                )),
                declassification_lifecycle.clone(),
            )),
        );

        let executor_identity = ActiveResponseExecutorAuthorityIdentity::new(
            signer.public_key(),
            self.executor_generation,
        )
        .map_err(|error| {
            invalid(format!(
                "active response executor identity is invalid: {error}"
            ))
        })?;
        let executor = Arc::new(
            DurableActiveResponseExecutor::new(
                executor_identity.clone(),
                self.executor_lease_owner_id.clone(),
                Arc::clone(&self.security_store),
                Arc::clone(&self.effects),
                active_response_receipt_sink,
                Arc::clone(&self.alert_outbox),
                Arc::clone(&self.clock),
                self.executor_lease_ms,
            )
            .map_err(|error| invalid(format!("active response executor is invalid: {error}")))?,
        );
        let executor: Arc<dyn ActiveResponseExecutorAuthority> = executor;
        let executor: Arc<dyn ActiveResponseExecutorAuthority> = Arc::new(
            LifecycleCheckedProductionActiveResponseExecutorAuthority::new(
                executor,
                declassification_lifecycle,
            ),
        );
        if executor.identity() != executor_identity {
            return Err(invalid(
                "active response executor wrapper changed the authority identity",
            ));
        }
        executor.ensure_ready().map_err(|error| {
            invalid(format!("active response executor is unavailable: {error}"))
        })?;
        let response_policy = Arc::new(GovernedProductionResponsePolicy {
            runtime_policy_hash: runtime_policy_hash.to_string(),
            policy_version: self.response_policy_version.clone(),
            approval_policy_id: self.response_approval_policy_id.clone(),
            allowed_effects: self.response_allowed_effects.clone(),
            automatic_ttl_ceiling_ms: self.response_automatic_ttl_ceiling_ms,
            max_finding_age_ms: self.response_max_finding_age_ms,
        });

        let authorities = SecurityRuntimeAuthorityBundleBuilder::new()
            .with_active_response_requirement_resolver(response_policy)
            .with_admission_operation_store(
                self.admission_operation_store.clone() as Arc<dyn AdmissionOperationStore>
            )
            .with_approval_store(self.approval_store.clone() as Arc<dyn ApprovalStore>)
            .with_budget_store(Arc::clone(&self.budget_store))
            .with_session_throttle_store(Arc::clone(&self.security_store))
            .with_indexed_finding_store(indexed_store)
            .with_trusted_receipt_signers(vec![signer.public_key()])
            .with_executor_authority(executor)
            .build()
            .map_err(|error| invalid(format!("security authority bundle is invalid: {error}")))?;
        let runtime = SecurityRuntime::production(
            Arc::clone(&manifests),
            SecurityDurability::persistent(),
            parts,
            authorities,
        )
        .map_err(|error| invalid(format!("production security runtime is invalid: {error}")))?;
        if !Arc::ptr_eq(runtime.manifests(), &manifests) {
            return Err(invalid(
                "security runtime replaced the manifest registry authority",
            ));
        }
        Ok(runtime)
    }
}

fn open_security_state_store_with_lifecycle_lease(
    path: &Path,
) -> Result<ProductionSecurityStateAuthority, BrokerIntegrationError> {
    open_security_state_store_with_lifecycle_lease_after_acquire(path, || Ok(()))
}

fn open_security_state_store_with_lifecycle_lease_after_acquire<F>(
    path: &Path,
    after_acquire: F,
) -> Result<ProductionSecurityStateAuthority, BrokerIntegrationError>
where
    F: FnOnce() -> Result<(), BrokerIntegrationError>,
{
    open_security_state_store_with_lifecycle_lease_after_acquire_and_open(
        path,
        after_acquire,
        || SqliteSecurityStateStore::open(path),
    )
}

#[cfg(test)]
fn open_security_state_store_with_lifecycle_lease_and_clock(
    path: &Path,
    clock: Arc<dyn chio_store_sqlite::security_state::SecurityStateClock>,
) -> Result<ProductionSecurityStateAuthority, BrokerIntegrationError> {
    open_security_state_store_with_lifecycle_lease_after_acquire_and_open(
        path,
        || Ok(()),
        || SqliteSecurityStateStore::open_with_trusted_clock(path, clock),
    )
}

fn open_security_state_store_with_lifecycle_lease_after_acquire_and_open<F, O>(
    path: &Path,
    after_acquire: F,
    open_store: O,
) -> Result<ProductionSecurityStateAuthority, BrokerIntegrationError>
where
    F: FnOnce() -> Result<(), BrokerIntegrationError>,
    O: FnOnce() -> PortResult<SqliteSecurityStateStore>,
{
    let lease = Arc::new(RetainedSecurityStateLifecycleLease::acquire(path)?);
    after_acquire()?;
    lease.ensure_owned()?;
    let store = Arc::new(
        open_store()
            .map_err(|error| invalid(format!("security state store is unavailable: {error}")))?,
    );
    lease.ensure_owned()?;
    let locked_database_file = lease.try_clone_locked_file()?;
    #[cfg(target_os = "macos")]
    let locked_lifecycle_file = lease.try_clone_lifecycle_lock_file()?;
    let proof = store
        .security_state_lifecycle_owner_proof(
            locked_database_file,
            #[cfg(target_os = "macos")]
            locked_lifecycle_file,
        )
        .map_err(|error| {
            invalid(format!(
                "security state lifecycle owner proof is unavailable: {error}"
            ))
        })?;
    lease.ensure_owned()?;
    let owner: Arc<dyn ProductionSecurityStateLifecycleOwner> =
        Arc::new(RetainedProductionSecurityStateLifecycleOwner {
            path_custody: lease,
            store: Arc::clone(&store),
            proof,
        });
    Ok(ProductionSecurityStateAuthority::new(store, owner))
}

fn validate_factory_config(
    config: &ProductionSecurityRuntimeFactoryConfig,
) -> Result<LeaseOwnerId, BrokerIntegrationError> {
    if config.runtime.classification_rules.is_empty()
        || config.runtime.flow_fence_ttl_ms == 0
        || config.runtime.tripwire_max_event_age_ms == 0
        || config.runtime.tripwire_max_future_skew_ms > config.runtime.tripwire_max_event_age_ms
        || config.runtime.active_response_executor_generation == 0
        || config.runtime.active_response_execution_lease_ms == 0
        || config.runtime.active_response_allowed_effects.is_empty()
        || config.runtime.active_response_automatic_ttl_ceiling_ms == 0
        || config.runtime.active_response_max_finding_age_ms == 0
    {
        return Err(invalid(
            "production security runtime has an empty or zero-valued authority policy",
        ));
    }
    let paths = [
        &config.runtime.security_state_database_path,
        &config.runtime.decoy_registry_database_path,
        &config.runtime.approval_database_path,
        &config.runtime.alert_outbox_database_path,
        &config.runtime.alert_archive_path,
        &config.admission_operation_database_path,
        &config.budget_database_path,
        &config.native_receipt_database_path,
    ];
    let mut identities = BTreeSet::new();
    for path in paths {
        if !path.is_absolute() || path == Path::new(":memory:") {
            return Err(invalid(
                "production security authorities require absolute filesystem paths",
            ));
        }
        let identity = normalized_path(path)?;
        if !identities.insert(identity) {
            return Err(invalid(
                "production security authorities require distinct persistence paths",
            ));
        }
    }
    LeaseOwnerId::new(
        config
            .runtime
            .active_response_executor_lease_owner_id
            .clone(),
    )
    .map_err(|error| {
        invalid(format!(
            "active-response executor lease owner is invalid: {error}"
        ))
    })
}

fn compile_classifier_policy(
    config: &ProductionSecurityRuntimeFileConfig,
) -> Result<
    (
        Vec<RegexClassificationRule>,
        BTreeMap<RecordId, InformationLabel>,
    ),
    BrokerIntegrationError,
> {
    let mut rules = Vec::with_capacity(config.classification_rules.len());
    let mut labels = BTreeMap::new();
    for rule in &config.classification_rules {
        let category = RecordId::new(rule.category.clone())
            .map_err(|error| invalid(format!("classifier category is invalid: {error}")))?;
        if let Some(existing) = labels.insert(category, rule.label.clone()) {
            if existing != rule.label {
                return Err(invalid(
                    "classifier category has conflicting information labels",
                ));
            }
        }
        rules.push(
            RegexClassificationRule::new(
                rule.category.clone(),
                &rule.expression,
                rule.confidence_basis_points,
            )
            .map_err(|error| invalid(format!("classifier rule is invalid: {error}")))?,
        );
    }
    Ok((rules, labels))
}

fn normalized_path(path: &Path) -> Result<PathBuf, BrokerIntegrationError> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("production security authority path has no parent directory"))?;
    let normalized_parent = parent.canonicalize().map_err(|error| {
        invalid(format!(
            "production security authority parent is unavailable: {error}"
        ))
    })?;
    let file_name = path
        .file_name()
        .ok_or_else(|| invalid("production security authority path has no file name"))?;
    Ok(normalized_parent.join(file_name))
}

fn invalid(message: impl Into<String>) -> BrokerIntegrationError {
    BrokerIntegrationError::InvalidConfiguration(message.into())
}

pub(super) fn decode_runtime_policy_digest(
    runtime_policy_hash: &str,
) -> Result<chio_security_types::ports::Digest32, BrokerIntegrationError> {
    let bytes = runtime_policy_hash.as_bytes();
    if bytes.len() != 64
        || bytes
            .iter()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid(
            "runtime policy hash must be exactly 32 bytes of lowercase hex",
        ));
    }
    let mut decoded = [0_u8; 32];
    hex::decode_to_slice(runtime_policy_hash, &mut decoded)
        .map_err(|_| invalid("runtime policy hash is invalid"))?;
    Ok(chio_security_types::ports::Digest32::new(decoded))
}

struct DerivedRegistryKeyProvider {
    master_key: Zeroizing<[u8; 32]>,
}

impl DerivedRegistryKeyProvider {
    fn new(master_key: [u8; 32]) -> Self {
        Self {
            master_key: Zeroizing::new(master_key),
        }
    }

    fn derive(&self, domain: &[u8], tenant_id: &TenantId) -> Result<[u8; 32], RegistryError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&*self.master_key)
            .map_err(|_| RegistryError::KeyUnavailable)?;
        mac.update(domain);
        mac.update(tenant_id.as_str().as_bytes());
        let digest = mac.finalize().into_bytes();
        let mut derived = [0_u8; 32];
        derived.copy_from_slice(&digest);
        Ok(derived)
    }
}

impl RegistryKeyProvider for DerivedRegistryKeyProvider {
    fn key_for(&self, tenant_id: &TenantId) -> Result<RegistryKey, RegistryError> {
        let encryption_key = self.derive(REGISTRY_ENCRYPTION_DOMAIN, tenant_id)?;
        let index_key = self.derive(REGISTRY_INDEX_DOMAIN, tenant_id)?;
        let mut combined = [0_u8; 64];
        combined[..32].copy_from_slice(&encryption_key);
        combined[32..].copy_from_slice(&index_key);
        Ok(RegistryKey::from_bytes(combined))
    }
}

struct DenyRegistryExport;

impl RegistryExportAuthorizer for DenyRegistryExport {
    fn authorize(
        &self,
        _: &PrivilegedExportCredential,
        _: u64,
    ) -> Result<RegistryExportGrant, RegistryError> {
        Err(RegistryError::AuthorizationDenied)
    }
}

#[derive(Clone)]
struct ProductionWatermarkKeyResolver {
    keys: Arc<BTreeMap<(TenantId, RecordId), TrustedWatermarkKey>>,
}

impl ProductionWatermarkKeyResolver {
    fn new(
        configured: &[ProductionTrustedWatermarkKeyConfig],
    ) -> Result<Self, BrokerIntegrationError> {
        if configured.is_empty() {
            return Err(invalid(
                "production watermark verification requires an independently trusted key set",
            ));
        }
        let mut keys = BTreeMap::new();
        let mut has_verifying_key = false;
        for entry in configured {
            if entry.not_before_unix_ms > MAX_IJSON_INTEGER
                || entry.signing_cutoff_unix_ms > MAX_IJSON_INTEGER
                || entry.verify_until_unix_ms > MAX_IJSON_INTEGER
                || entry.signing_cutoff_unix_ms <= entry.not_before_unix_ms
                || entry.verify_until_unix_ms < entry.signing_cutoff_unix_ms
            {
                return Err(invalid(
                    "production watermark trusted key has an invalid time window",
                ));
            }
            let tenant_id = TenantId::new(entry.tenant_id.clone())
                .map_err(|error| invalid(format!("watermark key tenant id is invalid: {error}")))?;
            let key_id = RecordId::new(entry.key_id.clone())
                .map_err(|error| invalid(format!("watermark key id is invalid: {error}")))?;
            let trusted = TrustedWatermarkKey {
                public_key: entry.public_key.clone(),
                status: entry.status,
                not_before_unix_ms: entry.not_before_unix_ms,
                signing_cutoff_unix_ms: entry.signing_cutoff_unix_ms,
                verify_until_unix_ms: entry.verify_until_unix_ms,
            };
            if keys.insert((tenant_id, key_id), trusted).is_some() {
                return Err(invalid(
                    "production watermark trusted key set contains a duplicate tenant and key id",
                ));
            }
            has_verifying_key |= matches!(
                entry.status,
                WatermarkKeyStatus::Active | WatermarkKeyStatus::Overlap
            );
        }
        if !has_verifying_key {
            return Err(invalid(
                "production watermark trusted key set has no active or overlapping verification key",
            ));
        }
        Ok(Self {
            keys: Arc::new(keys),
        })
    }
}

impl WatermarkKeyResolver for ProductionWatermarkKeyResolver {
    fn resolve(
        &self,
        tenant_id: &TenantId,
        key_id: &RecordId,
    ) -> PortResult<Option<TrustedWatermarkKey>> {
        Ok(self.keys.get(&(tenant_id.clone(), key_id.clone())).cloned())
    }
}

#[derive(Clone)]
struct ProductionWatermarkSourceContextResolver {
    contexts: Arc<BTreeMap<RecordId, WatermarkSourceContext>>,
}
