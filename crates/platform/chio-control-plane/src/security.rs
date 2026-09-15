//! Central active-defense composition for production-capable kernels.
#[cfg(test)]
mod active_defense_host_tests;
mod active_response;
#[cfg(unix)]
mod active_response_authority;
mod active_response_validation;
pub mod adapters;
mod correlation;
mod durability;
mod event_consumer;
mod migration;
pub mod migration_evidence;
mod orchestration;
mod scheduler_worker;

pub use active_response::{
    DurableActiveResponseExecutor, DurableActiveResponseExecutorConfigError,
    MAX_ACTIVE_RESPONSE_LEASE_DURATION_MS,
};
#[cfg(unix)]
pub use active_response_authority::{
    active_response_authority_request_signing_bytes,
    active_response_authority_response_signing_bytes, validate_active_response_artifacts_draft,
    validate_active_response_policy_selection, ActiveResponseAdmissionArtifactsDraftWire,
    ActiveResponseAdmissionArtifactsWire, ActiveResponseAffectedIds, ActiveResponseApprovalTokens,
    ActiveResponseAuthorityHandler, ActiveResponseAuthorityHandlerError,
    ActiveResponseAuthorityHandlerResult, ActiveResponseAuthorityOperation,
    ActiveResponseAuthorityProtocolServer, ActiveResponseAuthorityProtocolServerConfig,
    ActiveResponseAuthorityRejection, ActiveResponseAuthorityRejectionClass,
    ActiveResponseAuthorityRequestBody, ActiveResponseAuthorityResponseBody,
    ActiveResponseAuthorityResult, ActiveResponseAuthorityServeOutcome, ActiveResponseEffects,
    ActiveResponsePolicySelectionWire, ProductionActiveResponseAuthorityClient,
    ProductionActiveResponseAuthorityFileConfig, SignedActiveResponseAuthorityRequest,
    SignedActiveResponseAuthorityResponse, ACTIVE_RESPONSE_AUTHORITY_REJECTION_KIND,
    ACTIVE_RESPONSE_AUTHORITY_REQUEST_DOMAIN, ACTIVE_RESPONSE_AUTHORITY_RESPONSE_DOMAIN,
    ACTIVE_RESPONSE_AUTHORITY_SCHEMA, ACTIVE_RESPONSE_AUTHORITY_TRANSIENT_REJECTION_KIND,
    MAX_ACTIVE_RESPONSE_AFFECTED_IDS, MAX_ACTIVE_RESPONSE_AUTHORITY_CLOCK_SKEW_SECONDS,
    MAX_ACTIVE_RESPONSE_AUTHORITY_SOCKET_PATH_BYTES, MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES,
};
pub use adapters::{
    AlertDispatchReport, AlertOutboxConfig, DeclassificationCompactionReport,
    DeclassificationReceiptDrainReport, DeclassificationReceiptOutboxDrainer,
    DeclassificationReconciliationReport, FlowResolverConfig, FlowResolverConfigError,
    NativeActiveResponseFindingAuthority, NativeFindingAuthorityConfigError,
    NativeSchedulerHealthPort, NativeSecurityReceiptSink, PersistentFlowResolver, SqliteSiemOutbox,
    StructuredClassificationAdapter,
};
pub use chio_kernel::{
    ActiveResponseArtifactAuthorityAttestation, ActiveResponseArtifactAuthorityAttestationBody,
};
pub use correlation::AttestedCorrelationWriter;
pub use durability::{AuthorityDurability, SecurityDurability};
pub use event_consumer::{
    AttestedFindingAdmissionArtifacts, AttestedFindingBatchPlanner,
    AttestedFindingResponsePolicyPlanner, AttestedFindingResponsePolicySelection,
    AttestedFindingResponseRecoveryLimits, CorrelationConsumerReport, CorrelationRuleReport,
    DurableAttestedFindingBatchPlanner, KernelAttestedFindingResponseCoordinator,
    NativeSecurityEventVerifier, ProductionCorrelationConsumer,
    ReservedAttestedFindingResponseBatch, ReservedAttestedFindingResponsePlan,
    SecurityEventReceiptProjection, SecurityEventVerifierConfigError, TrustedSecurityEventProducer,
    TrustedSecurityEventReceiptProducer, VerifiedSecurityEventIngress,
    SECURITY_EVENT_RECEIPT_PROJECTION_VERSION,
};
pub use migration::{
    EnterpriseMigrationRuntimeBinding, EnterpriseMigrationRuntimeError,
    EnterpriseOperationalFailureDisposition,
};
pub use migration_evidence::{
    DurableEnterpriseMigrationStateBinding, EnterpriseEvidenceRunnerIdentity,
    EnterpriseMigrationCanaryEvidenceBody, EnterpriseMigrationCanaryVerificationPolicy,
    EnterpriseMigrationCutoverAttestationBody, EnterpriseMigrationEvidenceBinding,
    EnterpriseMigrationEvidenceError, EnterpriseMigrationGateResultDigests,
    SignedEnterpriseMigrationCanaryEvidence, SignedEnterpriseMigrationCutoverAttestation,
    ENTERPRISE_MIGRATION_CANARY_EVIDENCE_SCHEMA, ENTERPRISE_MIGRATION_CUTOVER_ATTESTATION_SCHEMA,
};
pub use orchestration::{
    ProductionActiveDefenseBuildError, ProductionActiveDefenseConfig, ProductionActiveDefenseHost,
    ProductionActiveDefenseHostConfig, ProductionActiveDefenseHostError,
    ProductionActiveDefenseOrchestrator, ProductionSecurityStateAuthority,
    ProductionSecurityStateLifecycleOwner,
};
pub use scheduler_worker::{
    ActiveDefenseServiceRegistry, ActiveDefenseServices, ProductionResponseSchedulerConfig,
    ProductionResponseWorker, ProductionResponseWorkerHandle, ProductionResponseWorkerLoopConfig,
    ResponseWorkerHealth, ResponseWorkerLifecycle, ResponseWorkerPort, ResponseWorkerTick,
    ResponseWorkerTickError, SqliteResponseWorkerPort,
};

use std::sync::Arc;

use chio_kernel::{
    ChioKernel, PostInvocationPipeline, SecurityInvocationContextAuthority,
    SecurityPreDispatchPolicy,
};
use chio_security_kernel::{
    CapabilitySetSuspensionGuard, ContainmentGuard, EgressRestrictionGuard, FlowPostInvocationHook,
    FlowPostInvocationPort, FlowPreDispatchHook, FlowPreDispatchPort, FlowPreInvocationGuard,
    FlowPreInvocationPort, IssuanceFreezeAdmission, MissingContextPolicy, RawOutputTripwireHook,
    SecurityClock, SessionThrottleGuard, SystemSecurityClock, TripwireEventPublisher,
    TripwireGuard,
};
use chio_security_types::ports::TripwireDetectorPort;
use chio_store_sqlite::security_state::ActiveDefenseOverlayInventory;
use chio_store_sqlite::SqliteSecurityStateStore;

/// Readiness boundary for the durable flow, manifest, decoy, and event
/// authorities supplied to [`ActiveDefenseRuntime`].
///
/// The SQLite security-state store is checked independently. Implementations
/// must reject ephemeral stores and unverified manifest registries.
pub trait ActiveDefenseRuntimeReadiness: Send + Sync {
    fn ensure_ready(&self) -> Result<(), String>;
}

#[derive(Debug, thiserror::Error)]
pub enum ActiveDefenseInstallError {
    #[error("active-defense runtime is not ready: {0}")]
    RuntimeNotReady(String),

    #[error("persistent active-defense state is not ready: {0}")]
    StateNotReady(String),

    #[error("kernel rejected active-defense installation: {0}")]
    Kernel(#[from] chio_kernel::KernelError),
}

/// Fully constructed active-defense dependencies for one kernel.
///
/// Construction alone does not claim production readiness. The central kernel
/// builder calls [`Self::ensure_ready`] before installing any component.
pub struct ActiveDefenseRuntime {
    state: Arc<SqliteSecurityStateStore>,
    readiness: Arc<dyn ActiveDefenseRuntimeReadiness>,
    tripwire_detector: Arc<dyn TripwireDetectorPort>,
    tripwire_publisher: Arc<TripwireEventPublisher>,
    flow_pre_invocation: Arc<dyn FlowPreInvocationPort>,
    flow_pre_dispatch: Arc<dyn FlowPreDispatchPort>,
    flow_post_invocation: Arc<dyn FlowPostInvocationPort>,
    security_context_authority: Arc<dyn SecurityInvocationContextAuthority>,
    clock: Arc<dyn SecurityClock>,
}

impl ActiveDefenseRuntime {
    #[must_use]
    pub fn new(
        state: Arc<SqliteSecurityStateStore>,
        readiness: Arc<dyn ActiveDefenseRuntimeReadiness>,
        tripwire_detector: Arc<dyn TripwireDetectorPort>,
        tripwire_publisher: Arc<TripwireEventPublisher>,
        flow_pre_invocation: Arc<dyn FlowPreInvocationPort>,
        flow_pre_dispatch: Arc<dyn FlowPreDispatchPort>,
        flow_post_invocation: Arc<dyn FlowPostInvocationPort>,
        security_context_authority: Arc<dyn SecurityInvocationContextAuthority>,
    ) -> Self {
        Self {
            state,
            readiness,
            tripwire_detector,
            tripwire_publisher,
            flow_pre_invocation,
            flow_pre_dispatch,
            flow_post_invocation,
            security_context_authority,
            clock: Arc::new(SystemSecurityClock),
        }
    }

    /// Replace the system clock with an authenticated runtime clock.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn SecurityClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Check every external authority and all persistent restrictive stores.
    pub fn ensure_ready(&self) -> Result<ActiveDefenseOverlayInventory, ActiveDefenseInstallError> {
        self.readiness
            .ensure_ready()
            .map_err(ActiveDefenseInstallError::RuntimeNotReady)?;
        self.state
            .active_defense_overlay_inventory()
            .map_err(|error| ActiveDefenseInstallError::StateNotReady(error.to_string()))
    }

    pub(crate) fn install_pre_invocation(&self, kernel: &mut ChioKernel) {
        let missing_context = MissingContextPolicy::Deny;
        kernel.add_guard(Box::new(TripwireGuard::new(
            Arc::clone(&self.tripwire_detector),
            Arc::clone(&self.tripwire_publisher),
            missing_context,
        )));
        kernel.add_guard(Box::new(ContainmentGuard::new(
            self.state.clone(),
            missing_context,
        )));
        kernel.add_guard(Box::new(CapabilitySetSuspensionGuard::new(
            self.state.clone(),
            missing_context,
        )));
        kernel.add_guard(Box::new(EgressRestrictionGuard::new(
            self.state.clone(),
            missing_context,
        )));
        kernel.add_guard(Box::new(FlowPreInvocationGuard::new(
            Arc::clone(&self.flow_pre_invocation),
            missing_context,
        )));
        kernel.add_guard(Box::new(SessionThrottleGuard::new(
            self.state.clone(),
            Arc::clone(&self.clock),
            missing_context,
        )));
    }

    pub(crate) fn raw_output_pipeline(&self) -> PostInvocationPipeline {
        let mut pipeline = PostInvocationPipeline::new();
        pipeline.add(Box::new(RawOutputTripwireHook::new(
            Arc::clone(&self.tripwire_detector),
            Arc::clone(&self.tripwire_publisher),
            MissingContextPolicy::Deny,
        )));
        pipeline
    }

    pub(crate) fn append_flow_post_invocation(&self, pipeline: &mut PostInvocationPipeline) {
        pipeline.add(Box::new(FlowPostInvocationHook::new(
            Arc::clone(&self.flow_post_invocation),
            MissingContextPolicy::Deny,
        )));
    }

    pub(crate) fn install_dispatch_and_issuance(
        &self,
        kernel: &mut ChioKernel,
    ) -> Result<(), ActiveDefenseInstallError> {
        kernel.set_capability_issuance_admission_authority(Arc::new(
            IssuanceFreezeAdmission::new(self.state.clone()),
        ))?;
        kernel.set_security_pre_dispatch_hook(Arc::new(FlowPreDispatchHook::new(Arc::clone(
            &self.flow_pre_dispatch,
        ))));
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_invocation_context_authority(Arc::clone(
            &self.security_context_authority,
        ));
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::policy;
    use chio_core::{Ed25519Backend, Keypair};
    use chio_flow::FlowDenial;
    use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};
    use chio_security_kernel::{
        FlowPostInvocationInput, FlowPreDispatchInput, FlowPreInvocationInput, SecurityEventIngress,
    };
    use chio_security_types::ports::{
        EventAppend, PortResult, ProducerId, RecordId, TripwireDecision, TripwireInput,
        UnverifiedSecurityEvent,
    };

    struct ReadyRuntime;

    impl ActiveDefenseRuntimeReadiness for ReadyRuntime {
        fn ensure_ready(&self) -> Result<(), String> {
            Ok(())
        }
    }

    struct UnreadyRuntime;

    impl ActiveDefenseRuntimeReadiness for UnreadyRuntime {
        fn ensure_ready(&self) -> Result<(), String> {
            Err("verified manifest registry is unavailable".to_string())
        }
    }

    struct ClearDetector;

    impl TripwireDetectorPort for ClearDetector {
        fn detect(&self, _input: &TripwireInput) -> PortResult<TripwireDecision> {
            Ok(TripwireDecision::Clear)
        }
    }

    struct AcceptingIngress;

    impl SecurityEventIngress for AcceptingIngress {
        fn verify_and_append(&self, _event: &UnverifiedSecurityEvent) -> PortResult<EventAppend> {
            Ok(EventAppend::Inserted)
        }
    }

    struct AllowFlow;

    impl FlowPreInvocationPort for AllowFlow {
        fn evaluate(&self, _input: &FlowPreInvocationInput<'_>) -> Result<(), FlowDenial> {
            Ok(())
        }
    }

    impl FlowPreDispatchPort for AllowFlow {
        fn commit(
            &self,
            _input: &FlowPreDispatchInput<'_>,
        ) -> Result<Option<Box<dyn chio_security_kernel::FlowDispatchOutcomeRecorder>>, FlowDenial>
        {
            Ok(None)
        }
    }

    impl FlowPostInvocationPort for AllowFlow {
        fn evaluate(&self, _input: &FlowPostInvocationInput<'_>) -> Result<(), FlowDenial> {
            Ok(())
        }
    }

    struct ConfiguredAllowGuard;

    struct UncalledSecurityContextAuthority;

    impl SecurityInvocationContextAuthority for UncalledSecurityContextAuthority {
        fn resolve_security_invocation_context(
            &self,
            _context: &chio_core::session::OperationContext,
            _operation: &chio_core::session::ToolCallOperation,
        ) -> Result<chio_kernel::SecurityInvocationContext, KernelError> {
            Err(KernelError::Internal(
                "test security context authority was unexpectedly called".to_string(),
            ))
        }
    }

    impl Guard for ConfiguredAllowGuard {
        fn name(&self) -> &str {
            "configured-allow"
        }

        fn evaluate(&self, _context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::allow())
        }
    }

    fn runtime(
        directory: &tempfile::TempDir,
        readiness: Arc<dyn ActiveDefenseRuntimeReadiness>,
    ) -> ActiveDefenseRuntime {
        let state = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("security.sqlite3"))
                .expect("open security state"),
        );
        let publisher = Arc::new(
            TripwireEventPublisher::new(
                Arc::new(AcceptingIngress),
                Arc::new(SystemSecurityClock),
                Arc::new(Ed25519Backend::new(Keypair::from_seed(&[37; 32]))),
                ProducerId::new("control-plane-active-defense").expect("producer id"),
                RecordId::new("control-plane-active-defense-key-v1").expect("key id"),
                RecordId::new("control-plane-active-defense-policy-v1").expect("policy id"),
            )
            .expect("build tripwire publisher"),
        );
        let flow = Arc::new(AllowFlow);
        ActiveDefenseRuntime::new(
            state,
            readiness,
            Arc::new(ClearDetector),
            publisher,
            flow.clone(),
            flow.clone(),
            flow,
            Arc::new(UncalledSecurityContextAuthority),
        )
    }

    fn loaded_policy() -> policy::LoadedPolicy {
        let mut guard_pipeline = chio_guards::GuardPipeline::new();
        guard_pipeline.add(Box::new(ConfiguredAllowGuard));
        let mut post_invocation_pipeline = PostInvocationPipeline::new();
        post_invocation_pipeline.add(Box::new(chio_guards::SanitizerHook::new()));
        policy::LoadedPolicy {
            format: policy::PolicyFormat::ChioYaml,
            identity: policy::PolicyIdentity {
                source_hash: "source".to_string(),
                runtime_hash: "runtime".to_string(),
            },
            kernel: policy::KernelPolicyConfig::default(),
            default_capabilities: Vec::new(),
            guard_pipeline,
            post_invocation_pipeline,
            issuance_policy: None,
            runtime_assurance_policy: None,
            threshold_approval: None,
        }
    }

    #[test]
    fn active_defense_builder_installs_exact_boundary_order() {
        let directory = tempfile::tempdir().expect("create tempdir");
        let kernel = crate::build_kernel_with_active_defense(
            loaded_policy(),
            &Keypair::generate(),
            runtime(&directory, Arc::new(ReadyRuntime)),
        )
        .expect("build active-defense kernel");

        assert_eq!(
            &kernel.guard_names()[..6],
            [
                "chio-tripwire-pre-invocation",
                "chio-containment-overlay",
                "chio-capability-set-suspension",
                "chio-egress-restriction",
                "chio-flow-pre-invocation",
                "chio-session-throttle",
            ]
        );
        assert_eq!(kernel.guard_names().last(), Some(&"guard-pipeline"));
        assert_eq!(
            kernel.post_invocation_hook_names(),
            [
                "chio-watermark-tripwire",
                "output-sanitizer",
                "output-sanitizer",
                "chio-flow-post-invocation",
            ]
        );
        assert_eq!(
            kernel.security_pre_dispatch_policy(),
            SecurityPreDispatchPolicy::Enforce
        );
        assert_eq!(
            kernel.security_pre_dispatch_hook_name(),
            Some("chio-flow-pre-dispatch")
        );
    }

    #[test]
    fn active_defense_builder_refuses_unready_runtime() {
        let directory = tempfile::tempdir().expect("create tempdir");
        let result = crate::build_kernel_with_active_defense(
            loaded_policy(),
            &Keypair::generate(),
            runtime(&directory, Arc::new(UnreadyRuntime)),
        );
        let error = match result {
            Ok(_) => panic!("unready runtime must fail closed"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ActiveDefenseInstallError::RuntimeNotReady(message)
                if message == "verified manifest registry is unavailable"
        ));
    }
}
