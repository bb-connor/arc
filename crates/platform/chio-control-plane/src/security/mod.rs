#[cfg(test)]
mod active_defense_host_tests;
mod active_response;
#[cfg(unix)]
mod active_response_authority;
mod active_response_validation;
pub mod adapters;
pub mod broker;
#[cfg(unix)]
mod broker_composition;
mod broker_runtime;
mod correlation;
#[cfg(feature = "enterprise-conformance")]
mod enterprise_conformance;
mod event_consumer;
mod migration;
pub mod migration_evidence;
mod orchestration;
#[cfg(unix)]
mod production_runtime;
mod runtime;
#[cfg(test)]
mod runtime_tests;
mod scheduler_worker;

pub use active_response::{
    DurableActiveResponseExecutor, DurableActiveResponseExecutorConfigError,
    MAX_ACTIVE_RESPONSE_LEASE_DURATION_MS,
};
#[cfg(unix)]
pub use active_response_authority::{
    active_response_authority_request_signing_bytes,
    active_response_authority_response_signing_bytes, ActiveResponseAdmissionArtifactsDraftWire,
    ActiveResponseAdmissionArtifactsWire, ActiveResponseAffectedIds, ActiveResponseApprovalTokens,
    ActiveResponseAuthorityHandler, ActiveResponseAuthorityOperation,
    ActiveResponseAuthorityProtocolServer, ActiveResponseAuthorityProtocolServerConfig,
    ActiveResponseAuthorityRejection, ActiveResponseAuthorityRejectionClass,
    ActiveResponseAuthorityRequestBody, ActiveResponseAuthorityResponseBody,
    ActiveResponseAuthorityResult, ActiveResponseEffects, ActiveResponsePolicySelectionWire,
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
#[cfg(unix)]
pub use broker_composition::{
    DurableBrokerControlAuthority, ProductionBrokerActiveDefenseFileConfig,
    ProductionBrokerAdminFileConfig, ProductionBrokerClientFileConfig,
    ProductionBrokerHostDatabasePaths, ProductionBrokerKeyCustodyConfig,
    ProductionBrokerManifestRegistry, ProductionBrokerMigrationConfig,
    ProductionBrokerProductConfig, ProductionBrokerProductRuntime,
    ProductionBrokerProviderMigrationPosture, PRODUCTION_BROKER_PRODUCT_CONFIG_SCHEMA,
};
pub use broker_runtime::{
    BrokerOnlyToolRoute, BrokerReleaseReceiptPersistence, CombinedAuthorityBrokerRevocations,
    ReceiptStoreCapabilityLiveness,
};
pub use chio_kernel::{
    ActiveResponseArtifactAuthorityAttestation, ActiveResponseArtifactAuthorityAttestationBody,
};
pub use correlation::AttestedCorrelationWriter;
#[cfg(feature = "enterprise-conformance")]
pub use enterprise_conformance::{
    EnterpriseCompositionCoordinator, EnterpriseCompositionMutation,
    EnterpriseCompositionObservation,
};
pub use event_consumer::{
    AttestedFindingAdmissionArtifacts, AttestedFindingBatchPlanner,
    AttestedFindingResponsePolicyPlanner, AttestedFindingResponsePolicySelection,
    AttestedFindingResponseRecoveryLimits, CorrelationConsumerReport, CorrelationRuleReport,
    DurableAttestedFindingBatchPlanner, NativeSecurityEventVerifier, ProductionCorrelationConsumer,
    ReservedAttestedFindingResponseBatch, ReservedAttestedFindingResponsePlan,
    SecurityEventReceiptProjection, SecurityEventVerifierConfigError, TrustedSecurityEventProducer,
    TrustedSecurityEventReceiptProducer, VerifiedSecurityEventIngress,
    SECURITY_EVENT_RECEIPT_PROJECTION_VERSION,
};
#[cfg(test)]
pub(crate) use event_consumer::{
    AttestedFindingDispatchCommittedResume, AttestedFindingPreDispatchReconstruction,
    AttestedFindingResponseCompletionProof, AttestedFindingResponseCoordinator,
    PreparedAttestedFindingResponse,
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
#[cfg(test)]
pub(crate) use orchestration::ProductionSecurityStateAuthority;
pub use orchestration::{
    ProductionActiveDefenseBuildError, ProductionActiveDefenseConfig, ProductionActiveDefenseHost,
    ProductionActiveDefenseHostConfig, ProductionActiveDefenseHostError,
    ProductionActiveDefenseOrchestrator,
};
#[cfg(unix)]
pub use production_runtime::{
    ProductionClassificationRuleConfig, ProductionSecurityRuntimeFileConfig,
    ProductionTrustedWatermarkKeyConfig, ProductionWatermarkSourceContextConfig,
};
pub(crate) use runtime::install_security_runtime;
pub use runtime::{
    reject_unprotected_flow_manifest, ActiveDefenseMode, AuthorityDurability, SecurityDurability,
    SecurityInstallError, SecurityRuntime, SecurityRuntimeBuildError,
};
#[cfg(test)]
pub(crate) use runtime::{SecurityRuntimeAuthorityBundleBuilder, SecurityRuntimeParts};
pub use scheduler_worker::{
    ActiveDefenseServiceRegistry, ActiveDefenseServices, ProductionResponseSchedulerConfig,
    ProductionResponseWorker, ProductionResponseWorkerHandle, ProductionResponseWorkerLoopConfig,
    ResponseWorkerHealth, ResponseWorkerLifecycle, ResponseWorkerPort, ResponseWorkerTick,
    ResponseWorkerTickError, SqliteResponseWorkerPort,
};
