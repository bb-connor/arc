use std::collections::BTreeMap;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chio_core::crypto::Keypair;
use chio_core::crypto::SigningBackend;
use chio_errors::_generated::error_codes::{
    ATTEST_PROVENANCE_MISSING, CAPABILITY_SCOPE_EXCEEDED, CAPABILITY_SUBJECT_MISMATCH, CLI_IO,
    CLI_JSON, CLI_OTHER, CLI_YAML, GUARD_DENIED, GUARD_WASM_TRAP, MANIFEST_SCHEMA_INVALID,
    MANIFEST_SIGNATURE_INVALID, POLICY_CONSTRAINT_INVALID, POLICY_DECISION_DENIED,
    PROVIDER_TOOL_SERVER_ERROR, REPLAY_DETERMINISTIC_MISMATCH, REPLAY_FIXTURE_DRIFT,
    REPLAY_TRACE_NOT_FOUND, TRANSPORT_HTTP_FAILED, TRANSPORT_INVALID_REQUEST_SHAPE,
};
use chio_errors::{ChioError, ErrorCodeSpec};
use chio_kernel::transport::TransportError;
use chio_kernel::{ChioKernel, KernelConfig, StructuredErrorReport};
use chio_security_types::ports::{Digest32, RecordId};
use chio_security_types::{
    EnterpriseMigrationControl, EnterpriseMigrationKey, EnterpriseMigrationMinimumHead,
    EnterpriseMigrationScopeKind, EnterpriseMigrationStage, EnterpriseMigrationStateStore,
};
use chio_store_sqlite::{SqliteEnterpriseMigrationOpenPolicy, SqliteEnterpriseMigrationStateStore};

pub use chio_agent_web_interop as agent_web;
pub use chio_commerce_order as commerce_order;
pub use chio_enterprise_export as enterprise_export;
pub use chio_risk_comptroller as risk_comptroller;
pub use chio_transaction_passport as transaction_passport;
pub use chio_trust_market_context as trust_market;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
pub enum JwtProviderProfile {
    Generic,
    Auth0,
    Okta,
    AzureAd,
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Core(#[from] chio_core::error::Error),

    #[error("{0}")]
    Policy(#[from] policy::PolicyError),

    #[error("adapter error: {0}")]
    Adapter(#[from] chio_mcp_adapter::edge::AdapterError),

    #[error("kernel error: {0}")]
    Kernel(#[from] chio_kernel::KernelError),

    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] chio_kernel::CheckpointError),

    #[error("evidence export error: {0}")]
    EvidenceExport(#[from] chio_kernel::EvidenceExportError),

    #[error("credential error: {0}")]
    Credential(#[from] chio_credentials::CredentialError),

    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] chio_kernel::ReceiptStoreError),

    #[error("conformance load error: {0}")]
    ConformanceLoad(#[from] chio_conformance::LoadError),

    #[error("revocation store error: {0}")]
    RevocationStore(#[from] chio_kernel::RevocationStoreError),

    #[error("authority store error: {0}")]
    AuthorityStore(#[from] chio_kernel::AuthorityStoreError),

    #[error("budget store error: {0}")]
    BudgetStore(#[from] chio_kernel::BudgetStoreError),

    #[error("agent-economy budget store error: {0}")]
    AgentEconomyBudgetStore(#[from] chio_kernel::agent_economy_budget_store::BudgetStoreError),

    #[error("agent-economy admission operation error: {0}")]
    AgentEconomyAdmissionOperation(
        #[from] chio_kernel::admission_operation::AdmissionOperationError,
    ),

    #[error("sqlite serving-owner error: {0}")]
    SqliteServingOwner(#[from] chio_store_sqlite::SqliteServingOwnerError),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yml::Error),

    #[error("http error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("{0}")]
    Chio(#[from] ChioError),

    #[error("{0}")]
    Other(String),
}

impl CliError {
    pub fn registry_error(spec: &'static ErrorCodeSpec, message: impl Into<String>) -> Self {
        Self::Chio(ChioError::from_spec(spec, message))
    }

    pub fn capability_error(message: impl Into<String>) -> Self {
        Self::cli_other_error(message)
    }

    pub fn capability_scope_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CAPABILITY_SCOPE_EXCEEDED, message)
    }

    pub fn capability_subject_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CAPABILITY_SUBJECT_MISMATCH, message)
    }

    pub fn policy_error(message: impl Into<String>) -> Self {
        Self::registry_error(&POLICY_DECISION_DENIED, message)
    }

    pub fn policy_constraint_error(message: impl Into<String>) -> Self {
        Self::registry_error(&POLICY_CONSTRAINT_INVALID, message)
    }

    pub fn guard_error(message: impl Into<String>) -> Self {
        Self::registry_error(&GUARD_DENIED, message)
    }

    pub fn guard_wasm_error(message: impl Into<String>) -> Self {
        Self::registry_error(&GUARD_WASM_TRAP, message)
    }

    pub fn replay_trace_error(message: impl Into<String>) -> Self {
        Self::registry_error(&REPLAY_TRACE_NOT_FOUND, message)
    }

    pub fn replay_mismatch_error(message: impl Into<String>) -> Self {
        Self::registry_error(&REPLAY_DETERMINISTIC_MISMATCH, message)
    }

    pub fn replay_fixture_error(message: impl Into<String>) -> Self {
        Self::registry_error(&REPLAY_FIXTURE_DRIFT, message)
    }

    pub fn provider_error(message: impl Into<String>) -> Self {
        Self::registry_error(&PROVIDER_TOOL_SERVER_ERROR, message)
    }

    pub fn attest_error(message: impl Into<String>) -> Self {
        Self::registry_error(&ATTEST_PROVENANCE_MISSING, message)
    }

    pub fn manifest_schema_error(message: impl Into<String>) -> Self {
        Self::registry_error(&MANIFEST_SCHEMA_INVALID, message)
    }

    pub fn manifest_signature_error(message: impl Into<String>) -> Self {
        Self::registry_error(&MANIFEST_SIGNATURE_INVALID, message)
    }

    pub fn transport_error(message: impl Into<String>) -> Self {
        Self::registry_error(&TRANSPORT_HTTP_FAILED, message)
    }

    pub fn transport_shape_error(message: impl Into<String>) -> Self {
        Self::registry_error(&TRANSPORT_INVALID_REQUEST_SHAPE, message)
    }

    pub fn cli_io_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CLI_IO, message)
    }

    pub fn cli_json_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CLI_JSON, message)
    }

    pub fn cli_yaml_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CLI_YAML, message)
    }

    pub fn cli_other_error(message: impl Into<String>) -> Self {
        Self::registry_error(&CLI_OTHER, message)
    }

    fn report_with_context(
        &self,
        code: &str,
        context: serde_json::Value,
        suggested_fix: impl Into<String>,
    ) -> StructuredErrorReport {
        StructuredErrorReport::new(code, self.to_string(), context, suggested_fix)
    }

    pub fn report(&self) -> StructuredErrorReport {
        match self {
            Self::Core(error) => self.report_with_context(
                "CHIO-CLI-CORE",
                serde_json::json!({ "source": error.to_string() }),
                "Inspect the Chio artifact or request payload that triggered the core validation failure and correct it before retrying.",
            ),
            Self::Policy(error) => self.report_with_context(
                "CHIO-CLI-POLICY",
                serde_json::json!({ "source": error.to_string() }),
                "Fix the policy file contents or path so the requested command can load a valid policy document.",
            ),
            Self::Adapter(error) => self.report_with_context(
                "CHIO-CLI-ADAPTER",
                serde_json::json!({ "source": error.to_string() }),
                "Inspect the MCP adapter configuration and upstream server compatibility before retrying.",
            ),
            Self::Kernel(error) => error.report(),
            Self::Checkpoint(error) => self.report_with_context(
                "CHIO-CLI-CHECKPOINT",
                serde_json::json!({ "source": error.to_string() }),
                "Check the checkpoint input and configured receipt store, then retry once the checkpoint lane is valid.",
            ),
            Self::EvidenceExport(error) => self.report_with_context(
                "CHIO-CLI-EVIDENCE-EXPORT",
                serde_json::json!({ "source": error.to_string() }),
                "Inspect the evidence export inputs, output path, and receipt-store state before retrying.",
            ),
            Self::Credential(error) => self.report_with_context(
                "CHIO-CLI-CREDENTIAL",
                serde_json::json!({ "source": error.to_string() }),
                "Validate the credential, issuer, and subject inputs before retrying the command.",
            ),
            Self::ReceiptStore(error) => self.report_with_context(
                "CHIO-CLI-RECEIPT-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured receipt store path, permissions, and schema health before retrying.",
            ),
            Self::ConformanceLoad(error) => self.report_with_context(
                "CHIO-CLI-CONFORMANCE-LOAD",
                serde_json::json!({ "source": error.to_string() }),
                "Fix the conformance corpus path or file contents so the requested scenarios can be loaded successfully.",
            ),
            Self::RevocationStore(error) => self.report_with_context(
                "CHIO-CLI-REVOCATION-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured revocation store path, permissions, and schema health before retrying.",
            ),
            Self::AuthorityStore(error) => self.report_with_context(
                "CHIO-CLI-AUTHORITY-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured authority store path, permissions, and schema health before retrying.",
            ),
            Self::BudgetStore(error) => self.report_with_context(
                "CHIO-CLI-BUDGET-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the configured budget store path, permissions, and schema health before retrying.",
            ),
            Self::AgentEconomyBudgetStore(error) => self.report_with_context(
                "CHIO-CLI-AGENT-ECONOMY-BUDGET-STORE",
                serde_json::json!({ "source": error.to_string() }),
                "Restore the durable agent-economy budget authority invariant before retrying.",
            ),
            Self::AgentEconomyAdmissionOperation(error) => self.report_with_context(
                "CHIO-CLI-AGENT-ECONOMY-ADMISSION",
                serde_json::json!({ "source": error.to_string() }),
                "Restore the durable agent-economy admission operation invariant before retrying.",
            ),
            Self::SqliteServingOwner(error) => self.report_with_context(
                "CHIO-CLI-SQLITE-SERVING-OWNER",
                serde_json::json!({ "source": error.to_string() }),
                "Restore the provisioned SQLite serving-owner identity and exclusive lease before retrying.",
            ),
            Self::Sqlite(error) => self.report_with_context(
                "CHIO-CLI-SQLITE",
                serde_json::json!({ "source": error.to_string() }),
                "Check the SQLite path, file permissions, and database schema state before retrying.",
            ),
            Self::Transport(error) => self.report_with_context(
                "CHIO-CLI-TRANSPORT",
                serde_json::json!({ "source": error.to_string() }),
                "Verify the remote endpoint or subprocess transport is reachable and speaking the expected protocol.",
            ),
            Self::Io(error) => self.report_with_context(
                "CHIO-CLI-IO",
                serde_json::json!({ "source": error.to_string() }),
                "Check file paths, permissions, and parent directories before retrying.",
            ),
            Self::Json(error) => self.report_with_context(
                "CHIO-CLI-JSON",
                serde_json::json!({ "source": error.to_string() }),
                "Fix the JSON input so it is syntactically valid and matches the expected Chio schema.",
            ),
            Self::Yaml(error) => self.report_with_context(
                "CHIO-CLI-YAML",
                serde_json::json!({ "source": error.to_string() }),
                "Fix the YAML syntax or schema mismatch in the provided configuration before retrying.",
            ),
            Self::Reqwest(error) => self.report_with_context(
                "CHIO-CLI-HTTP",
                serde_json::json!({ "source": error.to_string() }),
                "Check network reachability, TLS settings, and remote endpoint availability before retrying.",
            ),
            Self::Chio(error) => {
                let diagnostic = error.diagnostic();
                let spec = diagnostic.registry_spec();
                StructuredErrorReport::new(
                    diagnostic.code().as_str(),
                    diagnostic.message(),
                    serde_json::json!({
                        "domain": diagnostic.domain().as_str(),
                        "severity": diagnostic.severity().as_str(),
                        "string_code": spec.map(|entry| entry.string_code),
                        "stability": spec.map(|entry| entry.stability),
                    }),
                    diagnostic
                        .help()
                        .or_else(|| spec.map(|entry| entry.help))
                        .unwrap_or(
                            "Inspect the Chio diagnostic and retry after correcting the request.",
                        ),
                )
            }
            Self::Other(message) => self.report_with_context(
                "CHIO-CLI-OTHER",
                serde_json::json!({ "detail": message }),
                "Read the error detail, correct the conflicting inputs or missing prerequisite, and retry the command.",
            ),
        }
    }
}

pub fn build_kernel(
    loaded_policy: policy::LoadedPolicy,
    kernel_kp: &Keypair,
) -> Result<ChioKernel, CliError> {
    build_kernel_with_security_runtime(loaded_policy, kernel_kp, None)
}

pub fn build_kernel_with_security_runtime(
    loaded_policy: policy::LoadedPolicy,
    kernel_kp: &Keypair,
    security_runtime: Option<security::SecurityRuntime>,
) -> Result<ChioKernel, CliError> {
    build_kernel_with_security_runtime_backend_and_hooks(
        loaded_policy,
        kernel_kp,
        security_runtime,
        None,
        |_| Ok(()),
        |_| Ok(()),
    )
}

pub fn build_kernel_with_external_authority_signing_runtime(
    loaded_policy: policy::LoadedPolicy,
    bootstrap_keypair: &Keypair,
    backend: Arc<dyn SigningBackend>,
    resolver: Arc<dyn chio_kernel::authority::AuthorityArtifactTrustResolver>,
    security_runtime: Option<security::SecurityRuntime>,
) -> Result<ChioKernel, CliError> {
    build_kernel_with_security_runtime_backend_and_hooks(
        loaded_policy,
        bootstrap_keypair,
        security_runtime,
        Some(BoundAuthoritySigningRuntime {
            backend,
            resolver,
            external: true,
        }),
        |_| Ok(()),
        |_| Ok(()),
    )
}

struct BoundAuthoritySigningRuntime {
    backend: Arc<dyn SigningBackend>,
    resolver: Arc<dyn chio_kernel::authority::AuthorityArtifactTrustResolver>,
    external: bool,
}

fn build_kernel_with_security_runtime_backend_and_hooks<Before, After>(
    loaded_policy: policy::LoadedPolicy,
    kernel_kp: &Keypair,
    security_runtime: Option<security::SecurityRuntime>,
    authority_signing_runtime: Option<BoundAuthoritySigningRuntime>,
    before_security_publication: Before,
    after_security_publication: After,
) -> Result<ChioKernel, CliError>
where
    Before: FnOnce(&mut ChioKernel) -> Result<(), CliError>,
    After: FnOnce(&mut ChioKernel) -> Result<(), CliError>,
{
    let policy::LoadedPolicy {
        identity,
        kernel: kernel_policy,
        guard_pipeline,
        post_invocation_pipeline,
        runtime_assurance_policy,
        threshold_approval_resolver,
        threshold_approval_policy_authority,
        active_defense,
        ..
    } = loaded_policy;

    let threshold_policy_authorities = match (
        threshold_approval_resolver.as_ref(),
        threshold_approval_policy_authority,
    ) {
        (Some(_), Some(authority)) => vec![authority],
        (Some(_), None) => {
            return Err(CliError::cli_other_error(
                "threshold approval policy requires an explicit proposal-authority public key"
                    .to_string(),
            ));
        }
        (None, Some(_)) => {
            return Err(CliError::cli_other_error(
                "threshold proposal authority was configured without a threshold approval policy"
                    .to_string(),
            ));
        }
        (None, None) => Vec::new(),
    };

    let config = KernelConfig {
        keypair: kernel_kp.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: kernel_policy.delegation_depth_limit,
        policy_hash: identity.runtime_hash,
        allow_sampling: kernel_policy.allow_sampling,
        allow_sampling_tool_use: kernel_policy.allow_sampling_tool_use,
        allow_elicitation: kernel_policy.allow_elicitation,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: kernel_policy.require_web3_evidence,
        allow_ephemeral_receipt_log: kernel_policy.allow_ephemeral_receipt_log,
        allow_ephemeral_revocation_store: kernel_policy.allow_ephemeral_revocation_store,
        checkpoint_batch_size: kernel_policy.checkpoint_batch_size,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: kernel_policy.dispatch_intent_journal,
    };

    let mut kernel = match authority_signing_runtime {
        Some(runtime) if runtime.external => {
            ChioKernel::new_with_external_authority_signing_runtime(
                config,
                runtime.backend,
                runtime.resolver,
            )
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
        }
        Some(runtime) => ChioKernel::new_with_authority_signing_runtime(
            config,
            runtime.backend,
            runtime.resolver,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        None => ChioKernel::new(config),
    };
    kernel.configure_durable_admission(
        kernel_policy.durable_admission_mode,
        kernel_policy.allow_unsafe_durable_admission_off,
    )?;
    before_security_publication(&mut kernel)?;

    let threshold_approval_resolver = threshold_approval_resolver.map(|resolver| {
        Arc::new(resolver)
            as Arc<dyn chio_kernel::threshold_approval::ThresholdApprovalRequirementResolver>
    });

    security::install_security_runtime(
        &mut kernel,
        active_defense.mode,
        security_runtime,
        threshold_approval_resolver.clone(),
        threshold_policy_authorities.clone(),
        chio_guards::default_runtime_guard_profile(),
        guard_pipeline,
        post_invocation_pipeline,
    )
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;

    if let Some(attestation_trust_policy) =
        runtime_assurance_policy.and_then(|policy| policy.attestation_trust_policy)
    {
        kernel.set_attestation_trust_policy(attestation_trust_policy);
    }

    if !matches!(active_defense.mode, security::ActiveDefenseMode::Enforce) {
        if let Some(resolver) = threshold_approval_resolver {
            kernel.set_threshold_approval_requirement_resolver(resolver)?;
            kernel.set_threshold_approval_policy_authorities(threshold_policy_authorities)?;
        }
    }
    after_security_publication(&mut kernel)?;

    Ok(kernel)
}

#[cfg(unix)]
/// Durable host stores used by the keyring-backed production broker topology.
#[derive(Clone, Copy)]
pub struct ProductionBrokerKernelHostConfig<'a> {
    pub receipt_database_path: &'a Path,
    pub revocation_database_path: &'a Path,
    pub budget_database_path: &'a Path,
    pub authority_seed_path: Option<&'a Path>,
    pub authority_database_path: Option<&'a Path>,
}

pub fn build_kernel_with_keyring_composition(
    loaded_policy: policy::LoadedPolicy,
    kernel_kp: &Keypair,
    composition: &KeyringRuntimeComposition,
) -> Result<ChioKernel, CliError> {
    build_kernel_with_keyring_composition_and_security_runtime(
        loaded_policy,
        kernel_kp,
        composition,
        None,
    )
}

pub fn build_kernel_with_keyring_composition_and_security_runtime(
    loaded_policy: policy::LoadedPolicy,
    kernel_kp: &Keypair,
    composition: &KeyringRuntimeComposition,
    security_runtime: Option<security::SecurityRuntime>,
) -> Result<ChioKernel, CliError> {
    composition.ensure_bound_signing_topology()?;
    let authority_signing_runtime = BoundAuthoritySigningRuntime {
        backend: composition.authority_signing_backend(),
        resolver: composition.authority_artifact_trust_resolver()?,
        external: false,
    };
    build_kernel_with_security_runtime_backend_and_hooks(
        loaded_policy,
        kernel_kp,
        security_runtime,
        Some(authority_signing_runtime),
        |_| Ok(()),
        |_| Ok(()),
    )
}

/// Keyring-backed variant of the atomic production broker construction.
#[cfg(unix)]
pub fn build_kernel_with_keyring_composition_and_production_broker_security_runtime(
    loaded_policy: policy::LoadedPolicy,
    kernel_kp: &Keypair,
    composition: &KeyringRuntimeComposition,
    broker: &security::ProductionBrokerProductRuntime,
    security_runtime: security::SecurityRuntime,
    host: ProductionBrokerKernelHostConfig<'_>,
) -> Result<ChioKernel, CliError> {
    composition.ensure_bound_signing_topology()?;
    let resolved_host = broker
        .resolve_host_database_paths(
            Some(host.receipt_database_path),
            Some(host.revocation_database_path),
            Some(host.budget_database_path),
            None,
            host.authority_database_path,
            None,
            None,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let bound_host = ProductionBrokerKernelHostConfig {
        receipt_database_path: &resolved_host.receipt_database_path,
        revocation_database_path: &resolved_host.revocation_database_path,
        budget_database_path: &resolved_host.budget_database_path,
        authority_seed_path: host.authority_seed_path,
        authority_database_path: host.authority_database_path,
    };
    let issuance_policy = loaded_policy.issuance_policy.clone();
    let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();
    let authority_signing_runtime = BoundAuthoritySigningRuntime {
        backend: composition.authority_signing_backend(),
        resolver: composition.authority_artifact_trust_resolver()?,
        external: false,
    };
    build_kernel_with_security_runtime_backend_and_hooks(
        loaded_policy,
        kernel_kp,
        Some(security_runtime),
        Some(authority_signing_runtime),
        |kernel| {
            let receipt_store = configure_production_broker_kernel_host(
                kernel,
                bound_host,
                issuance_policy,
                runtime_assurance_policy,
            )?;
            broker
                .validate_kernel_receipt_store_binding(receipt_store.as_ref())
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            composition.attach_receipt_store(receipt_store)?;
            broker
                .install_kernel_authorities_before_security_publication(kernel)
                .map_err(|error| CliError::cli_other_error(error.to_string()))
        },
        |kernel| {
            broker
                .validate_host_database_bindings()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            broker
                .register_kernel_route_after_security_publication(kernel)
                .map_err(|error| CliError::cli_other_error(error.to_string()))
        },
    )
}

#[cfg(unix)]
fn configure_production_broker_kernel_host(
    kernel: &mut ChioKernel,
    host: ProductionBrokerKernelHostConfig<'_>,
    issuance_policy: Option<policy::ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<policy::RuntimeAssuranceIssuancePolicy>,
) -> Result<Arc<dyn chio_kernel::ReceiptStore>, CliError> {
    let receipt_store = configure_receipt_store(
        kernel,
        Some(host.receipt_database_path),
        None,
        None,
        None,
        &[],
    )?
    .ok_or_else(|| {
        CliError::cli_other_error(
            "production broker kernel requires a durable normal receipt store".to_string(),
        )
    })?;
    configure_revocation_store(kernel, Some(host.revocation_database_path), None, None)?;
    configure_capability_authority(
        kernel,
        host.authority_seed_path,
        host.authority_database_path,
        Some(host.receipt_database_path),
        Some(host.budget_database_path),
        None,
        None,
        None,
        &[],
        None,
        issuance_policy,
        runtime_assurance_policy,
    )?;
    Ok(receipt_store)
}

#[derive(Clone)]
pub struct KeyringRuntimeComposition {
    router: Arc<chio_keyring::KeyringSigningRouter>,
    store: Arc<chio_keyring::SqliteKeyLogStore>,
    independent_services: Arc<chio_keyring::IndependentKeyLogServices>,
    rotation_runtime: Arc<chio_keyring::WitnessedRotationRuntime>,
    startup_readiness: chio_keyring::IndependentOperationReadiness,
    migration_binding: security::EnterpriseMigrationRuntimeBinding,
    authority_backend: Arc<MigrationGuardedSigningBackend>,
    operator_backend: Arc<dyn SigningBackend>,
    receipt_store: Arc<Mutex<Option<AttachedReceiptStore>>>,
    authority_rotation_lock: Arc<Mutex<()>>,
}

#[derive(Clone)]
struct MigrationGuardedSigningBackend {
    inner: Arc<dyn SigningBackend>,
    migration_binding: security::EnterpriseMigrationRuntimeBinding,
}

impl MigrationGuardedSigningBackend {
    fn require_enforced(&self) -> chio_core::error::Result<()> {
        self.migration_binding.require_enforced().map_err(|error| {
            chio_core::error::Error::InvalidSignature(format!(
                "key-log verification migration denied keyring signing: {error}"
            ))
        })
    }
}

impl SigningBackend for MigrationGuardedSigningBackend {
    fn algorithm(&self) -> chio_core::SigningAlgorithm {
        self.inner.algorithm()
    }

    fn public_key(&self) -> chio_core::PublicKey {
        self.inner.public_key()
    }

    fn sign_bytes(&self, message: &[u8]) -> chio_core::error::Result<chio_core::Signature> {
        self.require_enforced()?;
        let signature = self.inner.sign_bytes(message)?;
        self.require_enforced()?;
        Ok(signature)
    }

    fn sign_bytes_with_identity(
        &self,
        message: &[u8],
    ) -> chio_core::error::Result<chio_core::crypto::SigningOutcome> {
        self.require_enforced()?;
        let outcome = self.inner.sign_bytes_with_identity(message)?;
        self.require_enforced()?;
        Ok(outcome)
    }

    fn sign_bytes_for_identity(
        &self,
        expected_key: &chio_core::PublicKey,
        message: &[u8],
    ) -> chio_core::error::Result<chio_core::crypto::SigningOutcome> {
        self.require_enforced()?;
        let outcome = self.inner.sign_bytes_for_identity(expected_key, message)?;
        self.require_enforced()?;
        Ok(outcome)
    }

    fn sign_canonical_bytes(
        &self,
        canonical: &chio_core::canonical::CanonicalBytes<
            chio_core::canonical::CanonicalJsonWitness,
        >,
    ) -> chio_core::error::Result<chio_core::Signature> {
        self.require_enforced()?;
        let signature = self.inner.sign_canonical_bytes(canonical)?;
        self.require_enforced()?;
        Ok(signature)
    }
}

impl chio_keyring::KeyLogActivationGuard for security::EnterpriseMigrationRuntimeBinding {
    fn require_activation(&self) -> chio_keyring::Result<()> {
        self.require_enforced().map_err(|_| {
            chio_keyring::KeyringError::StateInvariant(
                "key-log verification migration denied selector activation",
            )
        })
    }
}

#[derive(Clone, Debug)]
pub struct KeyringRuntimeAuthorityStatus {
    pub public_key: chio_core::PublicKey,
    pub signing_epoch: u64,
    pub activated_at: Option<u64>,
    pub witnessed_verification_keys: Vec<chio_core::PublicKey>,
    pub operator_head: Option<chio_keyring::KeyLogPin>,
    pub checkpoint_stage: Option<chio_keyring::CheckpointStage>,
    pub witness_service_count: usize,
    pub audit_service_count: usize,
}

#[derive(Clone)]
struct AttachedReceiptStore {
    identity: chio_core::Hash,
    store: Arc<dyn chio_kernel::ReceiptStore>,
}

fn attach_receipt_store_transactionally<F>(
    attachment: &Mutex<Option<AttachedReceiptStore>>,
    candidate: Arc<dyn chio_kernel::ReceiptStore>,
    backfill: F,
) -> Result<usize, CliError>
where
    F: FnOnce(&dyn chio_kernel::ReceiptStore) -> Result<usize, CliError>,
{
    let identity = candidate.durable_storage_identity()?.ok_or_else(|| {
        CliError::cli_other_error(
            "keyring receipt store must expose a durable commit-domain identity".to_string(),
        )
    })?;
    let mut configured = attachment.lock().map_err(|_| {
        CliError::cli_other_error(
            "keyring receipt-store attachment lock is unavailable".to_string(),
        )
    })?;
    if let Some(existing) = configured.as_ref() {
        if existing.identity != identity {
            return Err(CliError::cli_other_error(
                "keyring receipt store is already bound to a different durable commit domain"
                    .to_string(),
            ));
        }
        return backfill(existing.store.as_ref());
    }

    let appended = backfill(candidate.as_ref())?;
    *configured = Some(AttachedReceiptStore {
        identity,
        store: candidate,
    });
    Ok(appended)
}

impl KeyringRuntimeComposition {
    fn require_key_log_verification(&self) -> Result<(), CliError> {
        self.migration_binding.require_enforced().map_err(|error| {
            CliError::cli_other_error(format!(
                "key-log verification migration enforcement failed: {error}"
            ))
        })
    }

    pub(crate) fn ensure_bound_signing_topology(&self) -> Result<(), CliError> {
        self.require_key_log_verification()?;
        if !self.router.uses_store(&self.store) {
            return Err(CliError::cli_other_error(
                "keyring signing router and artifact trust resolver must share one durable store"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn key_log_synchronization_response(
        &self,
        base: Option<&chio_keyring::KeyLogPin>,
    ) -> Result<chio_keyring::KeyLogSyncResponse, CliError> {
        self.require_key_log_verification()?;
        self.store
            .synchronization_response(base)
            .map_err(|error| CliError::cli_other_error(error.to_string()))
    }

    #[must_use]
    pub(crate) fn authority_signing_backend(&self) -> Arc<dyn SigningBackend> {
        self.authority_backend.clone()
    }

    pub(crate) fn sign_authority_artifact_with_evidence(
        &self,
        expected_public_key: &chio_core::PublicKey,
        artifact: &[u8],
    ) -> Result<chio_keyring::KeyringSigningResult, CliError> {
        self.ensure_bound_signing_topology()?;
        let outcome = self
            .authority_backend
            .sign_bytes_for_identity(expected_public_key, artifact)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        self.require_key_log_verification()?;
        if outcome.public_key != *expected_public_key
            || outcome.algorithm != expected_public_key.algorithm()
            || outcome.signature.algorithm() != outcome.algorithm
        {
            return Err(CliError::cli_other_error(
                "keyring authority backend returned a mismatched signing identity".to_string(),
            ));
        }
        let result = self
            .router
            .persisted_signing_result_for_artifact(
                expected_public_key,
                artifact,
                &outcome.signature,
            )
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        self.require_key_log_verification()?;
        Ok(result)
    }

    pub fn authority_status(&self) -> Result<KeyringRuntimeAuthorityStatus, CliError> {
        self.require_key_log_verification()?;
        let public_key = self
            .router
            .active_public_key()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let signing_epoch = self
            .router
            .signing_epoch()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let state = self
            .store
            .load_state()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "keyring authority status requires a witnessed key-log state".to_string(),
                )
            })?;
        let active = state
            .active_signing_key()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        if active.public_key != public_key || state.signing_epoch() != signing_epoch {
            return Err(CliError::cli_other_error(
                "keyring selector does not match the witnessed key-log state".to_string(),
            ));
        }
        let witnessed_verification_keys = state
            .witnessed_verification_keys()
            .into_iter()
            .map(|record| record.public_key)
            .collect();
        Ok(KeyringRuntimeAuthorityStatus {
            public_key,
            signing_epoch,
            activated_at: (active.activated_at != 0).then_some(active.activated_at),
            witnessed_verification_keys,
            operator_head: self
                .store
                .head_pin()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
            checkpoint_stage: self
                .store
                .head_stage()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
            witness_service_count: self.independent_services.witnesses().len(),
            audit_service_count: self.independent_services.auditors().len(),
        })
    }

    pub fn startup_readiness(
        &self,
    ) -> Result<&chio_keyring::IndependentOperationReadiness, CliError> {
        self.require_key_log_verification()?;
        Ok(&self.startup_readiness)
    }

    fn authority_artifact_trust_resolver(
        &self,
    ) -> Result<Arc<dyn chio_kernel::AuthorityArtifactTrustResolver>, CliError> {
        self.ensure_bound_signing_topology()?;
        Ok(Arc::new(KeyringAuthorityArtifactTrustResolver {
            store: Arc::clone(&self.store),
            migration_binding: self.migration_binding.clone(),
        }))
    }

    pub fn attach_receipt_store(
        &self,
        receipt_store: Arc<dyn chio_kernel::ReceiptStore>,
    ) -> Result<usize, CliError> {
        self.require_key_log_verification()?;
        attach_receipt_store_transactionally(
            self.receipt_store.as_ref(),
            receipt_store,
            |retained| self.forward_enterprise_receipts(retained),
        )
    }

    pub fn forward_enterprise_receipts(
        &self,
        receipt_store: &dyn chio_kernel::ReceiptStore,
    ) -> Result<usize, CliError> {
        self.require_key_log_verification()?;
        let configuration_binding = self
            .store
            .configuration_binding()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let mut appended = 0;
        for enterprise_receipt in self
            .store
            .load_enterprise_receipts()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
        {
            self.require_key_log_verification()?;
            if persist_key_enterprise_receipt(
                &enterprise_receipt,
                self.operator_backend.as_ref(),
                configuration_binding,
                receipt_store,
                &self.migration_binding,
            )? {
                appended += 1;
            }
        }
        Ok(appended)
    }

    pub(crate) fn rotate_or_resume_authority(
        &self,
        new_keypair: &Keypair,
    ) -> Result<chio_keyring::WitnessedRotationOutcome, CliError> {
        self.require_key_log_verification()?;
        let new_inner: Arc<dyn SigningBackend> =
            Arc::new(chio_core::crypto::Ed25519Backend::new(new_keypair.clone()));
        let new_backend = MigrationGuardedSigningBackend {
            inner: new_inner,
            migration_binding: self.migration_binding.clone(),
        };
        let state = self
            .store
            .load_state()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .ok_or_else(|| {
                CliError::cli_other_error("keyring operator log is not initialized".to_string())
            })?;
        let mut pending = if state.pending_event_id().is_some() {
            self.require_key_log_verification()?;
            self.rotation_runtime
                .resume_pending_rotation(Box::new(new_backend.clone()))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
        } else {
            let previous = self
                .store
                .load_events()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
                .into_iter()
                .last()
                .ok_or_else(|| {
                    CliError::cli_other_error(
                        "keyring operator log has no authority event".to_string(),
                    )
                })?;
            let policy = self.store.policy_clone();
            let issued_at = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| {
                        CliError::cli_other_error("system time precedes the Unix epoch".to_string())
                    })?
                    .as_millis(),
            )
            .map_err(|_| {
                CliError::cli_other_error("system time exceeds key-log range".to_string())
            })?;
            let sequence = previous.body.sequence.checked_add(1).ok_or_else(|| {
                CliError::cli_other_error("key-log sequence overflow".to_string())
            })?;
            let new_public_key = new_backend.public_key();
            let body = chio_keyring::KeyLogEventBody {
                schema: chio_keyring::KEY_LOG_EVENT_SCHEMA.to_string(),
                log_id: policy.log_id().clone(),
                sequence,
                event_id: chio_keyring::EventId::new(format!(
                    "event.authority.rotation.{sequence}"
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                previous_event_hash: Some(
                    previous
                        .envelope_hash()
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                ),
                authority_id: policy.authority_id().clone(),
                key_id: chio_keyring::derive_key_id(new_backend.algorithm(), &new_public_key)
                    .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                algorithm: new_backend.algorithm(),
                public_key: new_public_key,
                operation: chio_keyring::KeyLogOperation::Rotate {
                    previous_key_id: state
                        .active_signing_key()
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?
                        .key_id,
                    witness_roster_id: policy.witness_roster_id().clone(),
                    witness_roster_binding: policy
                        .witness_roster_binding()
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                },
                effective_at: issued_at,
                verify_until: Some(issued_at.checked_add(86_400_000).ok_or_else(|| {
                    CliError::cli_other_error("key rotation validity overflow".to_string())
                })?),
                reason: Some(
                    chio_keyring::EventReason::new("remote authority admin rotation")
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                ),
                issued_at,
            };
            let event = chio_keyring::SignedKeyLogEvent {
                authorizations: chio_keyring::KeyLogAuthorizations::rotation(
                    chio_keyring::OldKeyAuthorization::sign(&body, self.authority_backend.as_ref())
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                    chio_keyring::NewKeyProofOfPossession::sign(&body, &new_backend)
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                ),
                body,
            };
            self.require_key_log_verification()?;
            self.rotation_runtime
                .begin_rotation(&event, Box::new(new_backend))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
        };
        self.require_key_log_verification()?;
        self.rotation_runtime
            .collect_witnesses_and_activate(&mut pending, &self.independent_services)
            .map_err(|error| CliError::cli_other_error(error.to_string()))
    }

    pub fn rotate_remote_authority_seed(
        &self,
        active_seed_path: &Path,
    ) -> Result<(chio_core::PublicKey, chio_keyring::WitnessedRotationOutcome), CliError> {
        self.require_key_log_verification()?;
        let _rotation = self.authority_rotation_lock.lock().map_err(|_| {
            CliError::cli_other_error("keyring authority rotation lock is unavailable".to_string())
        })?;
        let (active_keypair, active_identity) =
            load_existing_authority_keypair_with_identity(active_seed_path)?;
        let state = self
            .store
            .load_state()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .ok_or_else(|| {
                CliError::cli_other_error("keyring operator log is not initialized".to_string())
            })?;
        let active_record = state
            .active_signing_key()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let active_key_id = chio_keyring::derive_key_id(
            active_keypair.public_key().algorithm(),
            &active_keypair.public_key(),
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let pending_path = keyring_pending_authority_seed_path(active_seed_path);
        let pending = load_optional_authority_seed_handoff(&pending_path)?;
        if active_key_id != active_record.key_id {
            let Some((handoff, recovered, pending_identity)) = pending else {
                return Err(CliError::cli_other_error(
                    "authority seed identity does not match the durable active selector"
                        .to_string(),
                ));
            };
            handoff.validate_keypair(&recovered)?;
            if state.pending_event_id().is_some()
                || handoff.target_epoch != state.signing_epoch()
                || handoff.key_id != active_record.key_id.to_string()
            {
                return Err(CliError::cli_other_error(
                    "authority seed recovery is not bound to the active selector epoch".to_string(),
                ));
            }
            self.require_key_log_verification()?;
            write_authority_seed_file_bound(active_seed_path, &recovered, Some(&active_identity))?;
            self.require_key_log_verification()?;
            remove_authority_seed_handoff(&pending_path, &handoff, &pending_identity)?;
            return Ok((recovered.public_key(), self.current_rotation_outcome()?));
        }
        let (next_keypair, pending_identity, target_epoch) = match pending {
            Some((handoff, keypair, identity)) => {
                handoff.validate_keypair(&keypair)?;
                if state.pending_event_id().is_none() {
                    match classify_quiescent_authority_seed_handoff(
                        &handoff,
                        state.signing_epoch(),
                        &active_record.key_id.to_string(),
                    )? {
                        QuiescentAuthoritySeedHandoff::Completed => {
                            self.require_key_log_verification()?;
                            remove_authority_seed_handoff(&pending_path, &handoff, &identity)?;
                            return Ok((
                                active_keypair.public_key(),
                                self.current_rotation_outcome()?,
                            ));
                        }
                        QuiescentAuthoritySeedHandoff::Resumable { target_epoch } => {
                            (keypair, identity, target_epoch)
                        }
                    }
                } else {
                    let pending_record = state.pending_rotation_key().ok_or_else(|| {
                        CliError::cli_other_error(
                            "durable pending event is missing its pending key".to_string(),
                        )
                    })?;
                    let expected_target =
                        state.signing_epoch().checked_add(1).ok_or_else(|| {
                            CliError::cli_other_error(
                                "authority signing epoch overflow".to_string(),
                            )
                        })?;
                    if handoff.base_epoch != state.signing_epoch()
                        || handoff.target_epoch != expected_target
                        || handoff.key_id != pending_record.key_id.to_string()
                    {
                        return Err(CliError::cli_other_error(
                            "pending authority seed does not match the durable rotation"
                                .to_string(),
                        ));
                    }
                    (keypair, identity, expected_target)
                }
            }
            None => {
                if state.pending_event_id().is_some() {
                    return Err(CliError::cli_other_error(
                        "durable pending rotation is missing its bound seed handoff".to_string(),
                    ));
                }
                let keypair = Keypair::generate();
                let target_epoch = state.signing_epoch().checked_add(1).ok_or_else(|| {
                    CliError::cli_other_error("authority signing epoch overflow".to_string())
                })?;
                let handoff =
                    AuthoritySeedHandoff::new(&keypair, state.signing_epoch(), target_epoch)?;
                self.require_key_log_verification()?;
                let identity = persist_authority_seed_handoff(&pending_path, &handoff)?;
                (keypair, identity, target_epoch)
            }
        };
        let outcome = self.rotate_or_resume_authority(&next_keypair)?;
        let next_key_id = chio_keyring::derive_key_id(
            next_keypair.public_key().algorithm(),
            &next_keypair.public_key(),
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        self.require_key_log_verification()?;
        if outcome.signing_epoch != target_epoch
            || self
                .router
                .active_public_key()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
                != next_keypair.public_key()
        {
            return Err(CliError::cli_other_error(
                "activated authority selector does not match the seed handoff".to_string(),
            ));
        }
        let handoff = load_authority_seed_handoff(&pending_path)?.0;
        if handoff.key_id != next_key_id.to_string() || handoff.target_epoch != target_epoch {
            return Err(CliError::cli_other_error(
                "authority seed handoff changed during activation".to_string(),
            ));
        }
        self.require_key_log_verification()?;
        write_authority_seed_file_bound(active_seed_path, &next_keypair, Some(&active_identity))?;
        self.require_key_log_verification()?;
        remove_authority_seed_handoff(&pending_path, &handoff, &pending_identity)?;
        Ok((next_keypair.public_key(), outcome))
    }

    fn current_rotation_outcome(&self) -> Result<chio_keyring::WitnessedRotationOutcome, CliError> {
        self.require_key_log_verification()?;
        let audit_pin = self
            .store
            .head_pin()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .ok_or_else(|| CliError::cli_other_error("key log has no active head".to_string()))?;
        Ok(chio_keyring::WitnessedRotationOutcome {
            checkpoint_hash: audit_pin.checkpoint_hash,
            signing_epoch: audit_pin.signing_epoch,
            audit_pin,
        })
    }
}

struct ControlPlaneKeyEnterpriseReceiptSink {
    operator_backend: Arc<dyn SigningBackend>,
    configuration_binding: chio_core::Hash,
    receipt_store: Arc<Mutex<Option<AttachedReceiptStore>>>,
    migration_binding: security::EnterpriseMigrationRuntimeBinding,
}

impl chio_keyring::KeyEnterpriseReceiptSink for ControlPlaneKeyEnterpriseReceiptSink {
    fn persist(
        &self,
        receipt: &chio_keyring::SignedKeyEnterpriseReceipt,
    ) -> chio_keyring::Result<()> {
        self.migration_binding.require_enforced().map_err(|_| {
            chio_keyring::KeyringError::StateInvariant(
                "key-log verification migration denied enterprise receipt persistence",
            )
        })?;
        let receipt_store = self
            .receipt_store
            .lock()
            .map_err(|_| chio_keyring::KeyringError::Synchronization)?
            .clone()
            .ok_or(chio_keyring::KeyringError::StateInvariant(
                "production key rotation requires an attached normal receipt store",
            ))?;
        self.migration_binding.require_enforced().map_err(|_| {
            chio_keyring::KeyringError::StateInvariant(
                "key-log verification migration denied enterprise receipt verification",
            )
        })?;
        persist_key_enterprise_receipt(
            receipt,
            self.operator_backend.as_ref(),
            self.configuration_binding,
            receipt_store.store.as_ref(),
            &self.migration_binding,
        )
        .map(|_| ())
        .map_err(|error| chio_keyring::KeyringError::Storage(error.to_string()))
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringRuntimeConfig {
    schema: String,
    database_path: PathBuf,
    enterprise_migration: KeyLogVerificationMigrationConfig,
    log_id: String,
    authority_id: String,
    bootstrap_public_key: String,
    operator_public_key: String,
    operator_seed_file_path: PathBuf,
    witness_roster_id: String,
    witness_public_keys: BTreeMap<String, String>,
    witness_service_endpoints: BTreeMap<String, PathBuf>,
    audit_service_endpoints: BTreeMap<String, PathBuf>,
    audit_public_keys: BTreeMap<String, String>,
    recovery_policy_id: String,
    #[serde(default)]
    recovery_public_keys: BTreeMap<String, String>,
    recovery_threshold: usize,
    artifact_time_public_keys: BTreeMap<String, String>,
    artifact_time_seed_file_path: PathBuf,
    max_checkpoint_future_skew_seconds: u64,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyLogVerificationMigrationConfig {
    state_database_path: PathBuf,
    deployment_id: RecordId,
    stage: EnterpriseMigrationStage,
    trusted_transition_signers: Vec<chio_core::PublicKey>,
    minimum_heads: Vec<EnterpriseMigrationMinimumHead>,
}

impl KeyLogVerificationMigrationConfig {
    fn validated_key(&self) -> Result<EnterpriseMigrationKey, CliError> {
        if !self.stage.operational_failure_must_deny() {
            return Err(CliError::cli_other_error(
                "production key-log verification migration must be enforced".to_string(),
            ));
        }
        if self.trusted_transition_signers.is_empty()
            || self.trusted_transition_signers.len() > 16
            || self
                .trusted_transition_signers
                .windows(2)
                .any(|pair| pair[0].to_hex() >= pair[1].to_hex())
        {
            return Err(CliError::cli_other_error(
                "key-log migration transition signers must be nonempty, bounded, sorted, and unique"
                    .to_string(),
            ));
        }
        let key = EnterpriseMigrationKey {
            deployment_id: self.deployment_id.clone(),
            scope_kind: EnterpriseMigrationScopeKind::Deployment,
            scope_id: self.deployment_id.clone(),
            control: EnterpriseMigrationControl::KeyLogVerification,
        };
        if self.minimum_heads.len() != 1
            || self.minimum_heads[0].key != key
            || !self.minimum_heads[0].is_valid()
            || self.minimum_heads[0].minimum_generation != self.stage.generation()
        {
            return Err(CliError::cli_other_error(
                "key-log migration requires one exact externally anchored deployment head"
                    .to_string(),
            ));
        }
        Ok(key)
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyLogVerificationMigrationPosture<'a> {
    schema: &'static str,
    deployment_id: &'a RecordId,
    control: EnterpriseMigrationControl,
    stage: EnterpriseMigrationStage,
    key_log_configuration_binding: chio_core::Hash,
}

fn key_log_verification_migration_posture_digest(
    config: &KeyLogVerificationMigrationConfig,
    key_log_configuration_binding: chio_core::Hash,
) -> Result<Digest32, CliError> {
    let canonical = chio_core::canonical_json_bytes(&KeyLogVerificationMigrationPosture {
        schema: "chio.key-log-verification-migration-posture.v1",
        deployment_id: &config.deployment_id,
        control: EnterpriseMigrationControl::KeyLogVerification,
        stage: config.stage,
        key_log_configuration_binding,
    })?;
    Ok(Digest32::new(
        *chio_core::hashing::sha256(&canonical).as_bytes(),
    ))
}

fn require_distinct_key_log_and_migration_databases(
    key_log_database_path: &Path,
    migration_database_path: &Path,
) -> Result<(), CliError> {
    let key_log_path = fs::canonicalize(key_log_database_path)?;
    let migration_path = fs::canonicalize(migration_database_path)?;
    if key_log_path == migration_path {
        return Err(CliError::cli_other_error(
            "key log and enterprise migration ledger require distinct durable files".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        let key_log_metadata = fs::metadata(&key_log_path)?;
        let migration_metadata = fs::metadata(&migration_path)?;
        if key_log_metadata.dev() == migration_metadata.dev()
            && key_log_metadata.ino() == migration_metadata.ino()
        {
            return Err(CliError::cli_other_error(
                "key log and enterprise migration ledger cannot share one inode".to_string(),
            ));
        }
    }
    Ok(())
}

fn load_key_log_verification_migration_binding(
    config: &KeyLogVerificationMigrationConfig,
    key_log_policy: &chio_keyring::KeyLogPolicy,
    key_log_database_path: &Path,
) -> Result<security::EnterpriseMigrationRuntimeBinding, CliError> {
    let key = config.validated_key()?;
    require_distinct_key_log_and_migration_databases(
        key_log_database_path,
        &config.state_database_path,
    )?;
    let posture_digest = key_log_verification_migration_posture_digest(
        config,
        key_log_policy
            .configuration_binding()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    )?;
    let policy = SqliteEnterpriseMigrationOpenPolicy::new(
        config.trusted_transition_signers.clone(),
        config.minimum_heads.clone(),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("key-log migration open policy failed: {error}"))
    })?;
    let concrete = Arc::new(
        SqliteEnterpriseMigrationStateStore::open(&config.state_database_path, policy).map_err(
            |error| {
                CliError::cli_other_error(format!(
                    "key-log migration state database failed: {error}"
                ))
            },
        )?,
    );
    let store: Arc<dyn EnterpriseMigrationStateStore> = concrete;
    let binding = security::EnterpriseMigrationRuntimeBinding::load(
        &store,
        &key,
        config.stage,
        posture_digest,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "key-log verification migration binding failed: {error}"
        ))
    })?;
    binding.require_enforced().map_err(|error| {
        CliError::cli_other_error(format!(
            "key-log verification migration is not enforced: {error}"
        ))
    })?;
    Ok(binding)
}

#[cfg(test)]
pub(crate) fn build_kernel_with_keyring_config(
    loaded_policy: policy::LoadedPolicy,
    kernel_kp: &Keypair,
    config_path: &Path,
) -> Result<ChioKernel, CliError> {
    let composition = load_keyring_runtime_composition(kernel_kp, config_path)?;
    build_kernel_with_keyring_composition(loaded_policy, kernel_kp, &composition)
}

pub fn load_keyring_runtime_composition(
    kernel_kp: &Keypair,
    config_path: &Path,
) -> Result<KeyringRuntimeComposition, CliError> {
    let config_bytes = fs::read(config_path)?;
    let config: KeyringRuntimeConfig = serde_yml::from_slice(&config_bytes)?;
    if config.schema != "chio.keyring.runtime-config.v1" {
        return Err(CliError::cli_other_error(
            "unsupported keyring runtime configuration schema".to_string(),
        ));
    }
    if config.witness_public_keys.len() != 3
        || config.witness_service_endpoints.len() != 3
        || config.audit_service_endpoints.len() != 2
        || config.audit_public_keys.len() != 2
        || config
            .audit_service_endpoints
            .keys()
            .collect::<std::collections::BTreeSet<_>>()
            != config
                .audit_public_keys
                .keys()
                .collect::<std::collections::BTreeSet<_>>()
        || config.artifact_time_public_keys.is_empty()
    {
        return Err(CliError::cli_other_error(
            "keyring production configuration requires three witnesses, two auditors, and artifact-time trust roots"
                .to_string(),
        ));
    }
    let witnesses = parse_keyring_public_keys(config.witness_public_keys, |value| {
        chio_keyring::WitnessId::new(value)
    })?;
    let recovery = parse_keyring_public_keys(config.recovery_public_keys, |value| {
        chio_keyring::RecoveryAuthorizerId::new(value)
    })?;
    let artifact_time = parse_keyring_public_keys(config.artifact_time_public_keys, |value| {
        chio_keyring::AnchorId::new(value)
    })?;
    let artifact_time_inner: Arc<dyn SigningBackend> = Arc::new(load_private_seed_backend(
        &config.artifact_time_seed_file_path,
    )?);
    let artifact_time_anchor_id = artifact_time
        .iter()
        .find_map(|(anchor_id, public_key)| {
            (public_key == &artifact_time_inner.public_key()).then(|| anchor_id.clone())
        })
        .ok_or_else(|| {
            CliError::cli_other_error(
                "artifact-time signing seed does not match a configured trust root".to_string(),
            )
        })?;
    let audit_public_keys = config
        .audit_public_keys
        .into_iter()
        .map(|(identifier, key)| Ok((identifier, parse_keyring_public_key(&key)?)))
        .collect::<Result<BTreeMap<_, _>, CliError>>()?;
    let key_log_policy = chio_keyring::KeyLogPolicy::new(chio_keyring::KeyLogPolicyConfig {
        log_id: chio_keyring::LogId::new(config.log_id)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        authority_id: chio_keyring::AuthorityId::new(config.authority_id)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        bootstrap_key: parse_keyring_public_key(&config.bootstrap_public_key)?,
        operator_key: parse_keyring_public_key(&config.operator_public_key)?,
        witness_roster_id: chio_keyring::WitnessRosterId::new(config.witness_roster_id)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        witness_keys: witnesses,
        recovery_policy_id: chio_keyring::RecoveryPolicyId::new(config.recovery_policy_id)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        recovery_keys: recovery,
        recovery_threshold: config.recovery_threshold,
        max_checkpoint_future_skew: checkpoint_future_skew_millis(
            config.max_checkpoint_future_skew_seconds,
        )?,
    })
    .and_then(|policy| policy.with_artifact_time_roots(artifact_time))
    .and_then(|policy| policy.with_auditor_roots(audit_public_keys))
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let migration_binding = load_key_log_verification_migration_binding(
        &config.enterprise_migration,
        &key_log_policy,
        &config.database_path,
    )?;
    let artifact_time_backend: Arc<dyn SigningBackend> = Arc::new(MigrationGuardedSigningBackend {
        inner: artifact_time_inner,
        migration_binding: migration_binding.clone(),
    });
    let witness_service_endpoints = config
        .witness_service_endpoints
        .into_iter()
        .map(|(identifier, endpoint)| {
            Ok((
                chio_keyring::WitnessId::new(identifier)
                    .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                endpoint,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, CliError>>()?;
    let store = Arc::new(
        chio_keyring::SqliteKeyLogStore::open_existing(
            &config.database_path,
            key_log_policy.clone(),
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let operator_head = store
        .head_pin()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
        .ok_or_else(|| {
            CliError::cli_other_error(
                "keyring operator log must be initialized before runtime startup".to_string(),
            )
        })?;
    let accepted_pin = match store
        .head_stage()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
    {
        Some(chio_keyring::CheckpointStage::Witnessed)
        | Some(chio_keyring::CheckpointStage::Activated) => operator_head.clone(),
        Some(chio_keyring::CheckpointStage::Pending) => store
            .latest_accepted_pin()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "keyring cannot boot from a pending genesis checkpoint".to_string(),
                )
            })?,
        None => {
            return Err(CliError::cli_other_error(
                "keyring operator log has no durable checkpoint".to_string(),
            ));
        }
    };
    let (independent_services, startup_readiness) =
        chio_keyring::IndependentKeyLogServices::connect_and_validate(
            &key_log_policy,
            witness_service_endpoints,
            config.audit_service_endpoints,
            &accepted_pin,
            &operator_head,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let operator_storage_identity = store.storage_identity();
    if startup_readiness
        .durable_storage_identities
        .contains(&operator_storage_identity)
    {
        return Err(CliError::cli_other_error(
            "operator, witnesses, and auditors must use independently durable storage".to_string(),
        ));
    }
    let operator_inner: Arc<dyn SigningBackend> =
        Arc::new(load_private_seed_backend(&config.operator_seed_file_path)?);
    let operator_backend: Arc<dyn SigningBackend> = Arc::new(MigrationGuardedSigningBackend {
        inner: operator_inner,
        migration_binding: migration_binding.clone(),
    });
    let active_inner: Arc<dyn SigningBackend> =
        Arc::new(chio_core::crypto::Ed25519Backend::new(kernel_kp.clone()));
    let active_backend: Box<dyn SigningBackend> = Box::new(MigrationGuardedSigningBackend {
        inner: active_inner,
        migration_binding: migration_binding.clone(),
    });
    let router = Arc::new(
        chio_keyring::KeyringSigningRouter::open_enterprise(
            Arc::clone(&store),
            active_backend,
            artifact_time_anchor_id,
            artifact_time_backend,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let independent_services = Arc::new(independent_services);
    let keyring_authority_backend = Arc::new(
        chio_keyring::KeyringAuthoritySigningBackend::new_enterprise(
            Arc::clone(&router),
            Arc::clone(&independent_services),
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let guarded_inner: Arc<dyn SigningBackend> = keyring_authority_backend;
    let authority_backend = Arc::new(MigrationGuardedSigningBackend {
        inner: guarded_inner,
        migration_binding: migration_binding.clone(),
    });
    let receipt_store = Arc::new(Mutex::new(None));
    let receipt_sink: Arc<dyn chio_keyring::KeyEnterpriseReceiptSink> =
        Arc::new(ControlPlaneKeyEnterpriseReceiptSink {
            operator_backend: Arc::clone(&operator_backend),
            configuration_binding: key_log_policy
                .configuration_binding()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
            receipt_store: Arc::clone(&receipt_store),
            migration_binding: migration_binding.clone(),
        });
    let rotation_runtime = Arc::new(
        chio_keyring::WitnessedRotationRuntime::new_enterprise(
            Arc::clone(&store),
            Arc::clone(&router),
            Arc::clone(&operator_backend),
            receipt_sink,
            Arc::new(migration_binding.clone()),
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let composition = KeyringRuntimeComposition {
        router,
        store,
        independent_services,
        rotation_runtime,
        startup_readiness,
        migration_binding,
        authority_backend,
        operator_backend,
        receipt_store,
        authority_rotation_lock: Arc::new(Mutex::new(())),
    };
    composition.ensure_bound_signing_topology()?;
    Ok(composition)
}

fn checkpoint_future_skew_millis(seconds: u64) -> Result<u64, CliError> {
    seconds.checked_mul(1_000).ok_or_else(|| {
        CliError::cli_other_error(
            "max_checkpoint_future_skew_seconds overflows milliseconds".to_string(),
        )
    })
}

fn parse_keyring_public_key(value: &str) -> Result<chio_core::PublicKey, CliError> {
    chio_core::PublicKey::from_hex(value)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn parse_keyring_public_keys<I, F>(
    values: BTreeMap<String, String>,
    identifier: F,
) -> Result<BTreeMap<I, chio_core::PublicKey>, CliError>
where
    I: Ord,
    F: Fn(String) -> chio_keyring::Result<I>,
{
    values
        .into_iter()
        .map(|(name, key)| {
            Ok((
                identifier(name).map_err(|error| CliError::cli_other_error(error.to_string()))?,
                parse_keyring_public_key(&key)?,
            ))
        })
        .collect()
}
