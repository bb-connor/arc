#![allow(clippy::result_large_err, clippy::too_many_arguments)]

use std::fs;
use std::path::Path;

use pact_core::crypto::Keypair;
use pact_kernel::transport::TransportError;
use pact_kernel::{KernelConfig, PactKernel};

#[path = "../../pact-cli/src/policy.rs"]
pub mod policy;

#[path = "../../pact-cli/src/issuance.rs"]
pub mod issuance;

#[path = "../../pact-cli/src/certify.rs"]
pub mod certify;

#[path = "../../pact-cli/src/enterprise_federation.rs"]
pub mod enterprise_federation;

#[path = "../../pact-cli/src/passport_verifier.rs"]
pub mod passport_verifier;

#[path = "../../pact-cli/src/evidence_export.rs"]
pub mod evidence_export;

#[path = "../../pact-cli/src/reputation.rs"]
pub mod reputation;

#[path = "../../pact-cli/src/trust_control.rs"]
pub mod trust_control;

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
    Core(#[from] pact_core::error::Error),

    #[error("{0}")]
    Policy(#[from] policy::PolicyError),

    #[error("adapter error: {0}")]
    Adapter(#[from] pact_mcp_adapter::AdapterError),

    #[error("kernel error: {0}")]
    Kernel(#[from] pact_kernel::KernelError),

    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] pact_kernel::CheckpointError),

    #[error("evidence export error: {0}")]
    EvidenceExport(#[from] pact_kernel::EvidenceExportError),

    #[error("credential error: {0}")]
    Credential(#[from] pact_credentials::CredentialError),

    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] pact_kernel::ReceiptStoreError),

    #[error("conformance load error: {0}")]
    ConformanceLoad(#[from] pact_conformance::LoadError),

    #[error("revocation store error: {0}")]
    RevocationStore(#[from] pact_kernel::RevocationStoreError),

    #[error("authority store error: {0}")]
    AuthorityStore(#[from] pact_kernel::AuthorityStoreError),

    #[error("budget store error: {0}")]
    BudgetStore(#[from] pact_kernel::BudgetStoreError),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("http error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("{0}")]
    Other(String),
}

pub fn build_kernel(loaded_policy: policy::LoadedPolicy, kernel_kp: &Keypair) -> PactKernel {
    let policy::LoadedPolicy {
        identity,
        kernel: kernel_policy,
        guard_pipeline,
        ..
    } = loaded_policy;

    let config = KernelConfig {
        keypair: kernel_kp.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: kernel_policy.delegation_depth_limit,
        policy_hash: identity.runtime_hash,
        allow_sampling: kernel_policy.allow_sampling,
        allow_sampling_tool_use: kernel_policy.allow_sampling_tool_use,
        allow_elicitation: kernel_policy.allow_elicitation,
        max_stream_duration_secs: pact_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: pact_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        checkpoint_batch_size: pact_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };

    let mut kernel = PactKernel::new(config);

    if !guard_pipeline.is_empty() {
        tracing::info!(
            guard_count = guard_pipeline.len(),
            "registering guard pipeline"
        );
        kernel.add_guard(Box::new(guard_pipeline));
    }

    kernel
}

pub fn configure_receipt_store(
    kernel: &mut PactKernel,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (receipt_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --receipt-db or --control-url for receipt persistence, not both"
                    .to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_receipt_store(Box::new(pact_store_sqlite::SqliteReceiptStore::open(path)?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_receipt_store(trust_control::build_remote_receipt_store(url, token)?);
        }
        (None, None) => {}
    }
    Ok(())
}

pub fn configure_revocation_store(
    kernel: &mut PactKernel,
    revocation_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (revocation_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --revocation-db or --control-url for revocation state, not both"
                    .to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_revocation_store(Box::new(pact_store_sqlite::SqliteRevocationStore::open(
                path,
            )?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_revocation_store(trust_control::build_remote_revocation_store(url, token)?);
        }
        (None, None) => {}
    }
    Ok(())
}

pub fn configure_capability_authority(
    kernel: &mut PactKernel,
    default_authority_keypair: &Keypair,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    issuance_policy: Option<policy::ReputationIssuancePolicy>,
) -> Result<(), CliError> {
    if control_url.is_some() && (authority_seed_path.is_some() || authority_db_path.is_some()) {
        return Err(CliError::Other(
            "use either local authority flags or --control-url, not both".to_string(),
        ));
    }
    if let Some(url) = control_url {
        if issuance_policy.is_some() {
            return Err(CliError::Other(
                "reputation-gated issuance must be enforced by the trust-control service itself; start `pact trust serve --policy <path>` instead of relying on client-side --control-url issuance".to_string(),
            ));
        }
        let token = require_control_token(control_token)?;
        kernel.set_capability_authority(trust_control::build_remote_capability_authority(
            url, token,
        )?);
        return Ok(());
    }

    match (authority_seed_path, authority_db_path) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --authority-seed-file or --authority-db, not both".to_string(),
            ));
        }
        (Some(path), None) => {
            let keypair = load_or_create_authority_keypair(path)?;
            kernel.set_capability_authority(issuance::wrap_capability_authority(
                Box::new(pact_kernel::LocalCapabilityAuthority::new(keypair)),
                issuance_policy,
                receipt_db_path,
                budget_db_path,
            ));
        }
        (None, Some(path)) => {
            kernel.set_capability_authority(issuance::wrap_capability_authority(
                Box::new(pact_store_sqlite::SqliteCapabilityAuthority::open(path)?),
                issuance_policy,
                receipt_db_path,
                budget_db_path,
            ));
        }
        (None, None) => {
            if issuance_policy.is_some() || receipt_db_path.is_some() {
                kernel.set_capability_authority(issuance::wrap_capability_authority(
                    Box::new(pact_kernel::LocalCapabilityAuthority::new(
                        default_authority_keypair.clone(),
                    )),
                    issuance_policy,
                    receipt_db_path,
                    budget_db_path,
                ));
            }
        }
    }
    Ok(())
}

pub fn configure_budget_store(
    kernel: &mut PactKernel,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (budget_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::Other(
                "use either --budget-db or --control-url for budget state, not both".to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_budget_store(Box::new(pact_store_sqlite::SqliteBudgetStore::open(path)?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_budget_store(trust_control::build_remote_budget_store(url, token)?);
        }
        (None, None) => {}
    }
    Ok(())
}

pub fn require_control_token(control_token: Option<&str>) -> Result<&str, CliError> {
    control_token.ok_or_else(|| {
        CliError::Other(
            "--control-url requires --control-token so trust-service authentication is explicit"
                .to_string(),
        )
    })
}

pub fn authority_public_key_from_seed_file(
    path: &Path,
) -> Result<Option<pact_core::PublicKey>, CliError> {
    match fs::read_to_string(path) {
        Ok(seed_hex) => Ok(Some(Keypair::from_seed_hex(seed_hex.trim())?.public_key())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::Io(error)),
    }
}

pub fn rotate_authority_keypair(path: &Path) -> Result<pact_core::PublicKey, CliError> {
    let keypair = Keypair::generate();
    write_authority_seed_file(path, &keypair)?;
    Ok(keypair.public_key())
}

pub fn load_or_create_authority_keypair(path: &Path) -> Result<Keypair, CliError> {
    match authority_public_key_from_seed_file(path)? {
        Some(_) => {
            let seed_hex = fs::read_to_string(path)?;
            Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
        }
        None => {
            let keypair = Keypair::generate();
            write_authority_seed_file(path, &keypair)?;
            Ok(keypair)
        }
    }
}

pub fn issue_default_capabilities(
    kernel: &PactKernel,
    agent_pk: &pact_core::PublicKey,
    default_capabilities: &[policy::DefaultCapability],
) -> Result<Vec<pact_core::CapabilityToken>, CliError> {
    default_capabilities
        .iter()
        .cloned()
        .map(|default_capability| {
            kernel
                .issue_capability(agent_pk, default_capability.scope, default_capability.ttl)
                .map_err(|error| {
                    CliError::Other(format!("failed to issue initial capability: {error}"))
                })
        })
        .collect()
}

fn write_authority_seed_file(path: &Path, keypair: &Keypair) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = path.with_extension(format!(
        "{}tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| format!("{ext}."))
            .unwrap_or_default()
    ));
    fs::write(&temp_path, format!("{}\n", keypair.seed_hex()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(temp_path, path)?;
    Ok(())
}
