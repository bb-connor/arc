#![allow(clippy::result_large_err, clippy::too_many_arguments)]
pub use chio_agent_web_interop as agent_web;
use chio_core::capability::threshold_approval::ThresholdApprovalRequirement;
use chio_core::crypto::Keypair;
use chio_kernel::{ChioKernel, KernelConfig};
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;
mod anchor_egress;
pub mod attestation;
pub mod certify;
mod durable_admission;
mod error;
pub use chio_enterprise_export as enterprise_export;
#[cfg(test)]
use durable_admission::create_private_directory;
pub use durable_admission::*;
pub(crate) use durable_admission::{durable_admission_lock_root, write_private_file_atomically};
pub use error::CliError;
pub mod economic_admission_cancellation;
pub mod economic_effect_coordinator;
pub mod economic_state_anchor;
pub mod economic_state_recovery;
pub mod enterprise_federation;
pub mod evidence_export;
pub mod federation_policy;
pub mod fiscal_runtime_readiness;
pub mod fiscal_runtime_startup;
pub mod fiscal_state_anchor;
pub mod fiscal_state_commit;
pub mod fiscal_state_recovery;
pub mod issuance;
mod keyring_runtime;
pub mod passport_verifier;
pub mod policy;
pub mod reputation;
pub use chio_risk_comptroller as risk_comptroller;
pub mod scim_lifecycle;
pub mod security;
pub mod seller_rail;
pub use chio_commerce_order as commerce_order;
pub use chio_transaction_passport as transaction_passport;
pub mod transaction_passport_risk;
pub mod trust_control;
pub use chio_trust_market_context as trust_market;
pub use keyring_runtime::{
    load_keyring_runtime_composition, load_keyring_runtime_from_authority_seed,
    KeyringRuntimeAuthorityStatus, KeyringRuntimeComposition,
};
struct LoadedThresholdApprovalResolver(ThresholdApprovalRequirement);

impl chio_kernel::threshold_approval::ThresholdApprovalRequirementResolver
    for LoadedThresholdApprovalResolver
{
    fn resolve_requirement(
        &self,
        policy_hash: &str,
        _server_id: &str,
        _tool_name: &str,
    ) -> Result<
        Option<chio_core::capability::threshold_approval::ThresholdApprovalRequirement>,
        String,
    > {
        Ok((self.0.policy_hash == policy_hash).then(|| self.0.clone()))
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
pub enum JwtProviderProfile {
    Generic,
    Auth0,
    Okta,
    AzureAd,
}

pub fn build_kernel(loaded_policy: policy::LoadedPolicy, kernel_kp: &Keypair) -> ChioKernel {
    build_kernel_components(loaded_policy, kernel_kp, None)
}

/// Build a kernel with the complete fail-closed active-defense adapter set.
///
/// The runtime is checked before any kernel is returned. Security guards are
/// installed before the default and configured guards, the raw-output
/// tripwire runs before existing post-invocation hooks, and the flow join runs
/// after them against the final representation.
pub fn build_kernel_with_active_defense(
    loaded_policy: policy::LoadedPolicy,
    kernel_kp: &Keypair,
    runtime: security::ActiveDefenseRuntime,
) -> Result<ChioKernel, security::ActiveDefenseInstallError> {
    runtime.ensure_ready()?;
    let mut kernel = build_kernel_components(loaded_policy, kernel_kp, Some(&runtime));
    runtime.install_dispatch_and_issuance(&mut kernel)?;
    Ok(kernel)
}

fn build_kernel_components(
    loaded_policy: policy::LoadedPolicy,
    kernel_kp: &Keypair,
    active_defense: Option<&security::ActiveDefenseRuntime>,
) -> ChioKernel {
    let policy::LoadedPolicy {
        identity,
        kernel: kernel_policy,
        guard_pipeline,
        post_invocation_pipeline: policy_post_invocation_pipeline,
        runtime_assurance_policy,
        threshold_approval,
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
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: kernel_policy.require_web3_evidence,
        allow_ephemeral_receipt_log: kernel_policy.allow_ephemeral_receipt_log,
        allow_ephemeral_revocation_store: kernel_policy.allow_ephemeral_revocation_store,
        checkpoint_batch_size: kernel_policy.checkpoint_batch_size,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    };

    let mut kernel = ChioKernel::new(config);
    if kernel
        .configure_durable_admission(
            kernel_policy.durable_admission_mode,
            kernel_policy.allow_unsafe_durable_admission_off,
        )
        .is_err()
    {
        tracing::error!("invalid durable admission configuration; retaining side-effecting mode");
    }

    if let Some(runtime) = active_defense {
        runtime.install_pre_invocation(&mut kernel);
    }

    let default_guard_profile = chio_guards::default_runtime_guard_profile();
    if !default_guard_profile.pre_invocation_guards.is_empty() {
        tracing::info!(
            guard_count = default_guard_profile.pre_invocation_guards.len(),
            "registering default runtime guard profile"
        );
        for guard in default_guard_profile.pre_invocation_guards {
            kernel.add_guard(guard);
        }
    }

    if !guard_pipeline.is_empty() {
        tracing::info!(
            guard_count = guard_pipeline.len(),
            "registering guard pipeline"
        );
        kernel.add_guard(Box::new(guard_pipeline));
    }

    let mut post_invocation_pipeline = active_defense
        .map_or_else(chio_kernel::PostInvocationPipeline::new, |runtime| {
            runtime.raw_output_pipeline()
        });
    post_invocation_pipeline.append(policy_post_invocation_pipeline);
    post_invocation_pipeline.append(default_guard_profile.post_invocation_pipeline);
    if let Some(runtime) = active_defense {
        runtime.append_flow_post_invocation(&mut post_invocation_pipeline);
    }

    if !post_invocation_pipeline.is_empty() {
        tracing::info!(
            hook_count = post_invocation_pipeline.len(),
            "registering post-invocation pipeline"
        );
        kernel.set_post_invocation_pipeline(post_invocation_pipeline);
    }

    if let Some(attestation_trust_policy) =
        runtime_assurance_policy.and_then(|policy| policy.attestation_trust_policy)
    {
        kernel.set_attestation_trust_policy(attestation_trust_policy);
    }

    if let Some(requirement) = threshold_approval {
        kernel.set_threshold_approval_requirement_resolver(Arc::new(
            LoadedThresholdApprovalResolver(requirement),
        ));
    }

    kernel
}

pub fn configure_receipt_store(
    kernel: &mut ChioKernel,
    receipt_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (receipt_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "use either --receipt-db or --control-url for receipt persistence, not both"
                    .to_string(),
            ));
        }
        (Some(path), None) => {
            // An in-memory SQLite path (`:memory:`, `file::memory:`, or a
            // `?mode=memory` URI) opens a database that is discarded when the
            // process exits. Attaching it here would satisfy the kernel's
            // receipt-persistence gate (`receipt_store.is_some()`) while silently
            // losing every receipt on restart, so refuse it: durable receipts
            // require a filesystem path, and an intentionally ephemeral log is
            // requested by omitting the path and setting
            // `allow_ephemeral_receipt_log` in policy.
            if path
                .to_str()
                .is_some_and(chio_store_sqlite::is_in_memory_sqlite_path)
            {
                return Err(CliError::cli_other_error(
                    "refusing to attach an in-memory receipt database as a durable store: an \
                     in-memory SQLite path loses every receipt on restart. Point --receipt-db at \
                     a filesystem path for durable receipts, or omit it and set \
                     allow_ephemeral_receipt_log in policy to run with an in-memory receipt log."
                        .to_string(),
                ));
            }
            let store = chio_store_sqlite::SqliteReceiptStore::open(path)?;
            store.wait_for_writer_ready(std::time::Duration::from_secs(30))?;
            kernel.set_receipt_store(Box::new(store))?;
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_receipt_store(
                trust_control::service_runtime::remote_stores::build_remote_receipt_store(
                    url, token,
                )?,
            )?;
        }
        (None, None) => {}
    }
    kernel.validate_web3_evidence_prerequisites()?;
    Ok(())
}

pub fn configure_revocation_store(
    kernel: &mut ChioKernel,
    revocation_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (revocation_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "use either --revocation-db or --control-url for revocation state, not both"
                    .to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_revocation_store(Box::new(chio_store_sqlite::SqliteRevocationStore::open(
                path,
            )?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_revocation_store(
                trust_control::service_runtime::remote_stores::build_remote_revocation_store(
                    url, token,
                )?,
            );
        }
        (None, None) => {}
    }
    Ok(())
}

pub fn configure_capability_authority(
    kernel: &mut ChioKernel,
    default_authority_keypair: &Keypair,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    issuance_policy: Option<policy::ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<policy::RuntimeAssuranceIssuancePolicy>,
) -> Result<(), CliError> {
    if control_url.is_some() && (authority_seed_path.is_some() || authority_db_path.is_some()) {
        return Err(CliError::cli_other_error(
            "use either local authority flags or --control-url, not both".to_string(),
        ));
    }
    if let Some(url) = control_url {
        if issuance_policy.is_some() || runtime_assurance_policy.is_some() {
            return Err(CliError::cli_other_error(
                "policy-gated issuance must be enforced by the trust-control service itself; start `chio trust serve --policy <path>` instead of relying on client-side --control-url issuance".to_string(),
            ));
        }
        let token = require_control_token(control_token)?;
        kernel.set_capability_authority(
            trust_control::service_runtime::remote_authority::build_remote_capability_authority(
                url, token,
            )?,
        );
        return Ok(());
    }

    match (authority_seed_path, authority_db_path) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "use either --authority-seed-file or --authority-db, not both".to_string(),
            ));
        }
        (Some(path), None) => {
            let keypair = load_or_create_authority_keypair(path)?;
            kernel.set_capability_authority(issuance::wrap_capability_authority(
                Box::new(chio_kernel::LocalCapabilityAuthority::new(keypair)),
                issuance_policy,
                runtime_assurance_policy,
                receipt_db_path,
                budget_db_path,
            ));
        }
        (None, Some(path)) => {
            kernel.set_capability_authority(issuance::wrap_capability_authority(
                Box::new(chio_store_sqlite::SqliteCapabilityAuthority::open(path)?),
                issuance_policy,
                runtime_assurance_policy,
                receipt_db_path,
                budget_db_path,
            ));
        }
        (None, None) => {
            if issuance_policy.is_some()
                || runtime_assurance_policy.is_some()
                || receipt_db_path.is_some()
            {
                kernel.set_capability_authority(issuance::wrap_capability_authority(
                    Box::new(chio_kernel::LocalCapabilityAuthority::new(
                        default_authority_keypair.clone(),
                    )),
                    issuance_policy,
                    runtime_assurance_policy,
                    receipt_db_path,
                    budget_db_path,
                ));
            }
        }
    }
    Ok(())
}

pub fn configure_budget_store(
    kernel: &mut ChioKernel,
    budget_db_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    match (budget_db_path, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::cli_other_error(
                "use either --budget-db or --control-url for budget state, not both".to_string(),
            ));
        }
        (Some(path), None) => {
            kernel.set_budget_store(Box::new(chio_store_sqlite::SqliteBudgetStore::open(path)?));
        }
        (None, Some(url)) => {
            let token = require_control_token(control_token)?;
            kernel.set_budget_store(
                trust_control::service_runtime::budget::build_remote_budget_store(url, token)?,
            );
        }
        (None, None) => {}
    }
    Ok(())
}

pub fn require_control_token(control_token: Option<&str>) -> Result<&str, CliError> {
    control_token.ok_or_else(|| {
        CliError::cli_other_error(
            "--control-url requires --control-token so trust-service authentication is explicit"
                .to_string(),
        )
    })
}

pub fn authority_public_key_from_seed_file(
    path: &Path,
) -> Result<Option<chio_core::PublicKey>, CliError> {
    match fs::read_to_string(path) {
        Ok(seed_hex) => Ok(Some(Keypair::from_seed_hex(seed_hex.trim())?.public_key())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::Io(error)),
    }
}

pub fn rotate_authority_keypair(path: &Path) -> Result<chio_core::PublicKey, CliError> {
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

/// Load existing seed-file signing custody without creating or repairing it.
pub fn load_existing_authority_keypair(path: &Path) -> Result<Keypair, CliError> {
    let seed_bytes = read_existing_authority_seed(path, 256)?;
    let seed_hex = std::str::from_utf8(&seed_bytes)
        .map_err(|_| CliError::cli_other_error("authority seed is not valid UTF-8"))?;
    Keypair::from_seed_hex(seed_hex.trim()).map_err(CliError::from)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthoritySeedFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    length: u64,
}

fn read_existing_authority_seed(path: &Path, maximum_bytes: usize) -> Result<Vec<u8>, CliError> {
    let path_metadata = fs::symlink_metadata(path)?;
    validate_authority_seed_metadata(&path_metadata)?;
    let expected_identity = authority_seed_file_identity(&path_metadata);

    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{open, Mode, OFlags};

        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
        File::from(descriptor)
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new().read(true).open(path)?;

    let opened_metadata = file.metadata()?;
    validate_authority_seed_metadata(&opened_metadata)?;
    if authority_seed_file_identity(&opened_metadata) != expected_identity {
        return Err(CliError::cli_io_error(
            "authority seed changed while it was opened",
        ));
    }

    let limit = u64::try_from(maximum_bytes)
        .map_err(|_| CliError::cli_io_error("invalid authority seed byte limit"))?
        .checked_add(1)
        .ok_or_else(|| CliError::cli_io_error("invalid authority seed byte limit"))?;
    let mut bytes = Vec::with_capacity(maximum_bytes);
    file.by_ref().take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        bytes.fill(0);
        return Err(CliError::cli_io_error(
            "authority seed exceeds its byte limit",
        ));
    }

    let final_path_metadata = fs::symlink_metadata(path)?;
    validate_authority_seed_metadata(&final_path_metadata)?;
    if authority_seed_file_identity(&final_path_metadata) != expected_identity
        || authority_seed_file_identity(&file.metadata()?) != expected_identity
    {
        bytes.fill(0);
        return Err(CliError::cli_io_error(
            "authority seed identity changed while it was read",
        ));
    }
    Ok(bytes)
}

fn validate_authority_seed_metadata(metadata: &fs::Metadata) -> Result<(), CliError> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CliError::cli_io_error(
            "authority seed must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.nlink() != 1 || metadata.mode() & 0o177 != 0 {
            return Err(CliError::cli_io_error(
                "authority seed must be singly linked with mode 0600 or stricter",
            ));
        }
    }
    Ok(())
}

fn authority_seed_file_identity(metadata: &fs::Metadata) -> AuthoritySeedFileIdentity {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;

    AuthoritySeedFileIdentity {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        length: metadata.len(),
    }
}

pub fn issue_default_capabilities(
    kernel: &ChioKernel,
    agent_pk: &chio_core::PublicKey,
    default_capabilities: &[policy::DefaultCapability],
) -> Result<Vec<chio_core::capability::token::CapabilityToken>, CliError> {
    default_capabilities
        .iter()
        .cloned()
        .map(|default_capability| {
            kernel
                .issue_capability(agent_pk, default_capability.scope, default_capability.ttl)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "failed to issue initial capability: {error}"
                    ))
                })
        })
        .collect()
}

fn write_authority_seed_file(path: &Path, keypair: &Keypair) -> Result<(), CliError> {
    write_private_file_atomically(path, format!("{}\n", keypair.seed_hex()).as_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use chio_errors::ErrorCodeSpec;
    use chio_errors::_generated::error_codes::{
        CLI_IO, CLI_YAML, GUARD_DENIED, MANIFEST_SCHEMA_INVALID, MANIFEST_SIGNATURE_INVALID,
        PROVIDER_TOOL_SERVER_ERROR, REPLAY_DETERMINISTIC_MISMATCH,
    };
    use chio_guards::PostInvocationPipeline;

    fn make_kernel(require_web3_evidence: bool) -> ChioKernel {
        make_kernel_with_key(require_web3_evidence, Keypair::generate())
    }

    fn make_kernel_with_key(require_web3_evidence: bool, keypair: Keypair) -> ChioKernel {
        ChioKernel::new(KernelConfig {
            keypair,
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "control-plane-test-policy".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
        })
    }

    fn unique_receipt_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    #[test]
    fn existing_authority_loader_never_provisions_missing_custody() {
        let directory = tempfile::tempdir().expect("create authority loader test directory");
        let seed_path = directory.path().join("missing.seed");

        let error = load_existing_authority_keypair(&seed_path)
            .err()
            .expect("missing seed must fail");

        assert!(!seed_path.exists());
        assert!(error.to_string().contains("No such file"));
    }

    #[test]
    fn existing_authority_loader_accepts_exact_private_seed_file() {
        let directory = tempfile::tempdir().expect("create authority loader test directory");
        let seed_path = directory.path().join("authority.seed");
        let expected = Keypair::generate();
        write_authority_seed_file(&seed_path, &expected).expect("persist authority seed");

        let loaded = load_existing_authority_keypair(&seed_path).expect("load authority seed");

        assert_eq!(loaded.public_key(), expected.public_key());
    }

    #[cfg(unix)]
    #[test]
    fn existing_authority_loader_rejects_permissive_or_linked_custody() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempfile::tempdir().expect("create authority loader test directory");
        let seed_path = directory.path().join("authority.seed");
        let alias_path = directory.path().join("authority-alias.seed");
        let keypair = Keypair::generate();
        write_authority_seed_file(&seed_path, &keypair).expect("persist authority seed");
        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o644))
            .expect("widen authority seed mode");

        let permissive = load_existing_authority_keypair(&seed_path)
            .err()
            .expect("permissive authority seed must fail");
        assert!(permissive.to_string().contains("mode 0600"));

        fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600))
            .expect("restore authority seed mode");
        symlink(&seed_path, &alias_path).expect("create authority seed symlink");
        let linked = load_existing_authority_keypair(&alias_path)
            .err()
            .expect("authority seed symlink must fail");
        assert!(linked.to_string().contains("regular file"));
    }

    fn assert_registry_error(
        err: &CliError,
        expected: &'static ErrorCodeSpec,
        expected_domain: &str,
    ) {
        match err {
            CliError::Chio(chio) => {
                assert_eq!(chio.code().as_str(), expected.urn);
                assert_eq!(chio.domain().as_str(), expected_domain);
            }
            other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
        }
    }

    #[test]
    fn migrated_cli_error_helpers_emit_registry_codes_and_domains() {
        let cases = [
            (
                CliError::manifest_signature_error("bad manifest signature"),
                &MANIFEST_SIGNATURE_INVALID,
                "manifest",
            ),
            (
                CliError::manifest_schema_error("bad manifest schema"),
                &MANIFEST_SCHEMA_INVALID,
                "manifest",
            ),
            (
                CliError::guard_error("guard denied request"),
                &GUARD_DENIED,
                "guard",
            ),
            (
                CliError::replay_mismatch_error("replay diverged"),
                &REPLAY_DETERMINISTIC_MISMATCH,
                "replay",
            ),
            (
                CliError::provider_error("provider adapter failed"),
                &PROVIDER_TOOL_SERVER_ERROR,
                "provider",
            ),
            (
                CliError::cli_io_error("could not read input"),
                &CLI_IO,
                "cli",
            ),
            (
                CliError::cli_yaml_error("could not parse yaml"),
                &CLI_YAML,
                "cli",
            ),
        ];

        for (err, expected, expected_domain) in cases {
            assert_registry_error(&err, expected, expected_domain);
        }
    }

    #[test]
    fn cli_error_report_rejects_mismatched_registry_metadata() {
        let spec = &chio_errors::_generated::error_codes::CAPABILITY_EXPIRED;
        let error = CliError::Chio(
            chio_errors::diagnostic(
                spec.urn,
                chio_errors::Domain::Manifest,
                spec.severity,
                "registered code with mismatched diagnostic domain",
            )
            .into_error(),
        );

        let report = error.report();

        assert_eq!(report.code, spec.urn);
        assert_eq!(report.context["domain"], "manifest");
        assert_eq!(report.context["severity"], spec.severity.as_str());
        assert_eq!(report.context["string_code"], serde_json::Value::Null);
        assert_eq!(report.context["stability"], serde_json::Value::Null);
        assert_eq!(
            report.suggested_fix,
            "Inspect the Chio diagnostic and retry after correcting the request."
        );
    }

    #[test]
    fn web3_evidence_requires_local_receipt_store() {
        let mut kernel = make_kernel(true);

        let error = configure_receipt_store(&mut kernel, None, None, None).unwrap_err();
        assert!(matches!(
            error,
            CliError::Kernel(chio_kernel::KernelError::Web3EvidenceUnavailable(_))
        ));
    }

    #[test]
    fn configure_receipt_store_refuses_in_memory_sqlite_paths() {
        // Every in-memory SQLite spelling must be refused so no store-wiring
        // caller can attach an ephemeral database while claiming durable
        // receipts. A durable filesystem path is accepted so the guard does not
        // over-reject real receipt databases.
        for path in [
            ":memory:",
            "file::memory:",
            "file:receipts.db?mode=memory",
            "file:receipts.db?cache=shared&mode=memory",
        ] {
            let mut kernel = make_kernel(false);
            let error = configure_receipt_store(&mut kernel, Some(Path::new(path)), None, None)
                .unwrap_err();
            assert!(
                error.to_string().contains("in-memory receipt database"),
                "{path} must be refused as a non-durable receipt store, got: {error}"
            );
        }

        let durable = unique_receipt_db_path("chio-control-plane-durable-receipts");
        let mut kernel = make_kernel(false);
        configure_receipt_store(&mut kernel, Some(&durable), None, None)
            .expect("durable filesystem receipt path must be accepted");
        let _ = std::fs::remove_file(durable);
    }

    #[test]
    fn durable_admission_runtime_shares_one_owner_on_a_distinct_sidecar() {
        let directory = tempfile::tempdir().expect("create durable admission test directory");
        create_private_directory(directory.path()).expect("secure test directory");
        let session_database = directory.path().join("sessions.sqlite3");
        let admission_database =
            durable_admission_sidecar_path(&session_database).expect("derive admission sidecar");
        assert_ne!(admission_database, session_database);

        let runtime = DurableAdmissionRuntime::open(&admission_database)
            .expect("open durable admission runtime");
        let kernel_public_key = runtime.kernel_keypair().public_key();
        let mut first = make_kernel_with_key(false, runtime.kernel_keypair());
        let mut second = make_kernel_with_key(false, runtime.kernel_keypair());
        runtime
            .attach(&mut first)
            .expect("attach first durable kernel");
        runtime
            .attach(&mut second)
            .expect("attach second durable kernel");

        assert!(DurableAdmissionRuntime::open(&admission_database).is_err());

        drop(first);
        drop(second);
        drop(runtime);
        let reopened = DurableAdmissionRuntime::open(&admission_database)
            .expect("serving owner released after shared runtimes drop");
        assert_eq!(reopened.kernel_keypair().public_key(), kernel_public_key);
    }

    #[test]
    fn durable_admission_runtime_rejects_a_lost_signing_seed() {
        let directory = tempfile::tempdir().expect("create durable admission test directory");
        create_private_directory(directory.path()).expect("secure test directory");
        let admission_database = directory.path().join("admission.sqlite3");
        let runtime = DurableAdmissionRuntime::open(&admission_database)
            .expect("open durable admission runtime");
        drop(runtime);

        let seed_path = durable_admission::durable_admission_kernel_seed_path(&admission_database)
            .expect("derive durable admission seed path");
        std::fs::remove_file(seed_path).expect("remove durable admission seed");

        let error = DurableAdmissionRuntime::open(&admission_database)
            .err()
            .expect("lost signing seed must not rebind durable admission state");
        assert!(error
            .to_string()
            .contains("bound to a different kernel signing key"));
    }

    #[test]
    fn web3_evidence_accepts_checkpoint_capable_sqlite_receipt_store() {
        let path = unique_receipt_db_path("chio-control-plane-web3-evidence");
        let mut kernel = make_kernel(true);

        configure_receipt_store(&mut kernel, Some(&path), None, None).unwrap();
        kernel.validate_web3_evidence_prerequisites().unwrap();

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn web3_evidence_rejects_remote_append_only_receipt_store() {
        let mut kernel = make_kernel(true);

        let error = configure_receipt_store(
            &mut kernel,
            None,
            Some("http://127.0.0.1:8080"),
            Some("test-token"),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CliError::Kernel(chio_kernel::KernelError::Web3EvidenceUnavailable(_))
        ));
        assert!(error
            .to_string()
            .contains("append-only remote receipt mirrors are unsupported"));
    }

    #[test]
    fn cli_error_report_passes_through_kernel_metadata() {
        let report = CliError::Kernel(chio_kernel::KernelError::OutOfScope {
            tool: "read_file".to_string(),
            server: "fs".to_string(),
        })
        .report();

        assert_eq!(report.code, "CHIO-KERNEL-OUT-OF-SCOPE-TOOL");
        assert_eq!(report.context["tool"], "read_file");
        assert_eq!(report.context["server"], "fs");
        assert!(report
            .suggested_fix
            .contains("Issue a capability that grants this tool"));
    }

    #[test]
    fn cli_error_report_captures_io_context() {
        let report = CliError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing file",
        ))
        .report();

        assert_eq!(report.code, "CHIO-CLI-IO");
        assert!(report.message.contains("i/o error"));
        assert!(report.context["source"]
            .as_str()
            .expect("io source string")
            .contains("missing file"));
        assert!(report.suggested_fix.contains("Check file paths"));
    }

    #[test]
    fn build_kernel_registers_post_invocation_pipeline() {
        let keypair = Keypair::generate();
        let loaded_policy = policy::LoadedPolicy {
            format: policy::PolicyFormat::ChioYaml,
            identity: policy::PolicyIdentity {
                source_hash: "source".to_string(),
                runtime_hash: "runtime".to_string(),
            },
            kernel: policy::KernelPolicyConfig::default(),
            default_capabilities: Vec::new(),
            guard_pipeline: chio_guards::GuardPipeline::new(),
            post_invocation_pipeline: {
                let mut pipeline = PostInvocationPipeline::new();
                pipeline.add(Box::new(chio_guards::SanitizerHook::new()));
                pipeline
            },
            issuance_policy: None,
            runtime_assurance_policy: None,
            threshold_approval: None,
        };

        let kernel = build_kernel(loaded_policy, &keypair);
        assert_eq!(kernel.post_invocation_hook_count(), 2);
    }

    #[test]
    fn build_kernel_registers_default_guard_profile() {
        let keypair = Keypair::generate();
        let loaded_policy = policy::LoadedPolicy {
            format: policy::PolicyFormat::ChioYaml,
            identity: policy::PolicyIdentity {
                source_hash: "source".to_string(),
                runtime_hash: "runtime".to_string(),
            },
            kernel: policy::KernelPolicyConfig::default(),
            default_capabilities: Vec::new(),
            guard_pipeline: chio_guards::GuardPipeline::new(),
            post_invocation_pipeline: PostInvocationPipeline::new(),
            issuance_policy: None,
            runtime_assurance_policy: None,
            threshold_approval: None,
        };

        let kernel = build_kernel(loaded_policy, &keypair);

        assert!(kernel.guard_count() >= 2);
        assert!(kernel.post_invocation_hook_count() >= 1);
    }
}
