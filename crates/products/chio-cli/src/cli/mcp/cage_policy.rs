use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub(crate) const MCP_CAGE_LAUNCH_POLICY_SCHEMA: &str = "chio.mcp.cage-launch-policy.v2";
const MAX_CAGE_POLICY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct SignedCagePolicyLaunchFactory {
    path: PathBuf,
    trusted_policy_signer: String,
    trusted_policy_signer_key: chio_core::PublicKey,
    signed_policy_bytes: Arc<[u8]>,
}

impl SignedCagePolicyLaunchFactory {
    pub(crate) fn new(
        path: PathBuf,
        trusted_policy_signer: String,
    ) -> Result<Self, CliError> {
        let signed_policy_bytes = read_cage_policy(&path)?;
        let trusted_policy_signer_key = chio_core::PublicKey::from_hex(&trusted_policy_signer)
            .map_err(|error| {
                CliError::cli_other_error(format!("invalid cage policy trust root: {error}"))
            })?;
        let _ = decode_cage_policy(
            &path,
            &signed_policy_bytes,
            &trusted_policy_signer_key,
        )?;
        Ok(Self {
            path,
            trusted_policy_signer,
            trusted_policy_signer_key,
            signed_policy_bytes: Arc::from(signed_policy_bytes),
        })
    }
}

impl chio_mcp_adapter::transport::NativeMcpLaunchFactory for SignedCagePolicyLaunchFactory {
    fn authorization_contract_digest(
        &self,
    ) -> Result<String, chio_mcp_adapter::edge::AdapterError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct LaunchFactoryContract<'a> {
            schema: &'static str,
            signed_policy_digest: String,
            trusted_policy_signer: &'a str,
        }

        let contract = chio_core::canonical_json_bytes(&LaunchFactoryContract {
            schema: "chio.native-mcp.launch-factory-contract.v1",
            signed_policy_digest: chio_core::sha256_hex(self.signed_policy_bytes.as_ref()),
            trusted_policy_signer: &self.trusted_policy_signer,
        })
        .map_err(|error| {
            chio_mcp_adapter::edge::AdapterError::ConnectionFailed(format!(
                "cage launch factory contract encoding failed: {error}"
            ))
        })?;
        Ok(chio_core::sha256_hex(&contract))
    }

    fn prepare_launch(
        &self,
        command: &str,
        args: &[&str],
        expected_server_id: &str,
        admitted_manifest_registry: Arc<chio_manifest::VerifiedManifestRegistry>,
    ) -> Result<chio_mcp_adapter::transport::NativeMcpLaunch, chio_mcp_adapter::edge::AdapterError>
    {
        let launch = load_native_mcp_launch_from_bytes(
            &self.path,
            self.signed_policy_bytes.as_ref(),
            &self.trusted_policy_signer_key,
            command,
            args,
            Some(admitted_manifest_registry),
        )
        .map_err(|error| {
            chio_mcp_adapter::edge::AdapterError::ConnectionFailed(error.to_string())
        })?;
        if launch.server_id() != expected_server_id {
            return Err(chio_mcp_adapter::edge::AdapterError::ConnectionFailed(
                "native MCP launch policy belongs to a different server".to_string(),
            ));
        }
        Ok(launch)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedMcpCageLaunchPolicy {
    body: McpCageLaunchPolicy,
    signer_public_key: chio_core::PublicKey,
    signature: chio_core::Signature,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpCageLaunchPolicy {
    schema: String,
    signed_manifest: chio_manifest::SignedManifest,
    registered_public_key: chio_core::PublicKey,
    operator_ceilings: CageOperatorCeilings,
    runtime: CageRuntimePolicy,
    limits: CageLimitPolicy,
    receipt: CageReceiptRuntimePolicy,
    enterprise_migration: CageMigrationPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    broker: Option<CageBrokerBinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CageMigrationPolicy {
    state_database_path: PathBuf,
    deployment_id: chio_security_types::ports::RecordId,
    stage: chio_security_types::EnterpriseMigrationStage,
    trusted_transition_signers: Vec<chio_core::PublicKey>,
    minimum_head: chio_security_types::EnterpriseMigrationMinimumHead,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CageOperatorCeilings {
    read_paths: BTreeSet<PathBuf>,
    write_paths: BTreeSet<PathBuf>,
    network_destinations: BTreeSet<chio_manifest::NetworkDestination>,
    environment_variables: BTreeSet<chio_manifest::EnvironmentVariableName>,
    native_syscall_profiles: BTreeSet<chio_manifest::NativeSyscallProfile>,
    forbidden_paths: BTreeSet<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CageRuntimePolicy {
    cage_init_path: PathBuf,
    cage_init_binding_digest: String,
    target_path: PathBuf,
    target_binding_digest: String,
    working_directory: PathBuf,
    runtime_files: BTreeSet<PathBuf>,
    target_argv: Vec<String>,
    execution_identity: chio_cage::ExecutionIdentity,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CageLimitPolicy {
    max_artifact_bytes: u64,
    launch_timeout_ms: u64,
    nofile_soft: u64,
    nofile_hard: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CageBrokerBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inherited_fd: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socket_path: Option<PathBuf>,
    authentication_digest: String,
    expected_peer_identity: chio_cage::BrokerPeerIdentity,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CageReceiptRuntimePolicy {
    database_path: PathBuf,
    signer_seed_path: PathBuf,
    trusted_signer_public_key: String,
    capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
}

/// Typed input for the demo provisioner. Policy serialization remains owned by
/// this module so provisioning cannot drift from the launch-time decoder.
#[allow(dead_code)]
pub(super) struct NativeMcpDemoCagePolicyInput {
    pub(super) signed_manifest: chio_manifest::SignedManifest,
    pub(super) registered_public_key: chio_core::PublicKey,
    pub(super) policy_signer_public_key: chio_core::PublicKey,
    pub(super) cage_init_path: PathBuf,
    pub(super) cage_init_binding_digest: String,
    pub(super) target_path: PathBuf,
    pub(super) target_binding_digest: String,
    pub(super) working_directory: PathBuf,
    pub(super) target_argv: Vec<String>,
    pub(super) execution_identity: chio_cage::ExecutionIdentity,
    pub(super) migration_database_path: PathBuf,
    pub(super) deployment_id: chio_security_types::ports::RecordId,
    pub(super) migration_signer_public_key: chio_core::PublicKey,
    pub(super) receipt_database_path: PathBuf,
    pub(super) receipt_signer_seed_path: PathBuf,
    pub(super) receipt_signer_public_key: chio_core::PublicKey,
}

/// Constructs and signs the exact private policy types consumed by native MCP
/// launch. The Disabled stage is intentional for this demo-only surface and
/// authorizes legacy launch without claiming cage containment.
#[allow(dead_code)]
pub(super) struct NativeMcpDemoCagePolicyFactory {
    input: NativeMcpDemoCagePolicyInput,
    migration_key: chio_security_types::EnterpriseMigrationKey,
}

#[allow(dead_code)]
impl NativeMcpDemoCagePolicyFactory {
    pub(super) fn new(input: NativeMcpDemoCagePolicyInput) -> Result<Self, CliError> {
        input.execution_identity.validate().map_err(|error| {
            CliError::cli_other_error(format!(
                "demo cage execution identity is invalid: {error}"
            ))
        })?;
        chio_manifest::verify_manifest(&input.signed_manifest, &input.registered_public_key)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "demo native MCP manifest verification failed: {error}"
                ))
            })?;
        if input.signed_manifest.manifest.schema != chio_manifest::TOOL_MANIFEST_SCHEMA {
            return Err(CliError::cli_other_error(
                "demo native MCP provisioning requires an exact signed v2 manifest".to_string(),
            ));
        }
        let permissions = input
            .signed_manifest
            .manifest
            .required_permissions
            .as_ref()
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "demo native MCP manifest requires explicit platform permissions".to_string(),
                )
            })?;
        if permissions.native_syscall_profile
            != chio_manifest::NativeSyscallProfile::NativeMinimalV1
            || permissions.read_paths.is_some()
            || permissions.write_paths.is_some()
            || permissions.network_destinations.is_some()
            || permissions.environment_variables.is_some()
        {
            return Err(CliError::cli_other_error(
                "demo native MCP manifest must use the closed native_minimal_v1 profile without ambient grants"
                    .to_string(),
            ));
        }
        if !input.cage_init_path.is_absolute()
            || !input.target_path.is_absolute()
            || !input.working_directory.is_absolute()
            || !input.migration_database_path.is_absolute()
            || !input.receipt_database_path.is_absolute()
            || !input.receipt_signer_seed_path.is_absolute()
            || input.target_argv.first().map(String::as_str)
                != input.target_path.to_str()
            || !is_sha256_hex(&input.cage_init_binding_digest)
            || !is_sha256_hex(&input.target_binding_digest)
        {
            return Err(CliError::cli_other_error(
                "demo native MCP policy paths, argv, or executable digests are not canonical"
                    .to_string(),
            ));
        }
        let scope_id = chio_security_types::ports::RecordId::new(
            input.signed_manifest.manifest.server_id.clone(),
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("invalid demo native MCP server id: {error}"))
        })?;
        let migration_key = chio_security_types::EnterpriseMigrationKey {
            deployment_id: input.deployment_id.clone(),
            scope_kind: chio_security_types::EnterpriseMigrationScopeKind::ToolServer,
            scope_id,
            control: chio_security_types::EnterpriseMigrationControl::CageEnforcement,
        };
        Ok(Self {
            input,
            migration_key,
        })
    }

    pub(super) fn launch_contract(
        &self,
    ) -> Result<chio_security_types::CageLaunchContractDigests, CliError> {
        let disabled_minimum_head = chio_security_types::EnterpriseMigrationMinimumHead {
            key: self.migration_key.clone(),
            minimum_generation: chio_security_types::EnterpriseMigrationStage::Disabled
                .generation(),
            transition_digest: chio_security_types::ports::Digest32::new([1_u8; 32]),
        };
        let policy = self.policy(disabled_minimum_head)?;
        cage_launch_contract_digests(&policy, &self.input.policy_signer_public_key)
    }

    pub(super) fn signed_policy_bytes(
        &self,
        minimum_head: chio_security_types::EnterpriseMigrationMinimumHead,
        signer: &chio_core::Keypair,
    ) -> Result<Vec<u8>, CliError> {
        if signer.public_key() != self.input.policy_signer_public_key {
            return Err(CliError::cli_other_error(
                "demo cage policy signer does not match the committed policy trust root"
                    .to_string(),
            ));
        }
        let body = self.policy(minimum_head)?;
        let (signature, _) = signer.sign_canonical(&body).map_err(|error| {
            CliError::cli_other_error(format!("failed to sign demo cage policy: {error}"))
        })?;
        chio_core::canonical_json_bytes(&SignedMcpCageLaunchPolicy {
            body,
            signer_public_key: signer.public_key(),
            signature,
        })
        .map_err(|error| {
            CliError::cli_other_error(format!("failed to encode demo cage policy: {error}"))
        })
    }

    fn policy(
        &self,
        minimum_head: chio_security_types::EnterpriseMigrationMinimumHead,
    ) -> Result<McpCageLaunchPolicy, CliError> {
        if minimum_head.key != self.migration_key
            || minimum_head.minimum_generation
                != chio_security_types::EnterpriseMigrationStage::Disabled.generation()
            || minimum_head.transition_digest.is_zero()
        {
            return Err(CliError::cli_other_error(
                "demo cage migration head must bind the exact Disabled generation-zero ledger"
                    .to_string(),
            ));
        }
        Ok(McpCageLaunchPolicy {
            schema: MCP_CAGE_LAUNCH_POLICY_SCHEMA.to_string(),
            signed_manifest: self.input.signed_manifest.clone(),
            registered_public_key: self.input.registered_public_key.clone(),
            operator_ceilings: CageOperatorCeilings {
                read_paths: BTreeSet::new(),
                write_paths: BTreeSet::new(),
                network_destinations: BTreeSet::new(),
                environment_variables: BTreeSet::new(),
                native_syscall_profiles: [chio_manifest::NativeSyscallProfile::NativeMinimalV1]
                    .into_iter()
                    .collect(),
                forbidden_paths: BTreeSet::new(),
            },
            runtime: CageRuntimePolicy {
                cage_init_path: self.input.cage_init_path.clone(),
                cage_init_binding_digest: self.input.cage_init_binding_digest.clone(),
                target_path: self.input.target_path.clone(),
                target_binding_digest: self.input.target_binding_digest.clone(),
                working_directory: self.input.working_directory.clone(),
                runtime_files: BTreeSet::new(),
                target_argv: self.input.target_argv.clone(),
                execution_identity: self.input.execution_identity.clone(),
            },
            limits: CageLimitPolicy {
                max_artifact_bytes: 1024 * 1024,
                launch_timeout_ms: 10_000,
                nofile_soft: 192,
                nofile_hard: 192,
            },
            receipt: CageReceiptRuntimePolicy {
                database_path: self.input.receipt_database_path.clone(),
                signer_seed_path: self.input.receipt_signer_seed_path.clone(),
                trusted_signer_public_key: self.input.receipt_signer_public_key.to_hex(),
                capability_id: "native-mcp-demo-launch".to_string(),
                tenant_id: Some("demo-local".to_string()),
            },
            enterprise_migration: CageMigrationPolicy {
                state_database_path: self.input.migration_database_path.clone(),
                deployment_id: self.input.deployment_id.clone(),
                stage: chio_security_types::EnterpriseMigrationStage::Disabled,
                trusted_transition_signers: vec![
                    self.input.migration_signer_public_key.clone(),
                ],
                minimum_head,
            },
            broker: None,
        })
    }
}

#[allow(dead_code)]
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CageMigrationLedgerDigest<'a> {
    state_database_path: &'a Path,
    deployment_id: &'a chio_security_types::ports::RecordId,
    trusted_transition_signers: &'a [chio_core::PublicKey],
}

fn canonical_component_digest<T: Serialize>(
    value: &T,
) -> Result<chio_security_types::ports::Digest32, CliError> {
    let bytes = chio_core::canonical_json_bytes(value).map_err(|error| {
        CliError::cli_other_error(format!("cage launch contract encoding failed: {error}"))
    })?;
    Ok(chio_security_types::ports::Digest32::new(
        *chio_core::sha256(&bytes).as_bytes(),
    ))
}

fn cage_launch_contract_digests(
    policy: &McpCageLaunchPolicy,
    trusted_policy_signer: &chio_core::PublicKey,
) -> Result<chio_security_types::CageLaunchContractDigests, CliError> {
    Ok(chio_security_types::CageLaunchContractDigests {
        policy_schema_digest: canonical_component_digest(&policy.schema)?,
        policy_signer_digest: canonical_component_digest(trusted_policy_signer)?,
        signed_manifest_digest: canonical_component_digest(&policy.signed_manifest)?,
        registered_public_key_digest: canonical_component_digest(&policy.registered_public_key)?,
        operator_ceilings_digest: canonical_component_digest(&policy.operator_ceilings)?,
        runtime_digest: canonical_component_digest(&policy.runtime)?,
        limits_digest: canonical_component_digest(&policy.limits)?,
        receipt_digest: canonical_component_digest(&policy.receipt)?,
        broker_binding_digest: canonical_component_digest(&policy.broker)?,
        migration_ledger_digest: canonical_component_digest(&CageMigrationLedgerDigest {
            state_database_path: &policy.enterprise_migration.state_database_path,
            deployment_id: &policy.enterprise_migration.deployment_id,
            trusted_transition_signers: &policy.enterprise_migration.trusted_transition_signers,
        })?,
    })
}

fn load_cage_migration_enforcer(
    policy: &CageMigrationPolicy,
    server_id: &str,
    launch_contract: &chio_security_types::CageLaunchContractDigests,
) -> Result<chio_security_types::EnterpriseMigrationRuntimeBinding, CliError> {
    use chio_security_types::EnterpriseMigrationStateStore;

    if policy.trusted_transition_signers.is_empty()
        || policy.trusted_transition_signers.len() > 16
        || policy
            .trusted_transition_signers
            .windows(2)
            .any(|pair| pair[0].to_hex() >= pair[1].to_hex())
    {
        return Err(CliError::cli_other_error(
            "cage migration trust roots must be nonempty, bounded, sorted, and unique"
                .to_string(),
        ));
    }
    let tool_server_id = chio_security_types::ports::RecordId::new(server_id.to_string())
        .map_err(|error| {
            CliError::cli_other_error(format!("invalid cage migration tool server id: {error}"))
        })?;
    let expected_key = chio_security_types::EnterpriseMigrationKey {
        deployment_id: policy.deployment_id.clone(),
        scope_kind: chio_security_types::EnterpriseMigrationScopeKind::ToolServer,
        scope_id: tool_server_id.clone(),
        control: chio_security_types::EnterpriseMigrationControl::CageEnforcement,
    };
    if policy.minimum_head.key != expected_key
        || !policy.minimum_head.is_valid()
        || policy.minimum_head.minimum_generation != policy.stage.generation()
    {
        return Err(CliError::cli_other_error(
            "cage migration anchor does not match the exact tool server, control, and stage"
                .to_string(),
        ));
    }
    let posture = chio_security_types::cage_migration_posture_digest(
        &policy.deployment_id,
        &tool_server_id,
        policy.stage,
        launch_contract,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("cage migration posture denied: {error}"))
    })?;
    let open_policy = chio_store_sqlite::SqliteEnterpriseMigrationOpenPolicy::new(
        policy.trusted_transition_signers.clone(),
        vec![policy.minimum_head.clone()],
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("invalid cage migration open policy: {error}"))
    })?;
    let concrete = Arc::new(
        chio_store_sqlite::SqliteEnterpriseMigrationStateStore::open(
            &policy.state_database_path,
            open_policy,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("cage migration ledger denied: {error}"))
        })?,
    );
    let store: Arc<dyn EnterpriseMigrationStateStore> = concrete;
    chio_security_types::EnterpriseMigrationRuntimeBinding::load(
        &store,
        &expected_key,
        policy.stage,
        posture,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("cage migration runtime binding denied: {error}"))
    })
}

pub(crate) fn load_native_mcp_launch(
    path: &Path,
    trusted_policy_signer: &str,
    command: &str,
    args: &[&str],
    admitted_manifest_registry: Option<Arc<chio_manifest::VerifiedManifestRegistry>>,
) -> Result<chio_mcp_adapter::transport::NativeMcpLaunch, CliError> {
    let bytes = read_cage_policy(path)?;
    let trusted_policy_signer = chio_core::PublicKey::from_hex(trusted_policy_signer)
        .map_err(|error| {
            CliError::cli_other_error(format!("invalid cage policy trust root: {error}"))
        })?;
    load_native_mcp_launch_from_bytes(
        path,
        &bytes,
        &trusted_policy_signer,
        command,
        args,
        admitted_manifest_registry,
    )
}

#[allow(dead_code)]
pub(super) fn validate_native_mcp_demo_policy(
    path: &Path,
    trusted_policy_signer: &chio_core::PublicKey,
    command: &str,
    args: &[&str],
    expected_server_id: &str,
    physical_migration_database_path: &Path,
) -> Result<(), CliError> {
    let bytes = read_cage_policy(path)?;
    let policy = decode_cage_policy(path, &bytes, trusted_policy_signer)?;
    if policy.enterprise_migration.stage
        != chio_security_types::EnterpriseMigrationStage::Disabled
        || policy.signed_manifest.manifest.server_id != expected_server_id
    {
        return Err(CliError::cli_other_error(
            "provisioned native MCP demo policy must bind the exact server at Disabled stage"
                .to_string(),
        ));
    }

    let launch_contract = cage_launch_contract_digests(&policy, trusted_policy_signer)?;
    let mut validation_policy = policy;
    validation_policy.enterprise_migration.state_database_path =
        physical_migration_database_path.to_path_buf();
    let _authorization = compose_legacy_authorized_launch(
        validation_policy,
        command,
        args,
        &launch_contract,
        None,
    )?;
    Ok(())
}

fn load_native_mcp_launch_from_bytes(
    path: &Path,
    bytes: &[u8],
    trusted_policy_signer: &chio_core::PublicKey,
    command: &str,
    args: &[&str],
    admitted_manifest_registry: Option<Arc<chio_manifest::VerifiedManifestRegistry>>,
) -> Result<chio_mcp_adapter::transport::NativeMcpLaunch, CliError> {
    let policy = decode_cage_policy(path, bytes, trusted_policy_signer)?;
    let launch_contract = cage_launch_contract_digests(&policy, trusted_policy_signer)?;
    if policy.enterprise_migration.stage.legacy_fallback_permitted() {
        compose_legacy_authorized_launch(
            policy,
            command,
            args,
            &launch_contract,
            admitted_manifest_registry,
        )
        .map(|authorization| {
            chio_mcp_adapter::transport::NativeMcpLaunch::LegacyAuthorized(Box::new(
                authorization,
            ))
        })
    } else {
        compose_cage_required_launch(
            policy,
            command,
            args,
            &launch_contract,
            admitted_manifest_registry,
        )
        .map(|launch| {
            chio_mcp_adapter::transport::NativeMcpLaunch::CageRequired(Box::new(launch))
        })
    }
}

fn read_cage_policy(path: &Path) -> Result<Vec<u8>, CliError> {
    let bytes = std::fs::read(path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read cage launch policy {}: {error}",
            path.display()
        ))
    })?;
    if bytes.is_empty() || bytes.len() > MAX_CAGE_POLICY_BYTES {
        return Err(CliError::cli_other_error(format!(
            "cage launch policy {} is empty or exceeds {} bytes",
            path.display(),
            MAX_CAGE_POLICY_BYTES
        )));
    }
    Ok(bytes)
}

fn decode_cage_policy(
    path: &Path,
    bytes: &[u8],
    trusted_policy_signer: &chio_core::PublicKey,
) -> Result<McpCageLaunchPolicy, CliError> {
    let policy: SignedMcpCageLaunchPolicy = serde_json::from_slice(bytes).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse cage launch policy {}: {error}",
            path.display()
        ))
    })?;
    let canonical = chio_core::canonical_json_bytes(&policy).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to canonicalize cage launch policy {}: {error}",
            path.display()
        ))
    })?;
    if canonical != bytes {
        return Err(CliError::cli_other_error(format!(
            "cage launch policy {} must be canonical JSON",
            path.display()
        )));
    }
    if &policy.signer_public_key != trusted_policy_signer
        || !trusted_policy_signer
            .verify_canonical(&policy.body, &policy.signature)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "cage launch policy signature verification failed: {error}"
                ))
            })?
    {
        return Err(CliError::cli_other_error(
            "cage launch policy is not signed by the configured trust root".to_string(),
        ));
    }
    policy.body.runtime.execution_identity.validate().map_err(|error| {
        CliError::cli_other_error(format!(
            "cage launch policy execution identity is invalid: {error}"
        ))
    })?;
    Ok(policy.body)
}

fn resolve_launch_manifest_registry(
    policy: &McpCageLaunchPolicy,
    topology: chio_manifest::RuntimeToolTopology,
    admitted_manifest_registry: Option<Arc<chio_manifest::VerifiedManifestRegistry>>,
    context: &str,
) -> Result<Arc<chio_manifest::VerifiedManifestRegistry>, CliError> {
    let server_id = policy.signed_manifest.manifest.server_id.as_str();
    let registry = match admitted_manifest_registry {
        Some(registry) => {
            let admitted = registry.verified_manifest(server_id).ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "{context} server is absent from the live admitted manifest registry"
                ))
            })?;
            let policy_envelope = chio_core::canonical_json_bytes(&policy.signed_manifest)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "{context} policy manifest encoding failed: {error}"
                    ))
                })?;
            let admitted_envelope =
                chio_core::canonical_json_bytes(admitted).map_err(|error| {
                    CliError::cli_other_error(format!(
                        "{context} admitted manifest encoding failed: {error}"
                    ))
                })?;
            if policy_envelope != admitted_envelope
                || policy.registered_public_key != admitted.signer_key
            {
                return Err(CliError::cli_other_error(format!(
                    "{context} cage policy manifest is not byte-identical to the live admitted signed envelope"
                )));
            }
            registry
        }
        None => {
            let mut registry = chio_manifest::VerifiedManifestRegistry::default();
            registry
                .register_public_only(
                    policy.signed_manifest.clone(),
                    &policy.registered_public_key,
                    topology,
                )
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "{context} manifest registry admission denied: {error}"
                    ))
                })?;
            Arc::new(registry)
        }
    };
    registry.authorize_cage_manifest(server_id).map_err(|error| {
        CliError::cli_other_error(format!(
            "{context} manifest topology authorization denied: {error}"
        ))
    })?;
    Ok(registry)
}

fn compose_legacy_authorized_launch(
    policy: McpCageLaunchPolicy,
    command: &str,
    args: &[&str],
    launch_contract: &chio_security_types::CageLaunchContractDigests,
    admitted_manifest_registry: Option<Arc<chio_manifest::VerifiedManifestRegistry>>,
) -> Result<chio_mcp_adapter::transport::LegacyNativeLaunchAuthorization, CliError> {
    if policy.schema != MCP_CAGE_LAUNCH_POLICY_SCHEMA
        || policy.signed_manifest.manifest.schema != chio_manifest::TOOL_MANIFEST_SCHEMA
    {
        return Err(CliError::cli_other_error(
            "legacy native launch requires a strict signed cage policy and v2 manifest"
                .to_string(),
        ));
    }
    let expected_argv = std::iter::once(command.to_string())
        .chain(args.iter().map(|argument| (*argument).to_string()))
        .collect::<Vec<_>>();
    if !Path::new(command).is_absolute()
        || policy.runtime.target_path != Path::new(command)
        || policy.runtime.target_argv != expected_argv
    {
        return Err(CliError::cli_other_error(
            "cage policy target path and argv must exactly match the wrapped command".to_string(),
        ));
    }
    let server_id = policy.signed_manifest.manifest.server_id.clone();
    let profile = policy
        .signed_manifest
        .manifest
        .required_permissions
        .as_ref()
        .ok_or_else(|| {
            CliError::cli_other_error(
                "cage launch policy manifest has no explicit platform permissions".to_string(),
            )
        })?
        .native_syscall_profile;
    let topology = if profile == chio_manifest::NativeSyscallProfile::BrokeredNativeV1 {
        chio_manifest::RuntimeToolTopology::brokered()
    } else {
        chio_manifest::RuntimeToolTopology::local()
    };
    let registry = resolve_launch_manifest_registry(
        &policy,
        topology,
        admitted_manifest_registry,
        "legacy launch",
    )?;
    let migration = load_cage_migration_enforcer(
        &policy.enterprise_migration,
        &server_id,
        launch_contract,
    )?;
    chio_mcp_adapter::transport::LegacyNativeLaunchAuthorization::new(
        server_id,
        migration,
        registry,
    )
    .map_err(|error| {
            CliError::cli_other_error(format!(
                "legacy native launch migration authorization denied: {error}"
            ))
        })
}

fn compose_cage_required_launch(
    policy: McpCageLaunchPolicy,
    command: &str,
    args: &[&str],
    launch_contract: &chio_security_types::CageLaunchContractDigests,
    admitted_manifest_registry: Option<Arc<chio_manifest::VerifiedManifestRegistry>>,
) -> Result<chio_mcp_adapter::transport::CageRequiredLaunch, CliError> {
    if policy.schema != MCP_CAGE_LAUNCH_POLICY_SCHEMA {
        return Err(CliError::cli_other_error(
            "unsupported MCP cage launch policy schema".to_string(),
        ));
    }
    if policy.signed_manifest.manifest.schema != chio_manifest::TOOL_MANIFEST_SCHEMA {
        return Err(CliError::cli_other_error(
            "cage launch policy requires a strict v2 signed manifest".to_string(),
        ));
    }
    let declared_permissions = policy
        .signed_manifest
        .manifest
        .required_permissions
        .as_ref()
        .ok_or_else(|| {
            CliError::cli_other_error(
                "cage launch policy manifest has no explicit platform permissions".to_string(),
            )
        })?;
    let declared_profile = declared_permissions.native_syscall_profile;
    let declared_brokered =
        declared_profile == chio_manifest::NativeSyscallProfile::BrokeredNativeV1;
    if declared_brokered != policy.broker.is_some() {
        return Err(CliError::cli_other_error(
            "brokered cage profile requires exactly one authenticated broker FD binding"
                .to_string(),
        ));
    }
    if declared_brokered
        && (declared_permissions
            .read_paths
            .as_ref()
            .is_some_and(|paths| !paths.is_empty())
            || declared_permissions
                .write_paths
                .as_ref()
                .is_some_and(|paths| !paths.is_empty())
            || declared_permissions
                .environment_variables
                .as_ref()
                .is_some_and(|names| !names.is_empty()))
    {
        return Err(CliError::cli_other_error(
            "brokered cage policy forbids raw file and environment credential grants".to_string(),
        ));
    }

    let expected_argv = std::iter::once(command.to_string())
        .chain(args.iter().map(|argument| (*argument).to_string()))
        .collect::<Vec<_>>();
    if !Path::new(command).is_absolute()
        || policy.runtime.target_path != Path::new(command)
        || policy.runtime.target_argv != expected_argv
    {
        return Err(CliError::cli_other_error(
            "cage policy target path and argv must exactly match the wrapped command".to_string(),
        ));
    }

    let topology = if declared_brokered {
        chio_manifest::RuntimeToolTopology::brokered()
    } else {
        chio_manifest::RuntimeToolTopology::local()
    };
    let server_id = policy.signed_manifest.manifest.server_id.clone();
    let manifest_registry = resolve_launch_manifest_registry(
        &policy,
        topology,
        admitted_manifest_registry,
        "cage launch",
    )?;
    let receipt_policy = policy.receipt;
    let ceilings = chio_cage::OperatorCeilings::new(
        policy.operator_ceilings.read_paths,
        policy.operator_ceilings.write_paths,
        policy.operator_ceilings.network_destinations,
        policy.operator_ceilings.environment_variables,
        policy.operator_ceilings.native_syscall_profiles,
    )
    .with_forbidden_paths(policy.operator_ceilings.forbidden_paths);
    let admitted = {
        let authorization = manifest_registry
            .authorize_cage_manifest(&server_id)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "cage manifest topology authorization denied: {error}"
                ))
            })?;
        let verified_permissions = authorization
            .signed_manifest()
            .manifest
            .required_permissions
            .as_ref()
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "cage launch policy manifest has no explicit platform permissions".to_string(),
                )
            })?;
        validate_runtime_file_declarations(&policy.runtime.runtime_files, verified_permissions)?;
        chio_cage::admit(authorization, &ceilings).map_err(|error| {
            CliError::cli_other_error(format!("cage manifest admission denied: {error}"))
        })?
    };
    let migration = load_cage_migration_enforcer(
        &policy.enterprise_migration,
        &server_id,
        launch_contract,
    )?;
    if policy.runtime.runtime_files.iter().any(|runtime_file| {
        !admitted
            .read_resources()
            .iter()
            .any(|resource| resource.path() == runtime_file.as_path())
    }) {
        return Err(CliError::cli_other_error(
            "cage runtime files must be exact read paths in the verified manifest".to_string(),
        ));
    }
    let runtime_paths = chio_cage::RuntimeResourcePaths::new(
        policy.runtime.cage_init_path,
        policy.runtime.target_path,
        policy.runtime.working_directory,
        policy.runtime.runtime_files,
        policy.runtime.execution_identity,
    )
    .with_target_argv(policy.runtime.target_argv)
    .with_max_artifact_bytes(policy.limits.max_artifact_bytes);
    let runtime = chio_cage::retain_runtime_resources(&runtime_paths).map_err(|error| {
        CliError::cli_other_error(format!("cage runtime artifact retention denied: {error}"))
    })?;
    if runtime.helper().binding_digest() != policy.runtime.cage_init_binding_digest
        || runtime.target().binding_digest() != policy.runtime.target_binding_digest
    {
        return Err(CliError::cli_other_error(
            "cage helper or target artifact does not match its pinned binding digest".to_string(),
        ));
    }

    let broker = policy.broker.map(retain_policy_broker).transpose()?;
    let compiled =
        chio_cage::compile(admitted, runtime, &parent_environment(), broker).map_err(|error| {
            CliError::cli_other_error(format!("cage plan compilation denied: {error}"))
        })?;
    if compiled.plan().resource_limits.nofile_soft != policy.limits.nofile_soft
        || compiled.plan().resource_limits.nofile_hard != policy.limits.nofile_hard
    {
        return Err(CliError::cli_other_error(
            "cage policy resource limits do not match the reviewed compiler limits".to_string(),
        ));
    }
    let launch_options =
        chio_cage::CageLaunchOptions::new(Duration::from_millis(policy.limits.launch_timeout_ms))
            .map_err(|_| CliError::cli_other_error("invalid cage launch timeout".to_string()))?;
    let receipt_persistence = cage_receipt_persistence(
        &receipt_policy,
        &server_id,
        compiled.profile_digest(),
        compiled.plan_digest(),
    )?;
    chio_mcp_adapter::transport::CageRequiredLaunch::new(
        manifest_registry,
        server_id,
        compiled,
        receipt_persistence,
        migration,
    )
    .map(|launch| launch.with_launch_options(launch_options))
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "cage receipt release-evidence configuration denied: {error}"
        ))
    })
}

fn validate_runtime_file_declarations(
    runtime_files: &BTreeSet<PathBuf>,
    permissions: &chio_manifest::RequiredPermissions,
) -> Result<(), CliError> {
    let declared_read_paths = permissions.read_paths.as_deref().unwrap_or_default();
    if runtime_files.iter().any(|runtime_file| {
        !declared_read_paths
            .iter()
            .any(|declared| Path::new(declared) == runtime_file.as_path())
    }) {
        return Err(CliError::cli_other_error(
            "cage runtime files must be exact read paths in the verified manifest".to_string(),
        ));
    }
    Ok(())
}

fn cage_receipt_persistence(
    policy: &CageReceiptRuntimePolicy,
    server_id: &str,
    profile_digest: &str,
    plan_digest: &str,
) -> Result<chio_mcp_adapter::transport::CageReceiptPersistence, CliError> {
    if !policy.database_path.is_absolute()
        || !policy.signer_seed_path.is_absolute()
        || policy.database_path == policy.signer_seed_path
    {
        return Err(CliError::cli_other_error(
            "cage receipt database and signer seed paths must be distinct absolute paths"
                .to_string(),
        ));
    }
    let signer = crate::load_existing_authority_keypair(&policy.signer_seed_path)?;
    let trusted_signer = chio_core::PublicKey::from_hex(&policy.trusted_signer_public_key)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "invalid cage receipt trusted signer public key: {error}"
            ))
        })?;
    let receipt_store: Arc<dyn chio_kernel::ReceiptStore> = Arc::new(
        chio_store_sqlite::SqliteReceiptStore::open(&policy.database_path).map_err(|error| {
            CliError::cli_other_error(format!("failed to open cage receipt store: {error}"))
        })?,
    );
    let context = chio_cage::CageReceiptSigningContext::new(
        policy.capability_id.clone(),
        server_id.to_string(),
        "cage-launch".to_string(),
        profile_digest.to_string(),
        policy.tenant_id.clone(),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("cage receipt signing context denied: {error}"))
    })?;
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CliError::cli_other_error("system clock is before Unix epoch".to_string()))?;
    let attempt_input = format!(
        "{server_id}\0{profile_digest}\0{plan_digest}\0{}\0{}",
        std::process::id(),
        elapsed.as_nanos()
    );
    let attempt_id = format!(
        "cage-launch-{}",
        chio_core::sha256_hex(attempt_input.as_bytes())
    );
    chio_mcp_adapter::transport::CageReceiptPersistence::new(
        attempt_id,
        context,
        Arc::new(chio_core::Ed25519Backend::new(signer)),
        trusted_signer,
        receipt_store,
    )
    .map_err(|error| CliError::cli_other_error(format!("cage receipt persistence denied: {error}")))
}

fn parent_environment() -> BTreeMap<String, String> {
    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

#[cfg(target_os = "linux")]
fn retain_policy_broker(binding: CageBrokerBinding) -> Result<chio_cage::BrokerIpc, CliError> {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    let file = match (binding.inherited_fd, binding.socket_path.as_ref()) {
        (Some(inherited_fd), None) => {
            if inherited_fd < 3 {
                return Err(CliError::cli_other_error(
                    "cage broker inherited FD must be at least 3".to_string(),
                ));
            }
            // SAFETY: fcntl duplicates a caller-owned live descriptor. On
            // success the returned descriptor has unique ownership and
            // CLOEXEC is set atomically.
            let duplicated = unsafe { libc::fcntl(inherited_fd, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicated < 0 {
                return Err(CliError::cli_other_error(format!(
                    "failed to duplicate inherited cage broker FD: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: a successful F_DUPFD_CLOEXEC returned a new descriptor
            // owned by this function and transferred immediately to File.
            unsafe { std::fs::File::from_raw_fd(duplicated) }
        }
        (None, Some(socket_path)) => {
            if !socket_path.is_absolute()
                || socket_path.as_os_str().as_encoded_bytes().is_empty()
                || socket_path.as_os_str().as_encoded_bytes().len() > 100
            {
                return Err(CliError::cli_other_error(
                    "cage broker socket path is invalid".to_string(),
                ));
            }
            let stream = UnixStream::connect(socket_path).map_err(|error| {
                CliError::cli_other_error(format!(
                    "failed to establish preconnected cage broker FD: {error}"
                ))
            })?;
            std::fs::File::from(OwnedFd::from(stream))
        }
        _ => {
            return Err(CliError::cli_other_error(
                "cage broker binding requires exactly one inherited FD or socket path".to_string(),
            ));
        }
    };
    chio_cage::retain_broker_ipc(
        file,
        binding.authentication_digest,
        binding.expected_peer_identity,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("cage broker FD authentication denied: {error}"))
    })
}

#[cfg(not(target_os = "linux"))]
fn retain_policy_broker(_binding: CageBrokerBinding) -> Result<chio_cage::BrokerIpc, CliError> {
    Err(CliError::cli_other_error(
        "cage broker FD binding is unsupported on this platform".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_security_types::EnterpriseMigrationStateStore;
    use chio_test_support::prelude::*;

    fn signed_manifest(
        profile: chio_manifest::NativeSyscallProfile,
    ) -> (chio_manifest::SignedManifest, chio_core::Keypair) {
        let keypair = chio_core::Keypair::from_seed(&[91; 32]);
        let manifest = chio_manifest::ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "cage-policy-test".to_string(),
            name: "Cage policy test".to_string(),
            description: None,
            version: "1".to_string(),
            tools: vec![chio_manifest::ToolDefinition {
                name: "echo".to_string(),
                description: "Echo".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: true,
                    requires_approval: false,
                    estimated_duration_ms: None,
                },
                latency_hint: Some(chio_manifest::LatencyHint::Fast),
                flow: None,
            }],
            server_tools: Vec::new(),
            required_permissions: Some(chio_manifest::RequiredPermissions {
                read_paths: None,
                write_paths: None,
                network_destinations: None,
                environment_variables: None,
                native_syscall_profile: profile,
            }),
            public_key: keypair.public_key().to_hex(),
        };
        let signed = chio_manifest::sign_manifest(&manifest, &keypair).test_unwrap();
        (signed, keypair)
    }

    fn policy(
        manifest_profile: chio_manifest::NativeSyscallProfile,
        ceiling_profile: chio_manifest::NativeSyscallProfile,
    ) -> McpCageLaunchPolicy {
        let (signed_manifest, keypair) = signed_manifest(manifest_profile);
        let deployment_id = chio_security_types::ports::RecordId::new("production.test")
            .test_expect("cage migration deployment id");
        let tool_server_id = chio_security_types::ports::RecordId::new("cage-policy-test")
            .test_expect("cage migration tool server id");
        let migration_key = chio_security_types::EnterpriseMigrationKey {
            deployment_id: deployment_id.clone(),
            scope_kind: chio_security_types::EnterpriseMigrationScopeKind::ToolServer,
            scope_id: tool_server_id,
            control: chio_security_types::EnterpriseMigrationControl::CageEnforcement,
        };
        McpCageLaunchPolicy {
            schema: MCP_CAGE_LAUNCH_POLICY_SCHEMA.to_string(),
            signed_manifest,
            registered_public_key: keypair.public_key(),
            operator_ceilings: CageOperatorCeilings {
                read_paths: BTreeSet::new(),
                write_paths: BTreeSet::new(),
                network_destinations: BTreeSet::new(),
                environment_variables: BTreeSet::new(),
                native_syscall_profiles: [ceiling_profile].into_iter().collect(),
                forbidden_paths: BTreeSet::new(),
            },
            runtime: CageRuntimePolicy {
                cage_init_path: PathBuf::from("/operator/chio-cage-init"),
                cage_init_binding_digest: "1".repeat(64),
                target_path: PathBuf::from("/operator/mcp-server"),
                target_binding_digest: "2".repeat(64),
                working_directory: PathBuf::from("/operator/workdir"),
                runtime_files: BTreeSet::new(),
                target_argv: vec!["/operator/mcp-server".to_string()],
                execution_identity: chio_cage::ExecutionIdentity::new(
                    10001,
                    10001,
                    Vec::new(),
                )
                .test_expect("valid execution identity"),
            },
            limits: CageLimitPolicy {
                max_artifact_bytes: 1024 * 1024,
                launch_timeout_ms: 10_000,
                nofile_soft: 192,
                nofile_hard: 192,
            },
            receipt: CageReceiptRuntimePolicy {
                database_path: PathBuf::from("/operator/cage-receipts.sqlite3"),
                signer_seed_path: PathBuf::from("/operator/cage-receipt-seed"),
                trusted_signer_public_key: keypair.public_key().to_hex(),
                capability_id: "cage-launch-capability".to_string(),
                tenant_id: Some("tenant-test".to_string()),
            },
            enterprise_migration: CageMigrationPolicy {
                state_database_path: PathBuf::from("/operator/enterprise-migration.sqlite3"),
                deployment_id,
                stage: chio_security_types::EnterpriseMigrationStage::Enforced,
                trusted_transition_signers: vec![keypair.public_key()],
                minimum_head: chio_security_types::EnterpriseMigrationMinimumHead {
                    key: migration_key,
                    minimum_generation: chio_security_types::EnterpriseMigrationStage::Enforced
                        .generation(),
                    transition_digest: chio_security_types::ports::Digest32::new([0x77; 32]),
                },
            },
            broker: None,
        }
    }

    fn signed_policy(
        policy: McpCageLaunchPolicy,
        signer: &chio_core::Keypair,
    ) -> SignedMcpCageLaunchPolicy {
        let (signature, _) = signer
            .sign_canonical(&policy)
            .test_expect("sign cage launch policy");
        SignedMcpCageLaunchPolicy {
            body: policy,
            signer_public_key: signer.public_key(),
            signature,
        }
    }

    fn test_launch_contract() -> chio_security_types::CageLaunchContractDigests {
        chio_security_types::CageLaunchContractDigests {
            policy_schema_digest: chio_security_types::ports::Digest32::new([0x80; 32]),
            policy_signer_digest: chio_security_types::ports::Digest32::new([0x81; 32]),
            signed_manifest_digest: chio_security_types::ports::Digest32::new([0x82; 32]),
            registered_public_key_digest: chio_security_types::ports::Digest32::new([0x83; 32]),
            operator_ceilings_digest: chio_security_types::ports::Digest32::new([0x84; 32]),
            runtime_digest: chio_security_types::ports::Digest32::new([0x85; 32]),
            limits_digest: chio_security_types::ports::Digest32::new([0x86; 32]),
            receipt_digest: chio_security_types::ports::Digest32::new([0x87; 32]),
            broker_binding_digest: chio_security_types::ports::Digest32::new([0x88; 32]),
            migration_ledger_digest: chio_security_types::ports::Digest32::new([0x89; 32]),
        }
    }

    fn durable_migration_policy_at_stage(
        directory: &Path,
        target_stage: chio_security_types::EnterpriseMigrationStage,
    ) -> (CageMigrationPolicy, chio_core::Keypair) {
        let trusted_directory = directory
            .canonicalize()
            .test_expect("canonical cage migration directory");
        let state_database_path = trusted_directory.join("enterprise-migration.sqlite3");
        let signer = chio_core::Keypair::from_seed(&[94; 32]);
        let deployment_id = chio_security_types::ports::RecordId::new("production.test")
            .test_expect("cage migration deployment id");
        let tool_server_id = chio_security_types::ports::RecordId::new("cage-policy-test")
            .test_expect("cage migration tool server id");
        let key = chio_security_types::EnterpriseMigrationKey {
            deployment_id: deployment_id.clone(),
            scope_kind: chio_security_types::EnterpriseMigrationScopeKind::ToolServer,
            scope_id: tool_server_id.clone(),
            control: chio_security_types::EnterpriseMigrationControl::CageEnforcement,
        };
        let store = chio_store_sqlite::SqliteEnterpriseMigrationStateStore::open(
            &state_database_path,
            chio_store_sqlite::SqliteEnterpriseMigrationOpenPolicy::new(
                vec![signer.public_key()],
                Vec::new(),
            )
            .test_expect("cage migration open policy"),
        )
        .test_expect("open cage migration ledger");
        let genesis = chio_security_types::EnterpriseMigrationTransitionBody::genesis(
            key.clone(),
            chio_security_types::cage_migration_posture_digest(
                &deployment_id,
                &tool_server_id,
                chio_security_types::EnterpriseMigrationStage::Disabled,
                &test_launch_contract(),
            )
            .test_expect("cage migration genesis posture"),
            chio_security_types::ports::Digest32::new([0x31; 32]),
            chio_security_types::ports::Digest32::new([0x32; 32]),
            chio_security_types::ports::Digest32::new([0x33; 32]),
            1,
            signer.public_key().to_hex(),
        )
        .test_expect("cage migration genesis body");
        let genesis = chio_store_sqlite::sign_enterprise_migration_transition(genesis, &signer)
            .test_expect("sign cage migration genesis");
        let _ = store
            .register(&genesis)
            .test_expect("register cage migration genesis");
        let mut state = store
            .load(&key)
            .test_expect("load cage migration genesis")
            .test_expect("cage migration genesis exists");
        while state.stage < target_stage {
            let next = state
                .stage
                .next()
                .test_expect("cage migration next stage");
            let body = chio_security_types::EnterpriseMigrationTransitionBody::promotion(
                &state,
                chio_security_types::cage_migration_posture_digest(
                    &deployment_id,
                    &tool_server_id,
                    next,
                    &test_launch_contract(),
                )
                    .test_expect("cage migration promotion posture"),
                chio_security_types::ports::Digest32::new([
                    0x40_u8.saturating_add(next.generation() as u8);
                    32
                ]),
                chio_security_types::ports::Digest32::new([
                    0x50_u8.saturating_add(next.generation() as u8);
                    32
                ]),
                chio_security_types::ports::Digest32::new([
                    0x60_u8.saturating_add(next.generation() as u8);
                    32
                ]),
                next.generation().saturating_add(10),
                signer.public_key().to_hex(),
            )
            .test_expect("cage migration promotion body");
            let transition =
                chio_store_sqlite::sign_enterprise_migration_transition(body, &signer)
                    .test_expect("sign cage migration promotion");
            let _ = store
                .compare_and_promote(&transition)
                .test_expect("promote cage migration state");
            state = store
                .load(&key)
                .test_expect("load promoted cage migration state")
                .test_expect("promoted cage migration state exists");
        }
        (
            CageMigrationPolicy {
                state_database_path,
                deployment_id,
                stage: target_stage,
                trusted_transition_signers: vec![signer.public_key()],
                minimum_head: state.minimum_head(),
            },
            signer,
        )
    }

    fn durable_migration_policy(
        directory: &Path,
    ) -> (CageMigrationPolicy, chio_core::Keypair) {
        durable_migration_policy_at_stage(
            directory,
            chio_security_types::EnterpriseMigrationStage::Enforced,
        )
    }

    #[test]
    fn cage_policy_requires_canonical_deny_unknown_json() {
        let body = policy(
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        );
        let signer = chio_core::Keypair::from_seed(&[92; 32]);
        let signed = signed_policy(body, &signer);
        let canonical = chio_core::canonical_json_bytes(&signed).test_unwrap();
        decode_cage_policy(Path::new("policy.json"), &canonical, &signer.public_key())
            .test_unwrap();

        let mut noncanonical = canonical.clone();
        noncanonical.push(b'\n');
        assert!(decode_cage_policy(
            Path::new("policy.json"),
            &noncanonical,
            &signer.public_key(),
        )
            .test_unwrap_err()
            .to_string()
            .contains("canonical JSON"));

        let mut value = serde_json::to_value(signed).test_unwrap();
        value["unknown"] = serde_json::json!(true);
        let unknown = chio_core::canonical_json_bytes(&value).test_unwrap();
        assert!(decode_cage_policy(
            Path::new("policy.json"),
            &unknown,
            &signer.public_key(),
        )
        .is_err());
        assert!(decode_cage_policy(
            Path::new("policy.json"),
            &canonical,
            &chio_core::Keypair::from_seed(&[93; 32]).public_key(),
        )
        .is_err());

        let mut forged_body = serde_json::to_value(policy(
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        ))
        .test_unwrap();
        forged_body["runtime"]["execution_identity"]["uid"] = serde_json::json!(0);
        let forged_body: McpCageLaunchPolicy = serde_json::from_value(forged_body).test_unwrap();
        let forged = signed_policy(forged_body, &signer);
        let forged = chio_core::canonical_json_bytes(&forged).test_unwrap();
        assert!(decode_cage_policy(
            Path::new("policy.json"),
            &forged,
            &signer.public_key(),
        )
        .test_unwrap_err()
        .to_string()
        .contains("execution identity"));
    }

    #[test]
    fn live_registry_rejects_replayed_policy_manifest_before_compilation() {
        let mut policy = policy(
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        );
        let original = policy.signed_manifest.clone();
        let mut registry = chio_manifest::VerifiedManifestRegistry::default();
        registry
            .register_public_only(
                original,
                &policy.registered_public_key,
                chio_manifest::RuntimeToolTopology::local(),
            )
            .test_expect("register live manifest");

        policy
            .signed_manifest
            .manifest
            .required_permissions
            .as_mut()
            .test_expect("test manifest permissions")
            .read_paths = Some(vec!["/operator/broader".to_string()]);
        let manifest_signer = chio_core::Keypair::from_seed(&[91; 32]);
        policy.signed_manifest =
            chio_manifest::sign_manifest(&policy.signed_manifest.manifest, &manifest_signer)
                .test_expect("sign replayed broader manifest");

        let error = resolve_launch_manifest_registry(
            &policy,
            chio_manifest::RuntimeToolTopology::local(),
            Some(Arc::new(registry)),
            "test launch",
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("not byte-identical"));
    }

    #[test]
    fn migration_posture_changes_with_every_authority_component() {
        let policy_signer = chio_core::Keypair::from_seed(&[92; 32]);
        let mut first = policy(
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        );
        let first_contract = cage_launch_contract_digests(&first, &policy_signer.public_key())
            .test_expect("first launch contract");
        first.runtime.execution_identity =
            chio_cage::ExecutionIdentity::new(10003, 10001, Vec::new())
                .test_expect("changed execution identity");
        let changed_contract = cage_launch_contract_digests(&first, &policy_signer.public_key())
            .test_expect("changed launch contract");
        assert_ne!(first_contract.runtime_digest, changed_contract.runtime_digest);

        let deployment_id = chio_security_types::ports::RecordId::new("production.test")
            .test_expect("deployment id");
        let tool_server_id = chio_security_types::ports::RecordId::new("cage-policy-test")
            .test_expect("tool server id");
        let first_posture = chio_security_types::cage_migration_posture_digest(
            &deployment_id,
            &tool_server_id,
            chio_security_types::EnterpriseMigrationStage::Enforced,
            &first_contract,
        )
        .test_expect("first posture");
        let changed_posture = chio_security_types::cage_migration_posture_digest(
            &deployment_id,
            &tool_server_id,
            chio_security_types::EnterpriseMigrationStage::Enforced,
            &changed_contract,
        )
        .test_expect("changed posture");
        assert_ne!(first_posture, changed_posture);
    }

    #[test]
    fn launch_factory_pins_verified_policy_bytes_at_construction() {
        let directory = tempfile::tempdir().test_expect("launch factory directory");
        let path = directory.path().join("cage-policy.json");
        let signer = chio_core::Keypair::from_seed(&[92; 32]);
        let signed = signed_policy(
            policy(
                chio_manifest::NativeSyscallProfile::NativeMinimalV1,
                chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            ),
            &signer,
        );
        std::fs::write(
            &path,
            chio_core::canonical_json_bytes(&signed).test_expect("canonical signed policy"),
        )
        .test_expect("write signed cage policy");
        let factory = SignedCagePolicyLaunchFactory::new(path.clone(), signer.public_key().to_hex())
            .test_expect("pin signed cage policy");
        let pinned = chio_mcp_adapter::transport::NativeMcpLaunchFactory::authorization_contract_digest(
            &factory,
        )
        .test_expect("pinned launch authorization");

        std::fs::write(&path, b"substituted").test_expect("replace policy path");
        let after_replacement =
            chio_mcp_adapter::transport::NativeMcpLaunchFactory::authorization_contract_digest(
                &factory,
            )
            .test_expect("retained pinned launch authorization");
        assert_eq!(pinned, after_replacement);
    }

    #[test]
    fn cage_migration_revalidates_after_preparation_and_recovers_only_by_rebuild() {
        let directory = tempfile::tempdir().test_expect("cage migration test directory");
        let (policy, signer) = durable_migration_policy(directory.path());
        let enforcer =
            load_cage_migration_enforcer(&policy, "cage-policy-test", &test_launch_contract())
            .test_expect("load enforced cage migration binding");
        enforcer
            .require_enforced()
            .test_expect("revalidate unchanged cage migration binding");

        let store = chio_store_sqlite::SqliteEnterpriseMigrationStateStore::open(
            &policy.state_database_path,
            chio_store_sqlite::SqliteEnterpriseMigrationOpenPolicy::new(
                vec![signer.public_key()],
                Vec::new(),
            )
            .test_expect("mutating cage migration open policy"),
        )
        .test_expect("open mutating cage migration ledger");
        let prior = store
            .load(&policy.minimum_head.key)
            .test_expect("load enforced cage migration state")
            .test_expect("enforced cage migration state exists");
        let tool_server_id = policy.minimum_head.key.scope_id.clone();
        let body = chio_security_types::EnterpriseMigrationTransitionBody::promotion(
            &prior,
            chio_security_types::cage_migration_posture_digest(
                &policy.deployment_id,
                &tool_server_id,
                chio_security_types::EnterpriseMigrationStage::LegacyRemoved,
                &test_launch_contract(),
            )
            .test_expect("legacy-removed cage posture"),
            chio_security_types::ports::Digest32::new([0x71; 32]),
            chio_security_types::ports::Digest32::new([0x72; 32]),
            chio_security_types::ports::Digest32::new([0x73; 32]),
            20,
            signer.public_key().to_hex(),
        )
        .test_expect("legacy-removed cage transition body");
        let transition = chio_store_sqlite::sign_enterprise_migration_transition(body, &signer)
            .test_expect("sign legacy-removed cage transition");
        let _ = store
            .compare_and_promote(&transition)
            .test_expect("promote cage migration beyond retained binding");
        let promoted = store
            .load(&policy.minimum_head.key)
            .test_expect("load legacy-removed cage state")
            .test_expect("legacy-removed cage state exists");

        assert!(enforcer.require_enforced().is_err());
        assert!(chio_mcp_adapter::transport::LegacyNativeLaunchAuthorization::new(
            "other-server",
            enforcer.clone(),
            Arc::new(chio_manifest::VerifiedManifestRegistry::default()),
        )
        .is_err());

        let mut rebuilt_policy = policy;
        rebuilt_policy.stage = chio_security_types::EnterpriseMigrationStage::LegacyRemoved;
        rebuilt_policy.minimum_head = promoted.minimum_head();
        let rebuilt = load_cage_migration_enforcer(
            &rebuilt_policy,
            "cage-policy-test",
            &test_launch_contract(),
        )
            .test_expect("rebuild cage migration binding at the anchored head");
        rebuilt
            .require_enforced()
            .test_expect("revalidate rebuilt cage migration binding");
    }

    #[test]
    fn independent_operator_ceiling_rejection_precedes_runtime_launch() {
        let error = compose_cage_required_launch(
            policy(
                chio_manifest::NativeSyscallProfile::NativeStandardV1,
                chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            ),
            "/operator/mcp-server",
            &[],
            &test_launch_contract(),
            None,
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("operator ceilings"));
    }

    #[test]
    fn operator_runtime_file_cannot_widen_verified_manifest_authority() {
        let mut policy = policy(
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        );
        policy
            .runtime
            .runtime_files
            .insert(PathBuf::from("/operator/arbitrary-secret"));

        let error = compose_cage_required_launch(
            policy,
            "/operator/mcp-server",
            &[],
            &test_launch_contract(),
            None,
        )
        .test_unwrap_err();
        assert!(error
            .to_string()
            .contains("exact read paths in the verified manifest"));
    }

    #[test]
    fn brokered_profile_without_authenticated_broker_binding_is_rejected() {
        let error = compose_cage_required_launch(
            policy(
                chio_manifest::NativeSyscallProfile::BrokeredNativeV1,
                chio_manifest::NativeSyscallProfile::BrokeredNativeV1,
            ),
            "/operator/mcp-server",
            &[],
            &test_launch_contract(),
            None,
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("authenticated broker FD"));
    }

    #[test]
    fn unprotected_wrapper_uses_signed_registry_flow_requirement() {
        let mut policy = policy(
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
            chio_manifest::NativeSyscallProfile::NativeMinimalV1,
        );
        let keypair = chio_core::Keypair::from_seed(&[91; 32]);
        policy.signed_manifest.manifest.tools[0].flow =
            Some(chio_manifest::ToolFlowDeclaration::public_egress());
        policy.signed_manifest =
            chio_manifest::sign_manifest(&policy.signed_manifest.manifest, &keypair).test_unwrap();

        let mut registry = chio_manifest::VerifiedManifestRegistry::default();
        registry
            .register_public_only(
                policy.signed_manifest,
                &keypair.public_key(),
                chio_manifest::RuntimeToolTopology::local(),
            )
            .test_unwrap();
        assert!(registry.authorize_cage_manifest("cage-policy-test").is_ok());

        let directory = tempfile::tempdir().test_expect("flow launch migration directory");
        let (migration_policy, _) = durable_migration_policy_at_stage(
            directory.path(),
            chio_security_types::EnterpriseMigrationStage::Shadow,
        );
        let migration = load_cage_migration_enforcer(
            &migration_policy,
            "cage-policy-test",
            &test_launch_contract(),
        )
            .test_expect("flow launch migration binding");
        let launch = chio_mcp_adapter::transport::NativeMcpLaunch::LegacyAuthorized(
            Box::new(
                chio_mcp_adapter::transport::LegacyNativeLaunchAuthorization::new(
                    "cage-policy-test".to_string(),
                    migration,
                    Arc::new(registry),
                )
                .test_expect("flow legacy launch authorization"),
            ),
        );
        assert!(launch.requires_flow_runtime());
        let error =
            super::super::wrap::require_unprotected_wrap_compatible(&launch).test_unwrap_err();
        assert!(error
            .to_string()
            .contains("rejects flow-required manifests"));

        let (signed_manifest, registered_key) =
            signed_manifest(chio_manifest::NativeSyscallProfile::NativeMinimalV1);
        let mut flow_free_registry = chio_manifest::VerifiedManifestRegistry::default();
        flow_free_registry
            .register_public_only(
                signed_manifest,
                &registered_key.public_key(),
                chio_manifest::RuntimeToolTopology::local(),
            )
            .test_expect("register flow-free signed manifest");
        let flow_free_migration = load_cage_migration_enforcer(
            &migration_policy,
            "cage-policy-test",
            &test_launch_contract(),
        )
                .test_expect("flow-free launch migration binding");
        let flow_free_launch = chio_mcp_adapter::transport::NativeMcpLaunch::LegacyAuthorized(
            Box::new(
                chio_mcp_adapter::transport::LegacyNativeLaunchAuthorization::new(
                    "cage-policy-test".to_string(),
                    flow_free_migration,
                    Arc::new(flow_free_registry),
                )
                .test_expect("flow-free legacy launch authorization"),
            ),
        );
        assert!(!flow_free_launch.requires_flow_runtime());
        super::super::wrap::require_unprotected_wrap_compatible(&flow_free_launch)
            .test_expect("flow-free launch remains wrapper compatible");
    }
}
