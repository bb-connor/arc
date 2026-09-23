use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub(crate) const MCP_CAGE_LAUNCH_POLICY_SCHEMA: &str = "chio.mcp.cage-launch-policy.v2";
const MAX_CAGE_POLICY_BYTES: usize = 4 * 1024 * 1024;

#[path = "cage_policy/evidence.rs"]
mod evidence;
#[cfg(target_os = "linux")]
pub(crate) use evidence::{export_native_launch_evidence, export_native_launch_observations};
pub(crate) use evidence::{
    verify_native_launch_evidence, verify_native_launch_observation, verify_native_start_file,
    NativeLaunchEvidence, NativeLaunchObservation,
};

#[cfg(all(test, target_os = "linux"))]
#[path = "cage_receipt_tests.rs"]
mod receipt_tests;

#[derive(Clone)]
pub(crate) struct SignedCagePolicyLaunchFactory {
    path: PathBuf,
    trusted_policy_signer: String,
    trusted_policy_signer_key: chio_core::PublicKey,
    signed_policy_bytes: Arc<[u8]>,
}

impl SignedCagePolicyLaunchFactory {
    pub(crate) fn new(path: PathBuf, trusted_policy_signer: String) -> Result<Self, CliError> {
        let signed_policy_bytes = read_cage_policy(&path)?;
        let trusted_policy_signer_key = chio_core::PublicKey::from_hex(&trusted_policy_signer)
            .map_err(|error| {
                CliError::cli_other_error(format!("invalid cage policy trust root: {error}"))
            })?;
        let _ = decode_cage_policy(&path, &signed_policy_bytes, &trusted_policy_signer_key)?;
        Ok(Self {
            path,
            trusted_policy_signer,
            trusted_policy_signer_key,
            signed_policy_bytes: Arc::from(signed_policy_bytes),
        })
    }
}

impl chio_mcp_adapter::transport::NativeMcpLaunchFactory for SignedCagePolicyLaunchFactory {
    #[cfg(target_os = "linux")]
    fn prepare_broker_launch(
        &self,
        command: &str,
        args: &[&str],
        expected_server_id: &str,
        admitted_manifest_registry: Arc<chio_manifest::VerifiedManifestRegistry>,
        stream: std::os::unix::net::UnixStream,
    ) -> Result<chio_mcp_adapter::transport::CageRequiredLaunch, chio_mcp_adapter::edge::AdapterError>
    {
        use chio_mcp_adapter::edge::AdapterError;
        use std::os::fd::OwnedFd;

        let policy = decode_cage_policy(
            &self.path,
            self.signed_policy_bytes.as_ref(),
            &self.trusted_policy_signer_key,
        )
        .map_err(|error| AdapterError::ConnectionFailed(error.to_string()))?;
        if policy
            .enterprise_migration
            .stage
            .legacy_fallback_permitted()
            || policy.signed_manifest.manifest.server_id != expected_server_id
        {
            return Err(AdapterError::ConnectionFailed(
                "prepared broker policy must enforce the exact tool server".to_string(),
            ));
        }
        let contract = cage_launch_contract_digests(&policy, &self.trusted_policy_signer_key)
            .map_err(|error| AdapterError::ConnectionFailed(error.to_string()))?;
        compose_cage_required_launch_with_prepared_broker(
            policy,
            &chio_core::sha256_hex(self.signed_policy_bytes.as_ref()),
            command,
            args,
            &contract,
            Some(admitted_manifest_registry),
            Some(std::fs::File::from(OwnedFd::from(stream))),
        )
        .map_err(|error| AdapterError::ConnectionFailed(error.to_string()))
    }

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

/// Reviewed connection identity for a brokered reference launch. The live
/// descriptor and its peer credentials are still authenticated at launch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisionedBrokerBinding {
    pub(super) socket_path: PathBuf,
    pub(super) authentication_digest: String,
    pub(super) expected_peer_identity: chio_cage::BrokerPeerIdentity,
}

impl ProvisionedBrokerBinding {
    pub(super) fn validate(&self) -> Result<(), CliError> {
        if !self.socket_path.is_absolute()
            || self.socket_path.as_os_str().as_encoded_bytes().len() > 100
            || self.socket_path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || !is_sha256_hex(&self.authentication_digest)
            || self.expected_peer_identity.pid == 0
        {
            return Err(CliError::cli_other_error(
                "broker binding requires an absolute socket path, SHA-256 authentication digest and nonzero peer PID".to_string(),
            ));
        }
        Ok(())
    }

    fn policy_binding(&self) -> CageBrokerBinding {
        CageBrokerBinding {
            inherited_fd: None,
            socket_path: Some(self.socket_path.clone()),
            authentication_digest: self.authentication_digest.clone(),
            expected_peer_identity: self.expected_peer_identity,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CageReceiptRuntimePolicy {
    database_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback_anchor_root: Option<PathBuf>,
    signer_seed_path: PathBuf,
    trusted_signer_public_key: String,
    capability_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
}

/// Typed input for the demo provisioner. Policy serialization remains owned by
/// this module so provisioning cannot drift from the launch-time decoder.
/// The grants a provisioned launch may hold: the operator ceilings of its
/// policy, which the signed manifest's permissions must stay within.
#[derive(Clone, Debug, Default)]
pub(super) struct ProvisionedCeilings {
    pub(super) read_paths: BTreeSet<PathBuf>,
    pub(super) write_paths: BTreeSet<PathBuf>,
    pub(super) runtime_files: BTreeSet<PathBuf>,
}

#[allow(dead_code)]
pub(super) struct ProvisionedCagePolicyInput {
    pub(super) max_artifact_bytes: u64,
    pub(super) receipt_rollback_anchor_root: Option<PathBuf>,
    pub(super) signed_manifest: chio_manifest::SignedManifest,
    pub(super) registered_public_key: chio_core::PublicKey,
    pub(super) policy_signer_public_key: chio_core::PublicKey,
    pub(super) stage: chio_security_types::EnterpriseMigrationStage,
    pub(super) ceilings: ProvisionedCeilings,
    pub(super) broker: Option<ProvisionedBrokerBinding>,
    pub(super) receipt_capability_id: String,
    pub(super) receipt_tenant_id: Option<String>,
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
/// launch. The stage comes from the provisioning profile: Disabled authorizes
/// a legacy launch without claiming containment (the demo), Enforced binds
/// the launch to the cage.
#[allow(dead_code)]
pub(super) struct ProvisionedCagePolicyFactory {
    input: ProvisionedCagePolicyInput,
    migration_key: chio_security_types::EnterpriseMigrationKey,
}

#[allow(dead_code)]
impl ProvisionedCagePolicyFactory {
    pub(super) fn new(input: ProvisionedCagePolicyInput) -> Result<Self, CliError> {
        if !(1..=256 * 1024 * 1024).contains(&input.max_artifact_bytes) {
            return Err(CliError::cli_other_error(
                "provisioned cage artifact ceiling must be in 1..268435456".to_string(),
            ));
        }
        input.execution_identity.validate().map_err(|error| {
            CliError::cli_other_error(format!("demo cage execution identity is invalid: {error}"))
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
        let expected_profile = if let Some(broker) = &input.broker {
            broker.validate()?;
            if input.stage != chio_security_types::EnterpriseMigrationStage::Enforced
                || !input.ceilings.read_paths.is_empty()
                || !input.ceilings.write_paths.is_empty()
                || !input.ceilings.runtime_files.is_empty()
            {
                return Err(CliError::cli_other_error(
                    "brokered provisioning requires Enforced stage without file or runtime-file grants".to_string(),
                ));
            }
            chio_manifest::NativeSyscallProfile::BrokeredNativeV1
        } else {
            chio_manifest::NativeSyscallProfile::NativeMinimalV1
        };
        if permissions.native_syscall_profile != expected_profile
            || permissions.network_destinations.is_some()
            || permissions.environment_variables.is_some()
        {
            return Err(CliError::cli_other_error(
                "provisioned native MCP manifest must match its closed launch profile without network or environment grants"
                    .to_string(),
            ));
        }
        let declared_read = declared_paths(permissions.read_paths.as_deref());
        let declared_write = declared_paths(permissions.write_paths.as_deref());
        if declared_read != input.ceilings.read_paths
            || declared_write != input.ceilings.write_paths
        {
            return Err(CliError::cli_other_error(
                "provisioned native MCP manifest grants must equal the policy's operator ceilings"
                    .to_string(),
            ));
        }
        if !input.ceilings.runtime_files.is_subset(&declared_read) {
            return Err(CliError::cli_other_error(
                "provisioned runtime files must be declared read paths of the manifest".to_string(),
            ));
        }
        if !input.cage_init_path.is_absolute()
            || !input.target_path.is_absolute()
            || !input.working_directory.is_absolute()
            || !input.migration_database_path.is_absolute()
            || !input.receipt_database_path.is_absolute()
            || !input.receipt_signer_seed_path.is_absolute()
            || input.target_argv.first().map(String::as_str) != input.target_path.to_str()
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
        let placeholder_minimum_head = chio_security_types::EnterpriseMigrationMinimumHead {
            key: self.migration_key.clone(),
            minimum_generation: self.input.stage.generation(),
            transition_digest: chio_security_types::ports::Digest32::new([1_u8; 32]),
        };
        let policy = self.policy(placeholder_minimum_head)?;
        cage_launch_contract_digests(&policy, &self.input.policy_signer_public_key)
    }

    pub(super) fn signed_policy_bytes(
        &self,
        minimum_head: chio_security_types::EnterpriseMigrationMinimumHead,
        signer: &chio_core::Keypair,
    ) -> Result<Vec<u8>, CliError> {
        if signer.public_key() != self.input.policy_signer_public_key {
            return Err(CliError::cli_other_error(
                "cage policy signer does not match the committed policy trust root".to_string(),
            ));
        }
        let body = self.policy(minimum_head)?;
        let (signature, _) = signer.sign_canonical(&body).map_err(|error| {
            CliError::cli_other_error(format!("failed to sign cage policy: {error}"))
        })?;
        chio_core::canonical_json_bytes(&SignedMcpCageLaunchPolicy {
            body,
            signer_public_key: signer.public_key(),
            signature,
        })
        .map_err(|error| {
            CliError::cli_other_error(format!("failed to encode cage policy: {error}"))
        })
    }

    fn policy(
        &self,
        minimum_head: chio_security_types::EnterpriseMigrationMinimumHead,
    ) -> Result<McpCageLaunchPolicy, CliError> {
        if minimum_head.key != self.migration_key
            || minimum_head.minimum_generation != self.input.stage.generation()
            || minimum_head.transition_digest.is_zero()
        {
            return Err(CliError::cli_other_error(format!(
                "cage migration head must bind the exact {:?} generation-{} ledger",
                self.input.stage,
                self.input.stage.generation()
            )));
        }
        Ok(McpCageLaunchPolicy {
            schema: MCP_CAGE_LAUNCH_POLICY_SCHEMA.to_string(),
            signed_manifest: self.input.signed_manifest.clone(),
            registered_public_key: self.input.registered_public_key.clone(),
            operator_ceilings: CageOperatorCeilings {
                read_paths: self.input.ceilings.read_paths.clone(),
                write_paths: self.input.ceilings.write_paths.clone(),
                network_destinations: BTreeSet::new(),
                environment_variables: BTreeSet::new(),
                native_syscall_profiles: [if self.input.broker.is_some() {
                    chio_manifest::NativeSyscallProfile::BrokeredNativeV1
                } else {
                    chio_manifest::NativeSyscallProfile::NativeMinimalV1
                }]
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
                runtime_files: self.input.ceilings.runtime_files.clone(),
                target_argv: self.input.target_argv.clone(),
                execution_identity: self.input.execution_identity.clone(),
            },
            limits: CageLimitPolicy {
                max_artifact_bytes: self.input.max_artifact_bytes,
                launch_timeout_ms: 10_000,
                nofile_soft: 192,
                nofile_hard: 192,
            },
            receipt: CageReceiptRuntimePolicy {
                database_path: self.input.receipt_database_path.clone(),
                rollback_anchor_root: self.input.receipt_rollback_anchor_root.clone(),
                signer_seed_path: self.input.receipt_signer_seed_path.clone(),
                trusted_signer_public_key: self.input.receipt_signer_public_key.to_hex(),
                capability_id: self.input.receipt_capability_id.clone(),
                tenant_id: self.input.receipt_tenant_id.clone(),
            },
            enterprise_migration: CageMigrationPolicy {
                state_database_path: self.input.migration_database_path.clone(),
                deployment_id: self.input.deployment_id.clone(),
                stage: self.input.stage,
                trusted_transition_signers: vec![self.input.migration_signer_public_key.clone()],
                minimum_head,
            },
            broker: self
                .input
                .broker
                .as_ref()
                .map(ProvisionedBrokerBinding::policy_binding),
        })
    }
}

#[allow(dead_code)]
fn declared_paths(paths: Option<&[String]>) -> BTreeSet<PathBuf> {
    paths
        .unwrap_or_default()
        .iter()
        .map(PathBuf::from)
        .collect()
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
            "cage migration trust roots must be nonempty, bounded, sorted, and unique".to_string(),
        ));
    }
    let tool_server_id =
        chio_security_types::ports::RecordId::new(server_id.to_string()).map_err(|error| {
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
    let trusted_policy_signer =
        chio_core::PublicKey::from_hex(trusted_policy_signer).map_err(|error| {
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
    if policy.enterprise_migration.stage != chio_security_types::EnterpriseMigrationStage::Disabled
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
    let _authorization =
        compose_legacy_authorized_launch(validation_policy, command, args, &launch_contract, None)?;
    Ok(())
}

/// Validate a provisioned policy at an enforcing stage without composing
/// the launch: the signature, the bound server, the stage, the launch
/// contract and the migration ledger it names. Composing the launch retains
/// the cage helper and the target on the enforcing host, which is the
/// edge's and the preflight's job.
#[allow(dead_code)]
pub(super) fn validate_provisioned_policy(
    path: &Path,
    trusted_policy_signer: &chio_core::PublicKey,
    command: &str,
    args: &[&str],
    expected_server_id: &str,
    expected_stage: chio_security_types::EnterpriseMigrationStage,
    physical_migration_database_path: &Path,
) -> Result<(), CliError> {
    let bytes = read_cage_policy(path)?;
    let policy = decode_cage_policy(path, &bytes, trusted_policy_signer)?;
    if policy.enterprise_migration.stage != expected_stage
        || policy.signed_manifest.manifest.server_id != expected_server_id
    {
        return Err(CliError::cli_other_error(format!(
            "provisioned policy must bind the exact server at {expected_stage:?} stage"
        )));
    }
    let expected_argv = std::iter::once(command.to_string())
        .chain(args.iter().map(|argument| (*argument).to_string()))
        .collect::<Vec<_>>();
    if policy.runtime.target_path != Path::new(command)
        || policy.runtime.target_argv != expected_argv
    {
        return Err(CliError::cli_other_error(
            "provisioned policy target path and argv must exactly match the provisioned command"
                .to_string(),
        ));
    }
    let launch_contract = cage_launch_contract_digests(&policy, trusted_policy_signer)?;
    let mut migration = policy.enterprise_migration;
    migration.state_database_path = physical_migration_database_path.to_path_buf();
    let binding = load_cage_migration_enforcer(
        &migration,
        &policy.signed_manifest.manifest.server_id,
        &launch_contract,
    )?;
    if !expected_stage.legacy_fallback_permitted() {
        binding.require_enforced().map_err(|error| {
            CliError::cli_other_error(format!(
                "provisioned migration ledger does not enforce the launch: {error}"
            ))
        })?;
    }
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
    if policy
        .enterprise_migration
        .stage
        .legacy_fallback_permitted()
    {
        compose_legacy_authorized_launch(
            policy,
            command,
            args,
            &launch_contract,
            admitted_manifest_registry,
        )
        .map(|authorization| {
            chio_mcp_adapter::transport::NativeMcpLaunch::LegacyAuthorized(Box::new(authorization))
        })
    } else {
        compose_cage_required_launch(
            policy,
            &chio_core::sha256_hex(bytes),
            command,
            args,
            &launch_contract,
            admitted_manifest_registry,
        )
        .map(|launch| chio_mcp_adapter::transport::NativeMcpLaunch::CageRequired(Box::new(launch)))
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
    policy
        .body
        .runtime
        .execution_identity
        .validate()
        .map_err(|error| {
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
            let admitted_envelope = chio_core::canonical_json_bytes(admitted).map_err(|error| {
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
    registry
        .authorize_cage_manifest(server_id)
        .map_err(|error| {
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
            "legacy native launch requires a strict signed cage policy and v2 manifest".to_string(),
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
    let migration =
        load_cage_migration_enforcer(&policy.enterprise_migration, &server_id, launch_contract)?;
    chio_mcp_adapter::transport::LegacyNativeLaunchAuthorization::new(
        server_id, migration, registry,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "legacy native launch migration authorization denied: {error}"
        ))
    })
}

fn compose_cage_required_launch(
    policy: McpCageLaunchPolicy,
    admitted_policy_digest: &str,
    command: &str,
    args: &[&str],
    launch_contract: &chio_security_types::CageLaunchContractDigests,
    admitted_manifest_registry: Option<Arc<chio_manifest::VerifiedManifestRegistry>>,
) -> Result<chio_mcp_adapter::transport::CageRequiredLaunch, CliError> {
    compose_cage_required_launch_with_prepared_broker(
        policy,
        admitted_policy_digest,
        command,
        args,
        launch_contract,
        admitted_manifest_registry,
        None,
    )
}

fn compose_cage_required_launch_with_prepared_broker(
    policy: McpCageLaunchPolicy,
    admitted_policy_digest: &str,
    command: &str,
    args: &[&str],
    launch_contract: &chio_security_types::CageLaunchContractDigests,
    admitted_manifest_registry: Option<Arc<chio_manifest::VerifiedManifestRegistry>>,
    prepared_broker: Option<std::fs::File>,
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
    if prepared_broker.is_some() && !declared_brokered {
        return Err(CliError::cli_other_error(
            "prepared broker descriptor requires the brokered native profile".to_string(),
        ));
    }
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
    let migration =
        load_cage_migration_enforcer(&policy.enterprise_migration, &server_id, launch_contract)?;
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

    let broker = match prepared_broker {
        Some(file) => {
            #[cfg(target_os = "linux")]
            {
                let binding = policy.broker.ok_or_else(|| {
                    CliError::cli_other_error(
                        "prepared broker policy binding is absent".to_string(),
                    )
                })?;
                Some(retain_prepared_policy_broker(
                    binding,
                    std::os::unix::net::UnixStream::from(std::os::fd::OwnedFd::from(file)),
                )?)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = file;
                return Err(CliError::cli_other_error(
                    "prepared broker cage launch is unsupported on this platform".to_string(),
                ));
            }
        }
        None => policy.broker.map(retain_policy_broker).transpose()?,
    };
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
        admitted_policy_digest,
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
    admitted_policy_digest: &str,
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
    let anchor = policy.rollback_anchor_root.as_ref().ok_or_else(|| {
        CliError::cli_other_error(
            "Enforced cage receipt storage requires a signed receipt rollback anchor on a separate filesystem snapshot domain".to_string(),
        )
    })?;
    if !anchor.is_absolute() {
        return Err(CliError::cli_other_error(
            "cage receipt rollback anchor must be absolute".to_string(),
        ));
    }
    // Reuse the existing independently anchored sink qualification. Opening an
    // ordinary SQLite store must never substitute for its rollback authority.
    let receipt_store: Arc<dyn chio_kernel::ReceiptStore> = Arc::new(
        chio_store_sqlite::SqliteReceiptStore::open_for_finding_pool(&policy.database_path, anchor)
            .map_err(|error| {
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
    .and_then(|context| context.with_admitted_policy_digest(admitted_policy_digest))
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

#[cfg(target_os = "linux")]
fn retain_prepared_policy_broker(
    binding: CageBrokerBinding,
    stream: std::os::unix::net::UnixStream,
) -> Result<chio_cage::BrokerIpc, CliError> {
    let endpoint = binding.socket_path.as_ref().ok_or_else(|| {
        CliError::cli_other_error("prepared broker requires a signed socket endpoint".to_string())
    })?;
    ProvisionedBrokerBinding {
        socket_path: endpoint.clone(),
        authentication_digest: binding.authentication_digest.clone(),
        expected_peer_identity: binding.expected_peer_identity,
    }
    .validate()?;
    if binding.inherited_fd.is_some()
        || stream
            .peer_addr()
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "prepared broker peer address is unavailable: {error}"
                ))
            })?
            .as_pathname()
            != Some(endpoint.as_path())
    {
        return Err(CliError::cli_other_error(
            "prepared broker descriptor does not match the signed socket endpoint".to_string(),
        ));
    }
    chio_cage::retain_broker_ipc(
        std::fs::File::from(std::os::fd::OwnedFd::from(stream)),
        binding.authentication_digest,
        binding.expected_peer_identity,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("prepared broker FD authentication denied: {error}"))
    })
}

#[cfg(test)]
#[path = "cage_policy/tests.rs"]
mod tests;
