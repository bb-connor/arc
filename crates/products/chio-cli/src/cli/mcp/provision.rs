use super::*;

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_security_types::EnterpriseMigrationStateStore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::cage_policy::{
    NativeMcpDemoCagePolicyFactory, NativeMcpDemoCagePolicyInput,
};

const REPORT_SCHEMA: &str = "chio.native-mcp-demo-provision-report.v1";
const SECURITY_MODE: &str = "disabled_legacy_authorized_demo";
const SECURITY_WARNING: &str =
    "Disabled is legacy-authorized demo mode, not cage containment.";
const MAX_TOOLS_FIXTURE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_JSON_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_MIGRATION_DATABASE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 1024 * 1024 * 1024;

const REVIEWED_TOOLS_FILE: &str = "reviewed-tools.json";
const SIGNED_MANIFEST_FILE: &str = "signed-manifest.json";
const MANIFEST_SEED_FILE: &str = "manifest-signer.seed";
const MANIFEST_PUBLIC_KEY_FILE: &str = "manifest-public-key";
const CAGE_POLICY_FILE: &str = "cage-launch-policy.json";
const CAGE_POLICY_SEED_FILE: &str = "cage-policy-signer.seed";
const CAGE_POLICY_PUBLIC_KEY_FILE: &str = "cage-policy-signer";
const MIGRATION_SEED_FILE: &str = "cage-migration-signer.seed";
const MIGRATION_PUBLIC_KEY_FILE: &str = "cage-migration-public-key";
const MIGRATION_GENESIS_FILE: &str = "cage-migration-genesis.json";
const MIGRATION_DATABASE_FILE: &str = "enterprise-migration.sqlite3";
const MIGRATION_DATABASE_WAL_FILE: &str = "enterprise-migration.sqlite3-wal";
const MIGRATION_DATABASE_SHM_FILE: &str = "enterprise-migration.sqlite3-shm";
const RECEIPT_SEED_FILE: &str = "cage-receipt-signer.seed";
const RECEIPT_PUBLIC_KEY_FILE: &str = "cage-receipt-public-key";
const RECEIPT_DATABASE_FILE: &str = "cage-receipts.sqlite3";
const CONTROL_AUTHORITY_SEED_FILE: &str = "control-authority.seed";
const CONTROL_AUTHORITY_PUBLIC_KEY_FILE: &str = "control-authority-public-key";
const TARGET_COMMAND_FILE: &str = "target-command";
const REPORT_FILE: &str = "provision-report.json";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeMcpDemoProvisionReport {
    schema: String,
    security_mode: String,
    containment_enforced: bool,
    warning: String,
    private_signers_are_demo_only: bool,
    created_at_unix_ms: u64,
    output_directory: PathBuf,
    runtime_security_directory: PathBuf,
    server_id: String,
    server_name: String,
    server_version: String,
    reviewed_tools_digest: String,
    reviewed_tool_count: usize,
    target_path: PathBuf,
    target_argv: Vec<String>,
    target_binding_digest: String,
    working_directory: PathBuf,
    execution_identity: chio_cage::ExecutionIdentity,
    chio_executable_path: PathBuf,
    chio_executable_digest: String,
    signed_manifest_digest: String,
    cage_policy_digest: String,
    migration_transition_digest: String,
    migration_stage: chio_security_types::EnterpriseMigrationStage,
    migration_generation: u64,
    manifest_public_key: String,
    cage_policy_public_key: String,
    migration_public_key: String,
    receipt_public_key: String,
    control_authority_public_key: String,
    artifacts: NativeMcpDemoArtifactPaths,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeMcpDemoArtifactPaths {
    reviewed_tools: PathBuf,
    signed_manifest: PathBuf,
    manifest_signer_seed: PathBuf,
    manifest_public_key: PathBuf,
    cage_policy: PathBuf,
    cage_policy_signer_seed: PathBuf,
    cage_policy_public_key: PathBuf,
    migration_signer_seed: PathBuf,
    migration_public_key: PathBuf,
    migration_genesis: PathBuf,
    migration_database: PathBuf,
    receipt_signer_seed: PathBuf,
    receipt_public_key: PathBuf,
    control_authority_seed: PathBuf,
    control_authority_public_key: PathBuf,
    target_command: PathBuf,
    report: PathBuf,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewedTools<'a> {
    tools: &'a [chio_mcp_adapter::edge::McpToolInfo],
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ReviewedToolsInput {
    Wrapped(ReviewedToolsObject),
    Bare(Vec<ReviewedMcpTool>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedToolsObject {
    tools: Vec<ReviewedMcpTool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewedMcpTool {
    name: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    input_schema: serde_json::Value,
    #[serde(default, rename = "outputSchema")]
    output_schema: Option<serde_json::Value>,
    #[serde(default)]
    annotations: Option<serde_json::Value>,
    #[serde(default)]
    execution: Option<serde_json::Value>,
}

impl From<ReviewedMcpTool> for chio_mcp_adapter::edge::McpToolInfo {
    fn from(value: ReviewedMcpTool) -> Self {
        Self {
            name: value.name,
            title: value.title,
            description: value.description,
            input_schema: value.input_schema,
            output_schema: value.output_schema,
            annotations: value.annotations,
            execution: value.execution,
        }
    }
}

struct ProvisionInputs {
    output_directory: PathBuf,
    runtime_security_directory: PathBuf,
    tools: Vec<chio_mcp_adapter::edge::McpToolInfo>,
    reviewed_tools_bytes: Vec<u8>,
    target_path: PathBuf,
    target_argv: Vec<String>,
    target_binding_digest: String,
    working_directory: PathBuf,
    execution_identity: chio_cage::ExecutionIdentity,
    chio_executable_path: PathBuf,
    chio_executable_digest: String,
    server_id: String,
    server_name: String,
    server_version: String,
}

struct ProvisionSigners {
    manifest: chio_core::Keypair,
    policy: chio_core::Keypair,
    migration: chio_core::Keypair,
    receipt: chio_core::Keypair,
    control_authority: chio_core::Keypair,
}

struct StagingDirectory {
    path: Option<PathBuf>,
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if let Some(path) = self.path.as_ref() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_provision_native_mcp_demo(
    output_dir: &Path,
    runtime_security_dir: Option<&Path>,
    tools_fixture: &Path,
    target: &Path,
    target_args: &[String],
    working_directory: Option<&Path>,
    execution_uid: u32,
    execution_gid: u32,
    execution_supplementary_gids: &[u32],
    server_id: &str,
    server_name: &str,
    server_version: &str,
) -> Result<(), CliError> {
    let inputs = resolve_inputs(
        output_dir,
        runtime_security_dir,
        tools_fixture,
        target,
        target_args,
        working_directory,
        execution_uid,
        execution_gid,
        execution_supplementary_gids,
        server_id,
        server_name,
        server_version,
    )?;

    match std::fs::symlink_metadata(&inputs.output_directory) {
        Ok(_) => {
            let report = validate_existing_provision(&inputs)?;
            return write_report_to_stdout(&report);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(CliError::cli_io_error(format!(
                "failed to inspect native MCP demo output {}: {error}",
                inputs.output_directory.display()
            )));
        }
    }

    provision_new(&inputs)
}

#[allow(clippy::too_many_arguments)]
fn resolve_inputs(
    output_dir: &Path,
    runtime_security_dir: Option<&Path>,
    tools_fixture: &Path,
    target: &Path,
    target_args: &[String],
    working_directory: Option<&Path>,
    execution_uid: u32,
    execution_gid: u32,
    execution_supplementary_gids: &[u32],
    server_id: &str,
    server_name: &str,
    server_version: &str,
) -> Result<ProvisionInputs, CliError> {
    validate_text_argument("server id", server_id, 256)?;
    validate_text_argument("server name", server_name, 512)?;
    validate_text_argument("server version", server_version, 128)?;
    if target_args.len() > 256
        || target_args
            .iter()
            .any(|argument| argument.len() > 16 * 1024 || argument.chars().any(char::is_control))
    {
        return Err(CliError::cli_other_error(
            "native MCP demo target argv is too large or contains control characters".to_string(),
        ));
    }

    let output_directory = require_exact_absolute_output_path(output_dir)?;
    let runtime_security_directory = match runtime_security_dir {
        Some(path) => require_exact_absolute_logical_directory(
            path,
            "native MCP demo runtime security directory",
        )?,
        None => output_directory.clone(),
    };
    let target_path = require_exact_canonical_path(target, "target executable")?;
    let target_binding_digest = hash_executable(&target_path, "target executable")?;
    let execution_identity = chio_cage::ExecutionIdentity::new(
        execution_uid,
        execution_gid,
        execution_supplementary_gids.to_vec(),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("invalid native MCP execution identity: {error}"))
    })?;
    let chio_executable = std::env::current_exe().map_err(|error| {
        CliError::cli_io_error(format!("failed to resolve the current Chio executable: {error}"))
    })?;
    let chio_executable_path = require_exact_canonical_path(
        &chio_executable
            .canonicalize()
            .map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to canonicalize the current Chio executable: {error}"
                ))
            })?,
        "current Chio executable",
    )?;
    let chio_executable_digest =
        hash_executable(&chio_executable_path, "current Chio executable")?;
    let working_directory = match working_directory {
        Some(path) => require_exact_canonical_directory(path, "working directory")?,
        None => target_path
            .parent()
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "target executable has no canonical parent directory".to_string(),
                )
            })?
            .to_path_buf(),
    };
    let target_path_text = target_path.to_str().ok_or_else(|| {
        CliError::cli_other_error("target executable path is not valid UTF-8".to_string())
    })?;
    let target_argv = std::iter::once(target_path_text.to_string())
        .chain(target_args.iter().cloned())
        .collect::<Vec<_>>();

    let tools_fixture = require_exact_canonical_path(tools_fixture, "tools fixture")?;
    let fixture_bytes = read_bounded_regular_file(
        &tools_fixture,
        MAX_TOOLS_FIXTURE_BYTES,
        false,
        "tools fixture",
    )?;
    let tools = decode_tools_fixture(&fixture_bytes, &tools_fixture)?;
    let reviewed_tools_bytes =
        chio_core::canonical_json_bytes(&ReviewedTools { tools: &tools }).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to encode the reviewed native MCP tool surface: {error}"
            ))
        })?;

    Ok(ProvisionInputs {
        output_directory,
        runtime_security_directory,
        tools,
        reviewed_tools_bytes,
        target_path,
        target_argv,
        target_binding_digest,
        working_directory,
        execution_identity,
        chio_executable_path,
        chio_executable_digest,
        server_id: server_id.to_string(),
        server_name: server_name.to_string(),
        server_version: server_version.to_string(),
    })
}

fn provision_new(inputs: &ProvisionInputs) -> Result<(), CliError> {
    let parent = inputs.output_directory.parent().ok_or_else(|| {
        CliError::cli_other_error("native MCP demo output has no parent directory".to_string())
    })?;
    let leaf = inputs
        .output_directory
        .file_name()
        .ok_or_else(|| {
            CliError::cli_other_error("native MCP demo output has no directory name".to_string())
        })?
        .to_string_lossy();
    let staging_path = parent.join(format!(
        ".{leaf}.chio-provision-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&staging_path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create native MCP demo staging directory {}: {error}",
            staging_path.display()
        ))
    })?;
    set_private_directory_permissions(&staging_path)?;
    let mut staging = StagingDirectory {
        path: Some(staging_path.clone()),
    };

    let signers = ProvisionSigners {
        manifest: chio_core::Keypair::generate(),
        policy: chio_core::Keypair::generate(),
        migration: chio_core::Keypair::generate(),
        receipt: chio_core::Keypair::generate(),
        control_authority: chio_core::Keypair::generate(),
    };
    persist_signers(&staging_path, &signers)?;
    write_public_keys(&staging_path, &signers)?;
    write_private_file(
        &staging_path.join(REVIEWED_TOOLS_FILE),
        &inputs.reviewed_tools_bytes,
        "reviewed tools",
    )?;
    write_private_file(
        &staging_path.join(TARGET_COMMAND_FILE),
        &chio_core::canonical_json_bytes(&inputs.target_argv).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to encode canonical target command argv: {error}"
            ))
        })?,
        "target command",
    )?;

    let signed_manifest = build_signed_manifest(inputs, &signers.manifest)?;
    let signed_manifest_bytes =
        chio_core::canonical_json_bytes(&signed_manifest).map_err(|error| {
            CliError::cli_other_error(format!("failed to encode signed demo manifest: {error}"))
        })?;
    write_private_file(
        &staging_path.join(SIGNED_MANIFEST_FILE),
        &signed_manifest_bytes,
        "signed manifest",
    )?;

    let deployment_id = demo_deployment_id(&inputs.server_id)?;
    let factory = build_policy_factory(inputs, signed_manifest, &signers, deployment_id.clone())?;
    let launch_contract = factory.launch_contract()?;
    let created_at_unix_ms = current_unix_ms()?;
    let migration_key = migration_key(&deployment_id, &inputs.server_id)?;
    let posture_digest = chio_security_types::cage_migration_posture_digest(
        &deployment_id,
        &migration_key.scope_id,
        chio_security_types::EnterpriseMigrationStage::Disabled,
        &launch_contract,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("failed to encode demo migration posture: {error}"))
    })?;
    let transition_body = chio_security_types::EnterpriseMigrationTransitionBody::genesis(
        migration_key.clone(),
        posture_digest,
        digest32(&signed_manifest_bytes),
        canonical_digest32(&launch_contract, "demo launch contract")?,
        launch_contract.runtime_digest,
        created_at_unix_ms,
        signers.migration.public_key().to_hex(),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("failed to build demo migration genesis: {error}"))
    })?;
    let transition = chio_store_sqlite::sign_enterprise_migration_transition(
        transition_body,
        &signers.migration,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("failed to sign demo migration genesis: {error}"))
    })?;
    let transition_bytes = chio_core::canonical_json_bytes(&transition).map_err(|error| {
        CliError::cli_other_error(format!("failed to encode demo migration genesis: {error}"))
    })?;
    write_private_file(
        &staging_path.join(MIGRATION_GENESIS_FILE),
        &transition_bytes,
        "migration genesis",
    )?;

    let migration_database_path = staging_path.join(MIGRATION_DATABASE_FILE);
    let store = chio_store_sqlite::SqliteEnterpriseMigrationStateStore::open(
        &migration_database_path,
        chio_store_sqlite::SqliteEnterpriseMigrationOpenPolicy::new(
            vec![signers.migration.public_key()],
            Vec::new(),
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("invalid demo migration open policy: {error}"))
        })?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("failed to create demo migration ledger: {error}"))
    })?;
    let _ = store.register(&transition).map_err(|error| {
        CliError::cli_other_error(format!("failed to append demo migration genesis: {error}"))
    })?;
    let migration_state = store
        .load(&migration_key)
        .map_err(|error| {
            CliError::cli_other_error(format!("failed to load demo migration genesis: {error}"))
        })?
        .ok_or_else(|| {
            CliError::cli_other_error("demo migration genesis was not retained".to_string())
        })?;
    let minimum_head = migration_state.minimum_head();
    drop(store);
    set_private_file_permissions(&migration_database_path)?;
    secure_existing_migration_sidecars(&migration_database_path)?;

    let cage_policy_bytes = factory.signed_policy_bytes(minimum_head, &signers.policy)?;
    write_private_file(
        &staging_path.join(CAGE_POLICY_FILE),
        &cage_policy_bytes,
        "cage policy",
    )?;

    let transition_digest = chio_store_sqlite::enterprise_migration_transition_digest(&transition)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to digest demo migration genesis: {error}"
            ))
        })?;
    let report = build_report(
        inputs,
        &signers,
        created_at_unix_ms,
        &signed_manifest_bytes,
        &cage_policy_bytes,
        transition_digest,
    );
    let report_bytes = chio_core::canonical_json_bytes(&report).map_err(|error| {
        CliError::cli_other_error(format!("failed to encode demo provision report: {error}"))
    })?;
    write_private_file(
        &staging_path.join(REPORT_FILE),
        &report_bytes,
        "provision report",
    )?;
    sync_directory(&staging_path)?;

    std::fs::rename(&staging_path, &inputs.output_directory).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to publish native MCP demo output {}: {error}",
            inputs.output_directory.display()
        ))
    })?;
    staging.path = None;
    sync_directory(parent)?;

    match validate_existing_provision(inputs) {
        Ok(validated) => write_report_to_stdout(&validated),
        Err(error) => {
            let _ = std::fs::remove_dir_all(&inputs.output_directory);
            Err(error)
        }
    }
}

fn validate_existing_provision(
    inputs: &ProvisionInputs,
) -> Result<NativeMcpDemoProvisionReport, CliError> {
    validate_private_directory(&inputs.output_directory)?;
    validate_exact_artifact_set(&inputs.output_directory)?;
    let report_bytes = read_bounded_regular_file(
        &inputs.output_directory.join(REPORT_FILE),
        MAX_JSON_ARTIFACT_BYTES,
        true,
        "provision report",
    )?;
    let report: NativeMcpDemoProvisionReport = serde_json::from_slice(&report_bytes).map_err(
        |error| CliError::cli_other_error(format!("invalid demo provision report: {error}")),
    )?;
    require_canonical_json(&report, &report_bytes, "demo provision report")?;
    let now = current_unix_ms()?;
    if report.created_at_unix_ms == 0 || report.created_at_unix_ms > now {
        return Err(CliError::cli_other_error(
            "demo provision report contains an invalid creation time".to_string(),
        ));
    }

    let reviewed_tools_bytes = read_bounded_regular_file(
        &inputs.output_directory.join(REVIEWED_TOOLS_FILE),
        MAX_JSON_ARTIFACT_BYTES,
        true,
        "reviewed tools",
    )?;
    if reviewed_tools_bytes != inputs.reviewed_tools_bytes {
        return Err(tampered("reviewed tools do not match the requested fixture"));
    }

    let signers = load_existing_signers(&inputs.output_directory)?;
    validate_public_key_files(&inputs.output_directory, &signers)?;
    let target_command = read_bounded_regular_file(
        &inputs.output_directory.join(TARGET_COMMAND_FILE),
        16 * 1024,
        true,
        "target command",
    )?;
    let expected_target_command = chio_core::canonical_json_bytes(&inputs.target_argv).map_err(
        |error| {
            CliError::cli_other_error(format!(
                "failed to encode expected target command argv: {error}"
            ))
        },
    )?;
    if target_command != expected_target_command {
        return Err(tampered(
            "target command argv does not match the requested executable and arguments",
        ));
    }

    let signed_manifest = build_signed_manifest(inputs, &signers.manifest)?;
    let expected_manifest_bytes =
        chio_core::canonical_json_bytes(&signed_manifest).map_err(|error| {
            CliError::cli_other_error(format!("failed to encode expected demo manifest: {error}"))
        })?;
    let signed_manifest_bytes = read_bounded_regular_file(
        &inputs.output_directory.join(SIGNED_MANIFEST_FILE),
        MAX_JSON_ARTIFACT_BYTES,
        true,
        "signed manifest",
    )?;
    if signed_manifest_bytes != expected_manifest_bytes {
        return Err(tampered("signed manifest does not match the reviewed tool surface"));
    }

    let deployment_id = demo_deployment_id(&inputs.server_id)?;
    let migration_key = migration_key(&deployment_id, &inputs.server_id)?;
    let genesis_bytes = read_bounded_regular_file(
        &inputs.output_directory.join(MIGRATION_GENESIS_FILE),
        MAX_JSON_ARTIFACT_BYTES,
        true,
        "migration genesis",
    )?;
    let transition: chio_security_types::EnterpriseMigrationTransition =
        serde_json::from_slice(&genesis_bytes).map_err(|error| {
            CliError::cli_other_error(format!("invalid demo migration genesis: {error}"))
        })?;
    require_canonical_json(&transition, &genesis_bytes, "demo migration genesis")?;
    let transition_digest = chio_store_sqlite::enterprise_migration_transition_digest(&transition)
        .map_err(|error| tampered(&format!("migration genesis signature is invalid: {error}")))?;

    let migration_database_path = inputs.output_directory.join(MIGRATION_DATABASE_FILE);
    validate_private_regular_file(
        &migration_database_path,
        MAX_MIGRATION_DATABASE_BYTES,
        "migration database",
    )?;
    let store = chio_store_sqlite::SqliteEnterpriseMigrationStateStore::open(
        &migration_database_path,
        chio_store_sqlite::SqliteEnterpriseMigrationOpenPolicy::new(
            vec![signers.migration.public_key()],
            Vec::new(),
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("invalid demo migration open policy: {error}"))
        })?,
    )
    .map_err(|error| tampered(&format!("migration ledger verification failed: {error}")))?;
    let state = store
        .load(&migration_key)
        .map_err(|error| tampered(&format!("migration ledger load failed: {error}")))?
        .ok_or_else(|| tampered("migration ledger has no exact demo genesis"))?;
    if state.stage != chio_security_types::EnterpriseMigrationStage::Disabled
        || state.generation != 0
        || state.transition_digest != transition_digest
    {
        return Err(tampered(
            "migration ledger is not at the exact Disabled generation-zero genesis",
        ));
    }
    let minimum_head = state.minimum_head();
    drop(store);
    secure_existing_migration_sidecars(&migration_database_path)?;

    let factory = build_policy_factory(inputs, signed_manifest, &signers, deployment_id.clone())?;
    let launch_contract = factory.launch_contract()?;
    let posture_digest = chio_security_types::cage_migration_posture_digest(
        &deployment_id,
        &migration_key.scope_id,
        chio_security_types::EnterpriseMigrationStage::Disabled,
        &launch_contract,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("failed to encode expected migration posture: {error}"))
    })?;
    let expected_transition_body =
        chio_security_types::EnterpriseMigrationTransitionBody::genesis(
            migration_key,
            posture_digest,
            digest32(&signed_manifest_bytes),
            canonical_digest32(&launch_contract, "demo launch contract")?,
            launch_contract.runtime_digest,
            report.created_at_unix_ms,
            signers.migration.public_key().to_hex(),
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("failed to rebuild demo migration genesis: {error}"))
        })?;
    let expected_transition = chio_store_sqlite::sign_enterprise_migration_transition(
        expected_transition_body,
        &signers.migration,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("failed to rebuild signed migration genesis: {error}"))
    })?;
    let expected_transition_bytes = chio_core::canonical_json_bytes(&expected_transition)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to encode expected migration genesis: {error}"
            ))
        })?;
    if genesis_bytes != expected_transition_bytes {
        return Err(tampered(
            "migration genesis does not match the exact signed launch contract",
        ));
    }

    let expected_policy_bytes = factory.signed_policy_bytes(minimum_head, &signers.policy)?;
    let cage_policy_bytes = read_bounded_regular_file(
        &inputs.output_directory.join(CAGE_POLICY_FILE),
        MAX_JSON_ARTIFACT_BYTES,
        true,
        "cage policy",
    )?;
    if cage_policy_bytes != expected_policy_bytes {
        return Err(tampered("cage policy does not match the exact demo launch contract"));
    }
    let target_args = inputs
        .target_argv
        .iter()
        .skip(1)
        .map(String::as_str)
        .collect::<Vec<_>>();
    super::cage_policy::validate_native_mcp_demo_policy(
        &inputs.output_directory.join(CAGE_POLICY_FILE),
        &signers.policy.public_key(),
        path_utf8(&inputs.target_path, "target executable")?,
        &target_args,
        &inputs.server_id,
        &migration_database_path,
    )?;

    let expected_report = build_report(
        inputs,
        &signers,
        report.created_at_unix_ms,
        &signed_manifest_bytes,
        &cage_policy_bytes,
        transition_digest,
    );
    if report != expected_report {
        return Err(tampered("provision report does not match the verified artifacts"));
    }
    validate_exact_artifact_set(&inputs.output_directory)?;
    Ok(report)
}

fn build_signed_manifest(
    inputs: &ProvisionInputs,
    signer: &chio_core::Keypair,
) -> Result<chio_manifest::SignedManifest, CliError> {
    let config = chio_mcp_adapter::adapter::McpAdapterConfig {
        server_id: inputs.server_id.clone(),
        server_name: inputs.server_name.clone(),
        server_version: inputs.server_version.clone(),
        public_key: signer.public_key().to_hex(),
    };
    let mut manifest = chio_mcp_adapter::generate_manifest(&config, inputs.tools.clone())
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "reviewed native MCP tools cannot form a strict manifest: {error}"
            ))
        })?;
    manifest.required_permissions = Some(chio_manifest::RequiredPermissions {
        read_paths: None,
        write_paths: None,
        network_destinations: None,
        environment_variables: None,
        native_syscall_profile: chio_manifest::NativeSyscallProfile::NativeMinimalV1,
    });
    chio_manifest::sign_manifest(&manifest, signer).map_err(|error| {
        CliError::cli_other_error(format!("failed to sign strict demo manifest: {error}"))
    })
}

fn build_policy_factory(
    inputs: &ProvisionInputs,
    signed_manifest: chio_manifest::SignedManifest,
    signers: &ProvisionSigners,
    deployment_id: chio_security_types::ports::RecordId,
) -> Result<NativeMcpDemoCagePolicyFactory, CliError> {
    NativeMcpDemoCagePolicyFactory::new(NativeMcpDemoCagePolicyInput {
        signed_manifest,
        registered_public_key: signers.manifest.public_key(),
        policy_signer_public_key: signers.policy.public_key(),
        cage_init_path: inputs.chio_executable_path.clone(),
        cage_init_binding_digest: inputs.chio_executable_digest.clone(),
        target_path: inputs.target_path.clone(),
        target_binding_digest: inputs.target_binding_digest.clone(),
        working_directory: inputs.working_directory.clone(),
        target_argv: inputs.target_argv.clone(),
        execution_identity: inputs.execution_identity.clone(),
        migration_database_path: inputs
            .runtime_security_directory
            .join(MIGRATION_DATABASE_FILE),
        deployment_id,
        migration_signer_public_key: signers.migration.public_key(),
        receipt_database_path: inputs.runtime_security_directory.join(RECEIPT_DATABASE_FILE),
        receipt_signer_seed_path: inputs.runtime_security_directory.join(RECEIPT_SEED_FILE),
        receipt_signer_public_key: signers.receipt.public_key(),
    })
}

fn build_report(
    inputs: &ProvisionInputs,
    signers: &ProvisionSigners,
    created_at_unix_ms: u64,
    signed_manifest_bytes: &[u8],
    cage_policy_bytes: &[u8],
    migration_transition_digest: chio_security_types::ports::Digest32,
) -> NativeMcpDemoProvisionReport {
    NativeMcpDemoProvisionReport {
        schema: REPORT_SCHEMA.to_string(),
        security_mode: SECURITY_MODE.to_string(),
        containment_enforced: false,
        warning: SECURITY_WARNING.to_string(),
        private_signers_are_demo_only: true,
        created_at_unix_ms,
        output_directory: inputs.output_directory.clone(),
        runtime_security_directory: inputs.runtime_security_directory.clone(),
        server_id: inputs.server_id.clone(),
        server_name: inputs.server_name.clone(),
        server_version: inputs.server_version.clone(),
        reviewed_tools_digest: chio_core::sha256_hex(&inputs.reviewed_tools_bytes),
        reviewed_tool_count: inputs.tools.len(),
        target_path: inputs.target_path.clone(),
        target_argv: inputs.target_argv.clone(),
        target_binding_digest: inputs.target_binding_digest.clone(),
        working_directory: inputs.working_directory.clone(),
        execution_identity: inputs.execution_identity.clone(),
        chio_executable_path: inputs.chio_executable_path.clone(),
        chio_executable_digest: inputs.chio_executable_digest.clone(),
        signed_manifest_digest: chio_core::sha256_hex(signed_manifest_bytes),
        cage_policy_digest: chio_core::sha256_hex(cage_policy_bytes),
        migration_transition_digest: hex::encode(migration_transition_digest.as_bytes()),
        migration_stage: chio_security_types::EnterpriseMigrationStage::Disabled,
        migration_generation: 0,
        manifest_public_key: signers.manifest.public_key().to_hex(),
        cage_policy_public_key: signers.policy.public_key().to_hex(),
        migration_public_key: signers.migration.public_key().to_hex(),
        receipt_public_key: signers.receipt.public_key().to_hex(),
        control_authority_public_key: signers.control_authority.public_key().to_hex(),
        artifacts: artifact_paths(&inputs.output_directory),
    }
}

fn artifact_paths(directory: &Path) -> NativeMcpDemoArtifactPaths {
    NativeMcpDemoArtifactPaths {
        reviewed_tools: directory.join(REVIEWED_TOOLS_FILE),
        signed_manifest: directory.join(SIGNED_MANIFEST_FILE),
        manifest_signer_seed: directory.join(MANIFEST_SEED_FILE),
        manifest_public_key: directory.join(MANIFEST_PUBLIC_KEY_FILE),
        cage_policy: directory.join(CAGE_POLICY_FILE),
        cage_policy_signer_seed: directory.join(CAGE_POLICY_SEED_FILE),
        cage_policy_public_key: directory.join(CAGE_POLICY_PUBLIC_KEY_FILE),
        migration_signer_seed: directory.join(MIGRATION_SEED_FILE),
        migration_public_key: directory.join(MIGRATION_PUBLIC_KEY_FILE),
        migration_genesis: directory.join(MIGRATION_GENESIS_FILE),
        migration_database: directory.join(MIGRATION_DATABASE_FILE),
        receipt_signer_seed: directory.join(RECEIPT_SEED_FILE),
        receipt_public_key: directory.join(RECEIPT_PUBLIC_KEY_FILE),
        control_authority_seed: directory.join(CONTROL_AUTHORITY_SEED_FILE),
        control_authority_public_key: directory.join(CONTROL_AUTHORITY_PUBLIC_KEY_FILE),
        target_command: directory.join(TARGET_COMMAND_FILE),
        report: directory.join(REPORT_FILE),
    }
}

fn persist_signers(directory: &Path, signers: &ProvisionSigners) -> Result<(), CliError> {
    for (file_name, signer) in [
        (MANIFEST_SEED_FILE, &signers.manifest),
        (CAGE_POLICY_SEED_FILE, &signers.policy),
        (MIGRATION_SEED_FILE, &signers.migration),
        (RECEIPT_SEED_FILE, &signers.receipt),
        (CONTROL_AUTHORITY_SEED_FILE, &signers.control_authority),
    ] {
        chio_control_plane::persist_authority_keypair(&directory.join(file_name), signer)?;
    }
    Ok(())
}

fn load_existing_signers(directory: &Path) -> Result<ProvisionSigners, CliError> {
    Ok(ProvisionSigners {
        manifest: load_signer(directory, MANIFEST_SEED_FILE)?,
        policy: load_signer(directory, CAGE_POLICY_SEED_FILE)?,
        migration: load_signer(directory, MIGRATION_SEED_FILE)?,
        receipt: load_signer(directory, RECEIPT_SEED_FILE)?,
        control_authority: load_signer(directory, CONTROL_AUTHORITY_SEED_FILE)?,
    })
}

fn load_signer(directory: &Path, file_name: &str) -> Result<chio_core::Keypair, CliError> {
    validate_private_regular_file(&directory.join(file_name), 256, file_name)?;
    chio_control_plane::load_existing_authority_keypair(&directory.join(file_name)).map_err(
        |error| tampered(&format!("private signer {file_name} is invalid: {error}")),
    )
}

fn write_public_keys(directory: &Path, signers: &ProvisionSigners) -> Result<(), CliError> {
    for (file_name, key) in [
        (MANIFEST_PUBLIC_KEY_FILE, signers.manifest.public_key()),
        (CAGE_POLICY_PUBLIC_KEY_FILE, signers.policy.public_key()),
        (MIGRATION_PUBLIC_KEY_FILE, signers.migration.public_key()),
        (RECEIPT_PUBLIC_KEY_FILE, signers.receipt.public_key()),
        (
            CONTROL_AUTHORITY_PUBLIC_KEY_FILE,
            signers.control_authority.public_key(),
        ),
    ] {
        write_private_file(
            &directory.join(file_name),
            key.to_hex().as_bytes(),
            file_name,
        )?;
    }
    Ok(())
}

fn validate_public_key_files(
    directory: &Path,
    signers: &ProvisionSigners,
) -> Result<(), CliError> {
    for (file_name, expected) in [
        (MANIFEST_PUBLIC_KEY_FILE, signers.manifest.public_key()),
        (CAGE_POLICY_PUBLIC_KEY_FILE, signers.policy.public_key()),
        (MIGRATION_PUBLIC_KEY_FILE, signers.migration.public_key()),
        (RECEIPT_PUBLIC_KEY_FILE, signers.receipt.public_key()),
        (
            CONTROL_AUTHORITY_PUBLIC_KEY_FILE,
            signers.control_authority.public_key(),
        ),
    ] {
        let bytes = read_bounded_regular_file(
            &directory.join(file_name),
            128,
            true,
            file_name,
        )?;
        if bytes != expected.to_hex().as_bytes() {
            return Err(tampered(&format!(
                "public key file {file_name} does not match its private signer"
            )));
        }
    }
    Ok(())
}

fn decode_tools_fixture(
    bytes: &[u8],
    path: &Path,
) -> Result<Vec<chio_mcp_adapter::edge::McpToolInfo>, CliError> {
    let input: ReviewedToolsInput = serde_json::from_slice(bytes).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse reviewed tools fixture {}: {error}",
            path.display()
        ))
    })?;
    let tools = match input {
        ReviewedToolsInput::Wrapped(value) => value.tools,
        ReviewedToolsInput::Bare(value) => value,
    }
    .into_iter()
    .map(chio_mcp_adapter::edge::McpToolInfo::from)
    .collect::<Vec<_>>();
    if tools.is_empty() || tools.len() > 4096 {
        return Err(CliError::cli_other_error(
            "reviewed tools fixture must contain between 1 and 4096 tools".to_string(),
        ));
    }
    if tools.iter().any(|tool| tool.execution.is_some()) {
        return Err(CliError::cli_other_error(
            "reviewed tools fixture contains MCP execution metadata that the signed manifest cannot bind"
                .to_string(),
        ));
    }
    Ok(tools)
}

fn demo_deployment_id(
    server_id: &str,
) -> Result<chio_security_types::ports::RecordId, CliError> {
    chio_security_types::ports::RecordId::new(format!("chio.demo.{server_id}"))
        .map_err(|error| CliError::cli_other_error(format!("invalid demo deployment id: {error}")))
}

fn migration_key(
    deployment_id: &chio_security_types::ports::RecordId,
    server_id: &str,
) -> Result<chio_security_types::EnterpriseMigrationKey, CliError> {
    Ok(chio_security_types::EnterpriseMigrationKey {
        deployment_id: deployment_id.clone(),
        scope_kind: chio_security_types::EnterpriseMigrationScopeKind::ToolServer,
        scope_id: chio_security_types::ports::RecordId::new(server_id.to_string()).map_err(
            |error| CliError::cli_other_error(format!("invalid demo tool server id: {error}")),
        )?,
        control: chio_security_types::EnterpriseMigrationControl::CageEnforcement,
    })
}

fn canonical_digest32<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<chio_security_types::ports::Digest32, CliError> {
    let bytes = chio_core::canonical_json_bytes(value).map_err(|error| {
        CliError::cli_other_error(format!("failed to encode {label}: {error}"))
    })?;
    Ok(digest32(&bytes))
}

fn digest32(bytes: &[u8]) -> chio_security_types::ports::Digest32 {
    chio_security_types::ports::Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

fn current_unix_ms() -> Result<u64, CliError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            CliError::cli_other_error(format!("system clock precedes the Unix epoch: {error}"))
        })?
        .as_millis();
    u64::try_from(millis).map_err(|_| {
        CliError::cli_other_error("system clock does not fit Unix milliseconds".to_string())
    })
}

fn validate_text_argument(label: &str, value: &str, max_bytes: usize) -> Result<(), CliError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
    {
        Err(CliError::cli_other_error(format!(
            "native MCP demo {label} is blank, non-canonical, or too large"
        )))
    } else {
        Ok(())
    }
}

fn require_exact_absolute_output_path(path: &Path) -> Result<PathBuf, CliError> {
    if !path.is_absolute() {
        return Err(CliError::cli_other_error(
            "native MCP demo output directory must be an absolute path".to_string(),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        CliError::cli_other_error("native MCP demo output has no parent directory".to_string())
    })?;
    let canonical_parent = require_exact_canonical_directory(parent, "output parent")?;
    let leaf = path.file_name().ok_or_else(|| {
        CliError::cli_other_error("native MCP demo output has no directory name".to_string())
    })?;
    let canonical_output = canonical_parent.join(leaf);
    if canonical_output != path {
        return Err(CliError::cli_other_error(
            "native MCP demo output path must be absolute and canonical".to_string(),
        ));
    }
    Ok(canonical_output)
}

fn require_exact_absolute_logical_directory(
    path: &Path,
    label: &str,
) -> Result<PathBuf, CliError> {
    use std::path::Component;

    if !path.is_absolute() || path.file_name().is_none() {
        return Err(CliError::cli_other_error(format!(
            "{label} must be an exact absolute non-root path"
        )));
    }

    let mut exact = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                exact.push(component.as_os_str());
            }
            Component::CurDir | Component::ParentDir => {
                return Err(CliError::cli_other_error(format!(
                    "{label} must not contain dot segments"
                )));
            }
        }

        match std::fs::symlink_metadata(&exact) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(CliError::cli_other_error(format!(
                        "{label} must not contain symlink components"
                    )));
                }
                if exact != path && !metadata.is_dir() {
                    return Err(CliError::cli_other_error(format!(
                        "{label} has a non-directory path component"
                    )));
                }
                if exact == path && !metadata.is_dir() {
                    return Err(CliError::cli_other_error(format!(
                        "{label} must identify a directory or a not-yet-created directory"
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(CliError::cli_io_error(format!(
                    "failed to inspect {label} {}: {error}",
                    exact.display()
                )));
            }
        }
    }

    if exact.as_os_str() != path.as_os_str() {
        return Err(CliError::cli_other_error(format!(
            "{label} must not contain redundant separators or non-canonical components"
        )));
    }
    Ok(exact)
}

fn require_exact_canonical_path(path: &Path, label: &str) -> Result<PathBuf, CliError> {
    if !path.is_absolute() {
        return Err(CliError::cli_other_error(format!(
            "{label} must be an absolute canonical path"
        )));
    }
    let canonical = path.canonicalize().map_err(|error| {
        CliError::cli_io_error(format!("failed to canonicalize {label} {}: {error}", path.display()))
    })?;
    if canonical != path {
        return Err(CliError::cli_other_error(format!(
            "{label} must not contain symlinks, dot segments, or non-canonical components"
        )));
    }
    Ok(canonical)
}

fn require_exact_canonical_directory(path: &Path, label: &str) -> Result<PathBuf, CliError> {
    let canonical = require_exact_canonical_path(path, label)?;
    let metadata = std::fs::symlink_metadata(&canonical).map_err(|error| {
        CliError::cli_io_error(format!("failed to inspect {label} {}: {error}", canonical.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::cli_other_error(format!(
            "{label} must be a real directory"
        )));
    }
    Ok(canonical)
}

fn path_utf8<'a>(path: &'a Path, label: &str) -> Result<&'a str, CliError> {
    path.to_str()
        .ok_or_else(|| CliError::cli_other_error(format!("{label} path is not valid UTF-8")))
}

fn hash_executable(path: &Path, label: &str) -> Result<String, CliError> {
    let mut file = open_regular_file(path, false, label)?;
    let metadata = file.metadata().map_err(|error| {
        CliError::cli_io_error(format!("failed to inspect {label} {}: {error}", path.display()))
    })?;
    if metadata.len() == 0 || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(CliError::cli_other_error(format!(
            "{label} is empty or exceeds {MAX_EXECUTABLE_BYTES} bytes"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o111 == 0 {
            return Err(CliError::cli_other_error(format!(
                "{label} is not executable"
            )));
        }
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            CliError::cli_io_error(format!("failed to read {label} {}: {error}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_EXECUTABLE_BYTES {
            return Err(CliError::cli_other_error(format!(
                "{label} exceeds {MAX_EXECUTABLE_BYTES} bytes"
            )));
        }
        digest.update(&buffer[..read]);
    }
    if total != metadata.len() {
        return Err(CliError::cli_other_error(format!(
            "{label} changed while it was being hashed"
        )));
    }
    Ok(hex::encode(digest.finalize()))
}

fn read_bounded_regular_file(
    path: &Path,
    max_bytes: u64,
    require_private: bool,
    label: &str,
) -> Result<Vec<u8>, CliError> {
    let file = open_regular_file(path, require_private, label)?;
    let metadata = file.metadata().map_err(|error| {
        CliError::cli_io_error(format!("failed to inspect {label} {}: {error}", path.display()))
    })?;
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(CliError::cli_other_error(format!(
            "{label} is empty or exceeds {max_bytes} bytes"
        )));
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        CliError::cli_other_error(format!("{label} length does not fit memory bounds"))
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CliError::cli_io_error(format!("failed to read {label} {}: {error}", path.display()))
        })?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > max_bytes {
        return Err(CliError::cli_other_error(format!(
            "{label} changed while it was being read"
        )));
    }
    Ok(bytes)
}

fn open_regular_file(path: &Path, require_private: bool, label: &str) -> Result<File, CliError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|error| {
        CliError::cli_io_error(format!("failed to open {label} {}: {error}", path.display()))
    })?;
    let metadata = file.metadata().map_err(|error| {
        CliError::cli_io_error(format!("failed to inspect {label} {}: {error}", path.display()))
    })?;
    if !metadata.is_file() {
        return Err(CliError::cli_other_error(format!(
            "{label} must be a regular file"
        )));
    }
    #[cfg(unix)]
    if require_private {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600 {
            return Err(CliError::cli_other_error(format!(
                "{label} must be singly linked with mode 0600"
            )));
        }
    }
    Ok(file)
}

fn validate_private_regular_file(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<(), CliError> {
    let file = open_regular_file(path, true, label)?;
    let length = file
        .metadata()
        .map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect {label} {}: {error}",
                path.display()
            ))
        })?
        .len();
    if length == 0 || length > max_bytes {
        return Err(CliError::cli_other_error(format!(
            "{label} is empty or exceeds {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8], label: &str) -> Result<(), CliError> {
    if bytes.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "refusing to write empty {label}"
        )));
    }
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|error| {
        CliError::cli_io_error(format!("failed to create {label} {}: {error}", path.display()))
    })?;
    file.write_all(bytes).map_err(|error| {
        CliError::cli_io_error(format!("failed to write {label} {}: {error}", path.display()))
    })?;
    file.sync_all().map_err(|error| {
        CliError::cli_io_error(format!("failed to sync {label} {}: {error}", path.display()))
    })?;
    set_private_file_permissions(path)
}

fn set_private_file_permissions(path: &Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |error| {
                CliError::cli_io_error(format!(
                    "failed to set private permissions on {}: {error}",
                    path.display()
                ))
            },
        )?;
    }
    validate_private_regular_file(path, MAX_MIGRATION_DATABASE_BYTES, "provisioned artifact")
}

fn secure_existing_migration_sidecars(database_path: &Path) -> Result<(), CliError> {
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = database_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => set_private_file_permissions(&sidecar)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(CliError::cli_io_error(format!(
                    "failed to inspect migration database sidecar {}: {error}",
                    sidecar.display()
                )))
            }
        }
    }
    Ok(())
}

fn set_private_directory_permissions(path: &Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                CliError::cli_io_error(format!(
                    "failed to set private directory permissions on {}: {error}",
                    path.display()
                ))
            },
        )?;
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<(), CliError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to inspect demo output directory {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(tampered("demo output is not a real directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o777 != 0o700 {
            return Err(tampered("demo output directory mode is not 0700"));
        }
    }
    Ok(())
}

fn validate_exact_artifact_set(directory: &Path) -> Result<(), CliError> {
    let expected = [
        REVIEWED_TOOLS_FILE,
        SIGNED_MANIFEST_FILE,
        MANIFEST_SEED_FILE,
        MANIFEST_PUBLIC_KEY_FILE,
        CAGE_POLICY_FILE,
        CAGE_POLICY_SEED_FILE,
        CAGE_POLICY_PUBLIC_KEY_FILE,
        MIGRATION_SEED_FILE,
        MIGRATION_PUBLIC_KEY_FILE,
        MIGRATION_GENESIS_FILE,
        MIGRATION_DATABASE_FILE,
        RECEIPT_SEED_FILE,
        RECEIPT_PUBLIC_KEY_FILE,
        CONTROL_AUTHORITY_SEED_FILE,
        CONTROL_AUTHORITY_PUBLIC_KEY_FILE,
        TARGET_COMMAND_FILE,
        REPORT_FILE,
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect::<BTreeSet<_>>();
    let allowed = expected
        .iter()
        .cloned()
        .chain(
            [MIGRATION_DATABASE_WAL_FILE, MIGRATION_DATABASE_SHM_FILE]
                .into_iter()
                .map(std::ffi::OsString::from),
        )
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for entry in std::fs::read_dir(directory).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to list demo output directory {}: {error}",
            directory.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!("failed to inspect demo output entry: {error}"))
        })?;
        let name = entry.file_name();
        if !allowed.contains(&name) || !actual.insert(name) {
            return Err(tampered("demo output contains duplicate or unexpected artifacts"));
        }
    }
    if !expected.is_subset(&actual) {
        return Err(tampered("demo output is partial or contains unexpected artifacts"));
    }
    Ok(())
}

fn require_canonical_json<T: Serialize>(
    value: &T,
    bytes: &[u8],
    label: &str,
) -> Result<(), CliError> {
    let canonical = chio_core::canonical_json_bytes(value).map_err(|error| {
        CliError::cli_other_error(format!("failed to canonicalize {label}: {error}"))
    })?;
    if canonical != bytes {
        Err(tampered(&format!("{label} is not canonical JSON")))
    } else {
        Ok(())
    }
}

fn sync_directory(path: &Path) -> Result<(), CliError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            CliError::cli_io_error(format!("failed to sync directory {}: {error}", path.display()))
        })
}

fn write_report_to_stdout(report: &NativeMcpDemoProvisionReport) -> Result<(), CliError> {
    let bytes = chio_core::canonical_json_bytes(report).map_err(|error| {
        CliError::cli_other_error(format!("failed to encode demo provision report: {error}"))
    })?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(&bytes).map_err(|error| {
        CliError::cli_io_error(format!("failed to write demo provision report: {error}"))
    })?;
    lock.write_all(b"\n").map_err(|error| {
        CliError::cli_io_error(format!("failed to terminate demo provision report: {error}"))
    })
}

fn tampered(message: &str) -> CliError {
    CliError::cli_other_error(format!(
        "existing native MCP demo output is partial, tampered, or input-mismatched: {message}"
    ))
}
