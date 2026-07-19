use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::{Keypair, PublicKey, Signature};
use chio_manifest::{
    NativeSyscallProfile, RequiredPermissions, SignedManifest, ToolAnnotations, ToolDefinition,
    ToolManifest, TOOL_MANIFEST_SCHEMA,
};
use chio_security_types::ports::{Digest32, RecordId};
use chio_security_types::{
    CageLaunchContractDigests, EnterpriseMigrationControl, EnterpriseMigrationKey,
    EnterpriseMigrationMinimumHead, EnterpriseMigrationScopeKind, EnterpriseMigrationStage,
    EnterpriseMigrationStateStore, EnterpriseMigrationTransitionBody,
};
use serde::Serialize;

use crate::runner::{ConformanceRunOptions, RunnerError};

const SERVER_ID: &str = "conformance-mcp-core";
const SERVER_NAME: &str = "Conformance Fixture";
const SERVER_VERSION: &str = "0.1.0";
const CAGE_POLICY_SCHEMA: &str = "chio.mcp.cage-launch-policy.v2";

pub(crate) struct RemoteEdgeSecurityMaterial {
    pub(crate) signed_manifest_path: PathBuf,
    pub(crate) manifest_public_key: String,
    pub(crate) cage_policy_path: PathBuf,
    pub(crate) cage_policy_signer: String,
    pub(crate) python_executable: PathBuf,
    pub(crate) upstream_server_script: PathBuf,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SignedCagePolicy {
    body: CagePolicy,
    signer_public_key: PublicKey,
    signature: Signature,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CagePolicy {
    schema: String,
    signed_manifest: SignedManifest,
    registered_public_key: PublicKey,
    operator_ceilings: OperatorCeilings,
    runtime: RuntimePolicy,
    limits: LimitPolicy,
    receipt: ReceiptPolicy,
    enterprise_migration: MigrationPolicy,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct MigrationPolicy {
    state_database_path: PathBuf,
    deployment_id: RecordId,
    stage: EnterpriseMigrationStage,
    trusted_transition_signers: Vec<PublicKey>,
    minimum_head: EnterpriseMigrationMinimumHead,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct OperatorCeilings {
    read_paths: BTreeSet<PathBuf>,
    write_paths: BTreeSet<PathBuf>,
    network_destinations: BTreeSet<chio_manifest::NetworkDestination>,
    environment_variables: BTreeSet<chio_manifest::EnvironmentVariableName>,
    native_syscall_profiles: BTreeSet<NativeSyscallProfile>,
    forbidden_paths: BTreeSet<PathBuf>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimePolicy {
    cage_init_path: PathBuf,
    cage_init_binding_digest: String,
    target_path: PathBuf,
    target_binding_digest: String,
    working_directory: PathBuf,
    runtime_files: BTreeSet<PathBuf>,
    target_argv: Vec<String>,
    execution_identity: chio_cage::ExecutionIdentity,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct LimitPolicy {
    max_artifact_bytes: u64,
    launch_timeout_ms: u64,
    nofile_soft: u64,
    nofile_hard: u64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptPolicy {
    database_path: PathBuf,
    signer_seed_path: PathBuf,
    trusted_signer_public_key: String,
    capability_id: String,
    tenant_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MigrationLedgerDigest<'a> {
    state_database_path: &'a Path,
    deployment_id: &'a RecordId,
    trusted_transition_signers: &'a [PublicKey],
}

pub(crate) fn materialize_remote_edge_security(
    chio_executable: &Path,
    options: &ConformanceRunOptions,
    artifacts_dir: &Path,
) -> Result<RemoteEdgeSecurityMaterial, RunnerError> {
    let security_dir = artifacts_dir.join("security");
    fs::create_dir_all(&security_dir)?;
    let security_dir = fs::canonicalize(security_dir)?;
    let python_executable = resolve_python_executable(&options.python_binary)?;
    let upstream_server_script = fs::canonicalize(&options.upstream_server_script)?;
    let working_directory = fs::canonicalize(&options.repo_root)?;
    let chio_executable = fs::canonicalize(chio_executable)?;

    let manifest_signer = Keypair::generate();
    let manifest = conformance_manifest(&manifest_signer.public_key());
    let signed_manifest = chio_manifest::sign_manifest(&manifest, &manifest_signer)
        .map_err(|error| security_error(format!("sign fixture manifest: {error}")))?;
    let signed_manifest_bytes = chio_core::canonical_json_bytes(&signed_manifest)
        .map_err(|error| security_error(format!("encode fixture manifest: {error}")))?;
    let signed_manifest_path = security_dir.join("signed-manifest.json");
    write_private_file(&signed_manifest_path, &signed_manifest_bytes)?;

    let python_bytes = fs::read(&python_executable)?;
    let chio_bytes = fs::read(&chio_executable)?;
    let receipt_seed = *chio_core::sha256(b"chio.conformance.cage-receipt-signer.v1").as_bytes();
    let receipt_signer = Keypair::from_seed(&receipt_seed);
    let receipt_seed_path = security_dir.join("cage-receipt.seed");
    write_private_file(&receipt_seed_path, &receipt_seed)?;

    let deployment_id = record_id("conformance.mcp-core", "deployment")?;
    let tool_server_id = record_id(SERVER_ID, "tool server")?;
    let migration_database_path = security_dir.join("enterprise-migration.sqlite3");
    let migration_signer = Keypair::generate();
    let trusted_transition_signers = vec![migration_signer.public_key()];
    let policy_signer = Keypair::generate();
    let registered_public_key = manifest_signer.public_key();
    let operator_ceilings = OperatorCeilings {
        read_paths: BTreeSet::new(),
        write_paths: BTreeSet::new(),
        network_destinations: BTreeSet::new(),
        environment_variables: BTreeSet::new(),
        native_syscall_profiles: [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
        forbidden_paths: BTreeSet::new(),
    };
    let target_path_string = path_text(&python_executable, "Python executable")?;
    let script_path_string = path_text(&upstream_server_script, "upstream fixture")?;
    let runtime = RuntimePolicy {
        cage_init_path: chio_executable,
        cage_init_binding_digest: chio_core::sha256_hex(&chio_bytes),
        target_path: python_executable.clone(),
        target_binding_digest: chio_core::sha256_hex(&python_bytes),
        working_directory,
        runtime_files: BTreeSet::new(),
        target_argv: vec![target_path_string, script_path_string],
        execution_identity: chio_cage::ExecutionIdentity::new(10_001, 10_001, Vec::new()).map_err(
            |error| security_error(format!("build fixture execution identity: {error}")),
        )?,
    };
    let limits = LimitPolicy {
        max_artifact_bytes: 1024 * 1024,
        launch_timeout_ms: 10_000,
        nofile_soft: 192,
        nofile_hard: 192,
    };
    let receipt = ReceiptPolicy {
        database_path: security_dir.join("cage-receipts.sqlite3"),
        signer_seed_path: receipt_seed_path,
        trusted_signer_public_key: receipt_signer.public_key().to_hex(),
        capability_id: "conformance-mcp-core-launch".to_string(),
        tenant_id: "conformance-local".to_string(),
    };
    let launch_contract = cage_launch_contract_digests(
        &policy_signer.public_key(),
        &signed_manifest,
        &registered_public_key,
        &operator_ceilings,
        &runtime,
        &limits,
        &receipt,
        &MigrationLedgerDigest {
            state_database_path: &migration_database_path,
            deployment_id: &deployment_id,
            trusted_transition_signers: &trusted_transition_signers,
        },
    )?;
    let migration_key = EnterpriseMigrationKey {
        deployment_id: deployment_id.clone(),
        scope_kind: EnterpriseMigrationScopeKind::ToolServer,
        scope_id: tool_server_id.clone(),
        control: EnterpriseMigrationControl::CageEnforcement,
    };
    let posture_digest = chio_security_types::cage_migration_posture_digest(
        &deployment_id,
        &tool_server_id,
        EnterpriseMigrationStage::Disabled,
        &launch_contract,
    )
    .map_err(|error| security_error(format!("encode cage migration posture: {error}")))?;
    let trusted_at_unix_ms = current_unix_ms()?;
    let transition_body = EnterpriseMigrationTransitionBody::genesis(
        migration_key.clone(),
        posture_digest,
        digest(&signed_manifest_bytes),
        component_digest(&launch_contract)?,
        launch_contract.runtime_digest,
        trusted_at_unix_ms,
        migration_signer.public_key().to_hex(),
    )
    .map_err(|error| security_error(format!("build cage migration genesis: {error}")))?;
    let transition =
        chio_store_sqlite::sign_enterprise_migration_transition(transition_body, &migration_signer)
            .map_err(|error| security_error(format!("sign cage migration genesis: {error}")))?;
    let open_policy = chio_store_sqlite::SqliteEnterpriseMigrationOpenPolicy::new(
        trusted_transition_signers.clone(),
        Vec::new(),
    )
    .map_err(|error| security_error(format!("configure cage migration ledger: {error}")))?;
    let store = chio_store_sqlite::SqliteEnterpriseMigrationStateStore::open(
        &migration_database_path,
        open_policy,
    )
    .map_err(|error| security_error(format!("open cage migration ledger: {error}")))?;
    let _ = store
        .register(&transition)
        .map_err(|error| security_error(format!("register cage migration genesis: {error}")))?;
    let migration_state = store
        .load(&migration_key)
        .map_err(|error| security_error(format!("load cage migration genesis: {error}")))?
        .ok_or_else(|| security_error("cage migration genesis was not retained"))?;
    drop(store);

    let policy_body = CagePolicy {
        schema: CAGE_POLICY_SCHEMA.to_string(),
        signed_manifest: signed_manifest.clone(),
        registered_public_key,
        operator_ceilings,
        runtime,
        limits,
        receipt,
        enterprise_migration: MigrationPolicy {
            state_database_path: migration_database_path,
            deployment_id,
            stage: EnterpriseMigrationStage::Disabled,
            trusted_transition_signers,
            minimum_head: migration_state.minimum_head(),
        },
    };
    let (signature, _) = policy_signer
        .sign_canonical(&policy_body)
        .map_err(|error| security_error(format!("sign cage launch policy: {error}")))?;
    let signed_policy = SignedCagePolicy {
        body: policy_body,
        signer_public_key: policy_signer.public_key(),
        signature,
    };
    let signed_policy_bytes = chio_core::canonical_json_bytes(&signed_policy)
        .map_err(|error| security_error(format!("encode cage launch policy: {error}")))?;
    let cage_policy_path = security_dir.join("cage-launch-policy.json");
    write_private_file(&cage_policy_path, &signed_policy_bytes)?;

    Ok(RemoteEdgeSecurityMaterial {
        signed_manifest_path,
        manifest_public_key: manifest_signer.public_key().to_hex(),
        cage_policy_path,
        cage_policy_signer: policy_signer.public_key().to_hex(),
        python_executable,
        upstream_server_script,
    })
}

fn conformance_manifest(public_key: &PublicKey) -> ToolManifest {
    let tools = [
        (
            "echo_text",
            "Echo Text",
            "Return a simple text response",
            "message",
        ),
        (
            "slow_echo",
            "Slow Echo",
            "Sleep before returning a simple text response",
            "message",
        ),
        (
            "emit_fixture_notifications",
            "Emit Fixture Notifications",
            "Emit resource and catalog change notifications before returning",
            "uri",
        ),
        (
            "sampled_echo",
            "Sampled Echo",
            "Use sampling/createMessage before returning",
            "message",
        ),
        (
            "elicited_echo",
            "Elicited Echo",
            "Use form-mode elicitation/create before returning",
            "message",
        ),
        (
            "url_elicited_echo",
            "URL Elicited Echo",
            "Use URL-mode elicitation/create and completion notification before returning",
            "message",
        ),
        (
            "roots_echo",
            "Roots Echo",
            "Use roots/list before returning",
            "message",
        ),
    ]
    .into_iter()
    .map(|(name, title, description, property)| ToolDefinition {
        name: name.to_string(),
        description: format!("{title}\n\n{description}"),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                property: { "type": "string" }
            }
        }),
        output_schema: None,
        pricing: None,
        annotations: ToolAnnotations {
            read_only: true,
            destructive: false,
            idempotent: false,
            requires_approval: false,
        },
        latency_hint: None,
        flow: None,
    })
    .collect();

    ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: SERVER_ID.to_string(),
        name: SERVER_NAME.to_string(),
        description: Some("MCP server adapted to Chio protocol".to_string()),
        version: SERVER_VERSION.to_string(),
        tools,
        server_tools: Vec::new(),
        required_permissions: Some(RequiredPermissions {
            read_paths: None,
            write_paths: None,
            network_destinations: None,
            environment_variables: None,
            native_syscall_profile: NativeSyscallProfile::NativeMinimalV1,
        }),
        public_key: public_key.to_hex(),
    }
}

fn resolve_python_executable(binary: &OsStr) -> Result<PathBuf, RunnerError> {
    let output = Command::new(binary)
        .arg("-c")
        .arg("import os,sys; print(os.path.realpath(sys.executable))")
        .output()
        .map_err(|source| RunnerError::Spawn {
            command: format!("{} resolve executable", PathBuf::from(binary).display()),
            source,
        })?;
    if !output.status.success() {
        return Err(RunnerError::ProcessFailed {
            command: format!("{} resolve executable", PathBuf::from(binary).display()),
            status: output.status.code().unwrap_or(1),
            log_path: "<stderr>".to_string(),
        });
    }
    let path = std::str::from_utf8(&output.stdout)
        .map_err(|error| security_error(format!("Python executable path is not UTF-8: {error}")))?
        .trim();
    if path.is_empty() {
        return Err(security_error("Python did not report its executable path"));
    }
    Ok(fs::canonicalize(path)?)
}

fn component_digest<T: Serialize>(value: &T) -> Result<Digest32, RunnerError> {
    let bytes = chio_core::canonical_json_bytes(value)
        .map_err(|error| security_error(format!("encode cage launch contract: {error}")))?;
    Ok(digest(&bytes))
}

#[allow(clippy::too_many_arguments)]
fn cage_launch_contract_digests(
    policy_signer: &PublicKey,
    signed_manifest: &SignedManifest,
    registered_public_key: &PublicKey,
    operator_ceilings: &OperatorCeilings,
    runtime: &RuntimePolicy,
    limits: &LimitPolicy,
    receipt: &ReceiptPolicy,
    migration_ledger: &MigrationLedgerDigest<'_>,
) -> Result<CageLaunchContractDigests, RunnerError> {
    Ok(CageLaunchContractDigests {
        policy_schema_digest: component_digest(&CAGE_POLICY_SCHEMA)?,
        policy_signer_digest: component_digest(policy_signer)?,
        signed_manifest_digest: component_digest(signed_manifest)?,
        registered_public_key_digest: component_digest(registered_public_key)?,
        operator_ceilings_digest: component_digest(operator_ceilings)?,
        runtime_digest: component_digest(runtime)?,
        limits_digest: component_digest(limits)?,
        receipt_digest: component_digest(receipt)?,
        broker_binding_digest: component_digest(&Option::<()>::None)?,
        migration_ledger_digest: component_digest(migration_ledger)?,
    })
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

fn current_unix_ms() -> Result<u64, RunnerError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| security_error(format!("system clock precedes Unix epoch: {error}")))?
        .as_millis();
    u64::try_from(millis)
        .map_err(|_| security_error("system clock does not fit the migration timestamp"))
}

fn record_id(value: &str, label: &str) -> Result<RecordId, RunnerError> {
    RecordId::new(value.to_string())
        .map_err(|error| security_error(format!("invalid {label} identifier: {error}")))
}

fn path_text(path: &Path, label: &str) -> Result<String, RunnerError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| security_error(format!("{label} path is not UTF-8")))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), RunnerError> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn security_error(message: impl Into<String>) -> RunnerError {
    RunnerError::SecurityMaterial(message.into())
}
