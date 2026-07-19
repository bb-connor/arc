#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_core::{Keypair, PublicKey, Signature};
use chio_manifest::{NativeSyscallProfile, RequiredPermissions, SignedManifest, ToolManifest};
use chio_security_types::ports::{Digest32, RecordId};
use chio_security_types::{
    CageLaunchContractDigests, EnterpriseMigrationControl, EnterpriseMigrationKey,
    EnterpriseMigrationMinimumHead, EnterpriseMigrationScopeKind, EnterpriseMigrationStage,
    EnterpriseMigrationStateStore, EnterpriseMigrationTransitionBody,
};
use serde::Serialize;
use serde_json::{json, Value};

const CAGE_POLICY_SCHEMA: &str = "chio.mcp.cage-launch-policy.v2";
const MCP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

struct DiscoveryChild {
    child: Child,
}

impl Drop for DiscoveryChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NativeMcpSecurityMaterial {
    pub(crate) signed_manifest_path: PathBuf,
    pub(crate) manifest_public_key: String,
    pub(crate) cage_policy_path: PathBuf,
    pub(crate) cage_policy_signer: String,
    pub(crate) target_command: PathBuf,
    pub(crate) target_args: Vec<String>,
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

#[allow(dead_code)]
pub(crate) fn resolve_executable(name: &str) -> PathBuf {
    let candidate = Path::new(name);
    if candidate.components().count() > 1 {
        return fs::canonicalize(candidate).expect("canonicalize executable path");
    }

    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
        .and_then(|path| fs::canonicalize(path).ok())
        .unwrap_or_else(|| panic!("could not resolve executable `{name}` from PATH"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn materialize_mcp_security(
    output_dir: &Path,
    chio_executable: &Path,
    target_command: &Path,
    target_args: &[String],
    working_directory: &Path,
    server_id: &str,
    server_name: &str,
    server_version: &str,
) -> NativeMcpSecurityMaterial {
    fs::create_dir_all(output_dir).expect("create MCP security directory");
    #[cfg(unix)]
    fs::set_permissions(
        output_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("restrict MCP security directory permissions");
    let output_dir = fs::canonicalize(output_dir).expect("canonicalize MCP security directory");
    let chio_executable = fs::canonicalize(chio_executable).expect("canonicalize Chio executable");
    let target_command =
        fs::canonicalize(target_command).expect("canonicalize MCP target executable");
    let working_directory =
        fs::canonicalize(working_directory).expect("canonicalize MCP working directory");

    let manifest_signer = Keypair::generate();
    let discovered_tools = discover_tools(&target_command, target_args, &working_directory);
    let mut manifest = chio_mcp_adapter::generate_manifest(
        &chio_mcp_adapter::adapter::McpAdapterConfig {
            server_id: server_id.to_string(),
            server_name: server_name.to_string(),
            server_version: server_version.to_string(),
            public_key: manifest_signer.public_key().to_hex(),
        },
        discovered_tools,
    )
    .expect("project MCP manifest surface");
    manifest.required_permissions = Some(RequiredPermissions {
        read_paths: None,
        write_paths: None,
        network_destinations: None,
        environment_variables: None,
        native_syscall_profile: NativeSyscallProfile::NativeMinimalV1,
    });
    chio_manifest::validate_manifest(&manifest).expect("validate signed MCP fixture manifest");

    materialize_policy(
        &output_dir,
        &chio_executable,
        &target_command,
        target_args,
        &working_directory,
        manifest,
        manifest_signer,
    )
}

fn discover_tools(
    target_command: &Path,
    target_args: &[String],
    working_directory: &Path,
) -> Vec<chio_mcp_adapter::edge::McpToolInfo> {
    let mut child = Command::new(target_command)
        .args(target_args)
        .current_dir(working_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn MCP fixture for signed surface discovery");
    let mut stdin = child.stdin.take().expect("capture MCP discovery stdin");
    let stdout = child.stdout.take().expect("capture MCP discovery stdout");
    let _child = DiscoveryChild { child };

    write_json_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "chio-test-provisioner", "version": "0.1.0" }
            }
        }),
    );
    write_json_line(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
    write_json_line(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} }),
    );
    drop(stdin);

    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let result = read_discovery_response(BufReader::new(stdout));
        let _ = sender.send(result);
    });
    let response = receiver
        .recv_timeout(MCP_DISCOVERY_TIMEOUT)
        .unwrap_or_else(|error| panic!("MCP signed surface discovery timed out: {error}"))
        .unwrap_or_else(|error| panic!("MCP signed surface discovery failed: {error}"));
    reader
        .join()
        .unwrap_or_else(|_| panic!("MCP signed surface discovery reader panicked"));

    serde_json::from_value(
        response
            .get("result")
            .and_then(|result| result.get("tools"))
            .cloned()
            .expect("MCP discovery response tools"),
    )
    .expect("decode MCP discovery tools")
}

fn write_json_line(stdin: &mut impl Write, value: &Value) {
    writeln!(
        stdin,
        "{}",
        serde_json::to_string(value).expect("encode MCP discovery request")
    )
    .expect("write MCP discovery request");
    stdin.flush().expect("flush MCP discovery request");
}

fn read_discovery_response(mut stdout: impl BufRead) -> Result<Value, String> {
    let mut line = String::new();
    let mut initialized = false;
    loop {
        line.clear();
        let bytes = stdout
            .read_line(&mut line)
            .map_err(|error| format!("read response: {error}"))?;
        if bytes == 0 {
            return Err("fixture exited before tools/list completed".to_string());
        }
        let value: Value = serde_json::from_str(line.trim())
            .map_err(|error| format!("decode response: {error}"))?;
        match value.get("id").and_then(Value::as_u64) {
            Some(1) => initialized = true,
            Some(2) if initialized => return Ok(value),
            Some(2) => {
                return Err("tools/list completed before initialize".to_string());
            }
            _ => {}
        }
    }
}

fn materialize_policy(
    output_dir: &Path,
    chio_executable: &Path,
    target_command: &Path,
    target_args: &[String],
    working_directory: &Path,
    manifest: ToolManifest,
    manifest_signer: Keypair,
) -> NativeMcpSecurityMaterial {
    let signed_manifest =
        chio_manifest::sign_manifest(&manifest, &manifest_signer).expect("sign MCP manifest");
    let signed_manifest_bytes =
        chio_core::canonical_json_bytes(&signed_manifest).expect("encode signed MCP manifest");
    let signed_manifest_path = output_dir.join("signed-manifest.json");
    write_private_file(&signed_manifest_path, &signed_manifest_bytes);

    let receipt_signer = Keypair::generate();
    let receipt_seed_path = output_dir.join("cage-receipt.seed");
    chio_control_plane::persist_authority_keypair(&receipt_seed_path, &receipt_signer)
        .expect("persist cage receipt signer");

    let deployment_id = RecordId::new(format!("chio.fixture.{}", manifest.server_id))
        .expect("fixture deployment id");
    let tool_server_id = RecordId::new(manifest.server_id.clone()).expect("fixture server id");
    let migration_database_path = output_dir.join("enterprise-migration.sqlite3");
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
    let target_path_text = target_command
        .to_str()
        .expect("MCP target path is UTF-8")
        .to_string();
    let runtime = RuntimePolicy {
        cage_init_path: chio_executable.to_path_buf(),
        cage_init_binding_digest: chio_core::sha256_hex(
            &fs::read(chio_executable).expect("read Chio executable"),
        ),
        target_path: target_command.to_path_buf(),
        target_binding_digest: chio_core::sha256_hex(
            &fs::read(target_command).expect("read MCP target executable"),
        ),
        working_directory: working_directory.to_path_buf(),
        runtime_files: BTreeSet::new(),
        target_argv: std::iter::once(target_path_text)
            .chain(target_args.iter().cloned())
            .collect(),
    };
    let limits = LimitPolicy {
        max_artifact_bytes: 1024 * 1024,
        launch_timeout_ms: 10_000,
        nofile_soft: 192,
        nofile_hard: 192,
    };
    let receipt = ReceiptPolicy {
        database_path: output_dir.join("cage-receipts.sqlite3"),
        signer_seed_path: receipt_seed_path,
        trusted_signer_public_key: receipt_signer.public_key().to_hex(),
        capability_id: format!("{}-cage-launch", manifest.server_id),
        tenant_id: "fixture-local".to_string(),
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
    );

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
    .expect("encode cage migration posture");
    let transition_body = EnterpriseMigrationTransitionBody::genesis(
        migration_key.clone(),
        posture_digest,
        digest(&signed_manifest_bytes),
        component_digest(&launch_contract),
        launch_contract.runtime_digest,
        current_unix_ms(),
        migration_signer.public_key().to_hex(),
    )
    .expect("build cage migration genesis");
    let transition =
        chio_store_sqlite::sign_enterprise_migration_transition(transition_body, &migration_signer)
            .expect("sign cage migration genesis");
    let open_policy = chio_store_sqlite::SqliteEnterpriseMigrationOpenPolicy::new(
        trusted_transition_signers.clone(),
        Vec::new(),
    )
    .expect("configure cage migration ledger");
    let store = chio_store_sqlite::SqliteEnterpriseMigrationStateStore::open(
        &migration_database_path,
        open_policy,
    )
    .expect("open cage migration ledger");
    let _ = store
        .register(&transition)
        .expect("register cage migration genesis");
    let minimum_head = store
        .load(&migration_key)
        .expect("load cage migration genesis")
        .expect("cage migration genesis retained")
        .minimum_head();
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
            minimum_head,
        },
    };
    let (signature, _) = policy_signer
        .sign_canonical(&policy_body)
        .expect("sign cage launch policy");
    let signed_policy = SignedCagePolicy {
        body: policy_body,
        signer_public_key: policy_signer.public_key(),
        signature,
    };
    let signed_policy_bytes =
        chio_core::canonical_json_bytes(&signed_policy).expect("encode cage launch policy");
    let cage_policy_path = output_dir.join("cage-launch-policy.json");
    write_private_file(&cage_policy_path, &signed_policy_bytes);

    NativeMcpSecurityMaterial {
        signed_manifest_path,
        manifest_public_key: manifest_signer.public_key().to_hex(),
        cage_policy_path,
        cage_policy_signer: policy_signer.public_key().to_hex(),
        target_command: target_command.to_path_buf(),
        target_args: target_args.to_vec(),
    }
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
) -> CageLaunchContractDigests {
    CageLaunchContractDigests {
        policy_schema_digest: component_digest(&CAGE_POLICY_SCHEMA),
        policy_signer_digest: component_digest(policy_signer),
        signed_manifest_digest: component_digest(signed_manifest),
        registered_public_key_digest: component_digest(registered_public_key),
        operator_ceilings_digest: component_digest(operator_ceilings),
        runtime_digest: component_digest(runtime),
        limits_digest: component_digest(limits),
        receipt_digest: component_digest(receipt),
        broker_binding_digest: component_digest(&Option::<()>::None),
        migration_ledger_digest: component_digest(migration_ledger),
    }
}

fn component_digest<T: Serialize>(value: &T) -> Digest32 {
    let bytes = chio_core::canonical_json_bytes(value).expect("encode cage launch contract");
    digest(&bytes)
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

fn current_unix_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_millis();
    u64::try_from(millis).expect("system clock fits u64 milliseconds")
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).expect("create private security file");
    file.write_all(bytes).expect("write private security file");
    file.sync_all().expect("sync private security file");
}
