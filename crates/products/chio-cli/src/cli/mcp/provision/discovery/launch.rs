use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use super::{CliError, ProvisionInputs};

pub(super) enum DiscoveryChild {
    Enforced(Box<chio_cage::EnforcedChild>),
    Legacy(Child),
}

impl Drop for DiscoveryChild {
    fn drop(&mut self) {
        match self {
            Self::Enforced(child) => {
                let _ = child.signal(chio_cage::TerminationSignal::Terminate);
            }
            Self::Legacy(child) => {
                if let Ok(pid) = i32::try_from(child.id()) {
                    // SAFETY: the unreaped child owns a new process group with
                    // this ID. No other process group can reuse it yet.
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                }
                let _ = child.kill();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                while matches!(child.try_wait(), Ok(None)) {
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }
}

pub(super) fn start(
    inputs: &ProvisionInputs,
) -> Result<(DiscoveryChild, File, File, File), CliError> {
    if inputs.profile.containment_enforced() {
        return start_cage(inputs);
    }
    // Disabled/Shadow demos are explicitly unconfined. Never let that opt-in
    // turn privileged provisioning into an unconfined root execution path.
    // SAFETY: these credential queries have no pointer arguments or side effects.
    let privileged = unsafe { libc::getuid() == 0 || libc::geteuid() == 0 };
    if privileged {
        return Err(CliError::cli_other_error(
            "privileged discovery requires an Enforced cage; supply --tools-fixture for legacy provisioning",
        ));
    }
    let child = Command::new(&inputs.target_path)
        .args(inputs.target_argv.iter().skip(1))
        .current_dir(&inputs.working_directory)
        .env_clear()
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(failure)?;
    with_stdio(DiscoveryChild::Legacy(child))
}

fn start_cage(inputs: &ProvisionInputs) -> Result<(DiscoveryChild, File, File, File), CliError> {
    use chio_manifest::{
        NativeSyscallProfile, RequiredPermissions, RuntimeToolTopology, ToolAnnotations,
        ToolDefinition, ToolManifest, VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
    };

    // This ephemeral authority admits only a metadata-discovery process. No
    // discovered tool is registered until its returned surface is validated.
    let signer = chio_core::Keypair::generate();
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: inputs.server_id.clone(),
        name: inputs.server_name.clone(),
        description: None,
        version: inputs.server_version.clone(),
        tools: vec![ToolDefinition {
            name: "discover".to_string(),
            description: "Read MCP tool metadata".to_string(),
            input_schema: serde_json::json!({"type":"object"}),
            output_schema: None,
            pricing: None,
            latency_hint: None,
            flow: None,
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
        }],
        server_tools: Vec::new(),
        required_permissions: Some(RequiredPermissions {
            read_paths: super::super::declared_grants(&inputs.profile.ceilings.read_paths),
            write_paths: super::super::declared_grants(&inputs.profile.ceilings.write_paths),
            network_destinations: None,
            environment_variables: None,
            native_syscall_profile: NativeSyscallProfile::NativeMinimalV1,
        }),
        public_key: signer.public_key().to_hex(),
    };
    let signed = chio_manifest::sign_manifest(&manifest, &signer).map_err(failure)?;
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::local())
        .map_err(failure)?;
    let ceilings = chio_cage::OperatorCeilings::new(
        inputs.profile.ceilings.read_paths.clone(),
        inputs.profile.ceilings.write_paths.clone(),
        BTreeSet::new(),
        BTreeSet::new(),
        [NativeSyscallProfile::NativeMinimalV1]
            .into_iter()
            .collect(),
    );
    let admitted = chio_cage::admit(
        registry
            .authorize_cage_manifest(&inputs.server_id)
            .map_err(failure)?,
        &ceilings,
    )
    .map_err(failure)?;
    let paths = chio_cage::RuntimeResourcePaths::new(
        inputs.cage_init_path.clone(),
        inputs.target_path.clone(),
        inputs.working_directory.clone(),
        inputs.profile.ceilings.runtime_files.clone(),
        inputs.execution_identity.clone(),
    )
    .with_target_argv(inputs.target_argv.clone())
    .with_max_artifact_bytes(inputs.profile.max_artifact_bytes);
    let runtime = chio_cage::retain_runtime_resources(&paths).map_err(failure)?;
    let compiled =
        chio_cage::compile(admitted, runtime, &BTreeMap::new(), None).map_err(failure)?;
    if compiled.profile().target_binding_digest != inputs.target_binding_digest
        || compiled.profile().helper_binding_digest != inputs.cage_init_binding_digest
    {
        return Err(failure(
            "discovery executable changed after input validation",
        ));
    }
    let child =
        chio_cage::launch(compiled, chio_cage::CageLaunchOptions::default()).map_err(failure)?;
    with_stdio(DiscoveryChild::Enforced(Box::new(child)))
}

fn with_stdio(mut child: DiscoveryChild) -> Result<(DiscoveryChild, File, File, File), CliError> {
    // Own cleanup before extracting pipes, including partial extraction errors.
    let (stdin, stdout, stderr) = match &mut child {
        DiscoveryChild::Enforced(child) => child
            .take_stdio()
            .ok_or_else(|| failure("missing cage stdio"))?
            .into_parts(),
        DiscoveryChild::Legacy(child) => (
            File::from(std::os::fd::OwnedFd::from(
                child.stdin.take().ok_or_else(|| failure("missing stdin"))?,
            )),
            File::from(std::os::fd::OwnedFd::from(
                child
                    .stdout
                    .take()
                    .ok_or_else(|| failure("missing stdout"))?,
            )),
            File::from(std::os::fd::OwnedFd::from(
                child
                    .stderr
                    .take()
                    .ok_or_else(|| failure("missing stderr"))?,
            )),
        ),
    };
    Ok((child, stdin, stdout, stderr))
}

fn failure(error: impl std::fmt::Display) -> CliError {
    CliError::cli_other_error(format!("failed to launch MCP discovery: {error}"))
}
