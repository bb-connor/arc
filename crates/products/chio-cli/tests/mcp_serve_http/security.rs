use super::{mcp_security, ServerGuard};
use chio_test_support::ctx::TestUnwrap;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

pub(super) fn http_security_material(
    dir: &Path,
    script_path: &Path,
    startup_marker: Option<&Path>,
) -> mcp_security::NativeMcpSecurityMaterial {
    static MATERIALS: OnceLock<
        Mutex<HashMap<PathBuf, Arc<OnceLock<mcp_security::NativeMcpSecurityMaterial>>>>,
    > = OnceLock::new();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .test_unwrap("secure remote MCP test directory permissions");
    }
    let canonical_dir = fs::canonicalize(dir).test_unwrap("canonicalize remote MCP test directory");
    let material = {
        let mut materials = MATERIALS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(
            materials
                .entry(canonical_dir.clone())
                .or_insert_with(|| Arc::new(OnceLock::new())),
        )
    };

    material
        .get_or_init(|| {
            let target_command = mcp_security::resolve_executable("/usr/bin/python3");
            let script_path =
                fs::canonicalize(script_path).test_unwrap("canonicalize mock MCP server script");
            let mut target_args = vec![script_path
                .to_str()
                .test_unwrap("mock MCP server path is UTF-8")
                .to_string()];
            let mut write_paths = Vec::new();
            if let Some(marker) = startup_marker {
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                options
                    .open(marker)
                    .test_unwrap("create private startup marker");
                let marker = fs::canonicalize(marker).test_unwrap("canonicalize startup marker");
                target_args.extend([
                    "--startup-marker".to_string(),
                    marker
                        .to_str()
                        .test_unwrap("startup marker UTF-8")
                        .to_string(),
                ]);
                write_paths.push(marker);
            }
            let material = mcp_security::materialize_mcp_security(
                &canonical_dir.join("security"),
                Path::new(env!("CARGO_BIN_EXE_chio")),
                &target_command,
                &target_args,
                &canonical_dir,
                "wrapped-http-mock",
                "Wrapped HTTP Mock",
                "0.1.0",
                &write_paths,
            );
            if let Some(marker) = startup_marker {
                // Discovery used the same signed command. Count only the
                // actual edge's launches in shared-owner assertions.
                fs::write(marker, b"").test_unwrap("clear discovery startup marker");
            }
            material
        })
        .clone()
}

pub(super) fn spawn_secured_http_command(
    mut command: Command,
    dir: &Path,
    script_path: &Path,
    label: &str,
) -> ServerGuard {
    let startup_marker = command.get_envs().find_map(|(name, value)| {
        (name == "CHIO_MCP_STARTUP_MARKER_PATH")
            .then(|| value.map(PathBuf::from))
            .flatten()
    });
    command.env_remove("CHIO_MCP_STARTUP_MARKER_PATH");
    let security = http_security_material(dir, script_path, startup_marker.as_deref());
    command
        .current_dir(dir)
        .args([
            "--server-version",
            "0.1.0",
            "--signed-manifest",
            security
                .signed_manifest_path
                .to_str()
                .test_unwrap("signed manifest path"),
            "--manifest-public-key",
            &security.manifest_public_key,
            "--cage-policy",
            security
                .cage_policy_path
                .to_str()
                .test_unwrap("cage policy path"),
            "--cage-policy-signer",
            &security.cage_policy_signer,
            "--",
            security
                .target_command
                .to_str()
                .test_unwrap("MCP target command path"),
        ])
        .args(&security.target_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let child = command
        .spawn()
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    ServerGuard { child }
}
