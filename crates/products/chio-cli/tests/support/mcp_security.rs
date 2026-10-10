use chio_test_support::ctx::TestUnwrap;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug)]
pub(crate) struct NativeMcpSecurityMaterial {
    pub(crate) signed_manifest_path: PathBuf,
    pub(crate) manifest_public_key: String,
    pub(crate) cage_policy_path: PathBuf,
    pub(crate) cage_policy_signer: String,
    pub(crate) target_command: PathBuf,
    pub(crate) target_args: Vec<String>,
}

pub(crate) fn resolve_executable(name: &str) -> PathBuf {
    // The enforcing-host fixture packages Python and its exact import/ELF
    // closure. The selected target must match those reviewed runtime grants.
    let selected = if name == "/usr/bin/python3" {
        std::env::var_os("CHIO_DEMO_PYTHON").map(PathBuf::from)
    } else {
        None
    };
    let candidate = selected.as_deref().unwrap_or_else(|| Path::new(name));
    if candidate.components().count() > 1 {
        return fs::canonicalize(candidate).test_unwrap("canonicalize executable path");
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .map(|directory| directory.join(candidate))
        .find(|path| path.is_file() && fixture_executable_is_safe(path))
        .and_then(|path| fs::canonicalize(path).ok())
        .unwrap_or_else(|| panic!("could not resolve executable `{name}` from PATH"))
}

#[cfg(unix)]
fn fixture_executable_is_safe(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path)
        .map(|metadata| metadata.mode() & 0o022 == 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn fixture_executable_is_safe(_path: &Path) -> bool {
    true
}

fn required_path(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| {
        panic!("native MCP integration requires {name} from the enforcing-host fixture")
    }));
    assert!(path.is_absolute(), "{name} must be an absolute path");
    fs::canonicalize(path).unwrap_or_else(|error| panic!("resolve {name}: {error}"))
}

fn path_inventory(name: &str) -> BTreeSet<PathBuf> {
    let path = required_path(name);
    let text = fs::read_to_string(path).test_unwrap("read native fixture inventory");
    assert!(
        text.len() <= 64 * 1024,
        "native fixture inventory exceeds 64 KiB"
    );
    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let path = Path::new(line);
            assert!(path.is_absolute(), "native fixture paths must be absolute");
            fs::canonicalize(path).test_unwrap("resolve native fixture resource")
        })
        .collect()
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
    write_paths: &[PathBuf],
) -> NativeMcpSecurityMaterial {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        panic!("native MCP integration requires a qualified Linux x86_64 enforcing host");
    }
    let helper = required_path("CHIO_CAGE_INIT");
    let anchor = required_path("CHIO_RECEIPT_ANCHOR_ROOT");
    let mut read_paths = path_inventory("CHIO_CAGE_READ_PATHS_FILE");
    let mut runtime_files = path_inventory("CHIO_CAGE_RUNTIME_FILES_FILE");
    let target_command = fs::canonicalize(target_command).test_unwrap("canonicalize native target");
    let working_directory =
        fs::canonicalize(working_directory).test_unwrap("canonicalize working directory");
    let output_dir = fs::canonicalize(output_dir.parent().test_unwrap("native authority parent"))
        .test_unwrap("canonicalize native authority parent")
        .join(
            output_dir
                .file_name()
                .test_unwrap("native authority directory name"),
        );
    // Each caller supplies an owned Python script. Declare its retained runtime
    // file and exact read path; never grant the surrounding authority.
    let script = target_args.first().test_unwrap("native MCP fixture script");
    let script = fs::canonicalize(script).test_unwrap("canonicalize native MCP script");
    assert!(script.is_file(), "native MCP fixture script must be a file");
    let mut target_args = target_args.to_vec();
    target_args[0] = script
        .to_str()
        .test_unwrap("native MCP script path is UTF-8")
        .to_string();
    read_paths.insert(script.clone());
    runtime_files.insert(script);
    let identity = chio_cage::BrokerPeerIdentity::current_process()
        .test_unwrap("read native fixture operator identity");
    assert!(
        identity.uid != 0 && identity.gid != 0,
        "native MCP integration requires a non-root operator"
    );
    let mut command = Command::new(chio_executable);
    command
        .args([
            "security",
            "provision-reference-runtime",
            "--stage",
            "enforced",
            "--discover-tools",
        ])
        .arg("--output-dir")
        .arg(&output_dir)
        .arg("--cage-init")
        .arg(helper)
        .arg("--receipt-rollback-anchor-root")
        .arg(anchor)
        .args(["--max-artifact-bytes", "67108864"])
        .arg("--target")
        .arg(&target_command)
        .arg("--working-directory")
        .arg(&working_directory)
        .arg("--execution-uid")
        .arg(identity.uid.to_string())
        .arg("--execution-gid")
        .arg(identity.gid.to_string())
        .arg("--server-id")
        .arg(server_id)
        .arg("--server-name")
        .arg(server_name)
        .arg("--server-version")
        .arg(server_version)
        .arg("--syscall-profile")
        .arg("native-standard-v1");
    if let Ok(groups) = std::env::var("CHIO_CAGE_EXECUTION_SUPPLEMENTARY_GIDS") {
        for group in groups.split(',').filter(|group| !group.is_empty()) {
            let group: u32 = group.parse().test_unwrap("native supplementary group");
            assert_ne!(group, 0, "native fixture cannot retain root group");
            command
                .arg("--execution-supplementary-gid")
                .arg(group.to_string());
        }
    }
    for path in read_paths {
        command.arg("--read-path").arg(path);
    }
    for path in runtime_files {
        command.arg("--runtime-file").arg(path);
    }
    for path in write_paths {
        command
            .arg("--write-path")
            .arg(fs::canonicalize(path).test_unwrap("canonicalize native fixture write grant"));
    }
    for argument in &target_args {
        command.arg("--target-arg").arg(argument);
    }
    let output = command
        .output()
        .test_unwrap("provision enforced MCP fixture");
    assert!(
        output.status.success(),
        "enforced MCP fixture provisioning failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let read_key = |name: &str| {
        fs::read_to_string(output_dir.join(name))
            .test_unwrap("read provisioned public key")
            .trim()
            .to_string()
    };
    NativeMcpSecurityMaterial {
        signed_manifest_path: output_dir.join("signed-manifest.json"),
        manifest_public_key: read_key("manifest-public-key"),
        cage_policy_path: output_dir.join("cage-launch-policy.json"),
        cage_policy_signer: read_key("cage-policy-signer"),
        target_command,
        target_args,
    }
}
