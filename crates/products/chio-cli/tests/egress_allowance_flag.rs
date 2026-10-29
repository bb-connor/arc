#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use chio_egress_contract::{
    private_network_allowance_digest, EgressAllowanceSet, PrivateNetworkAllowanceError,
};

const VALID_ALLOWANCES: &str =
    "[[allow]]\nhost = \"control.vpc.internal\"\nport = 9443\ncidr = \"10.20.0.0/24\"\n";

const RESERVED_ALLOWANCES: &str =
    "[[allow]]\nhost = \"control.vpc.internal\"\nport = 9443\ncidr = \"169.254.0.0/16\"\n";

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "chio-egress-allowance-flag-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("create scratch directory");
    directory
}

fn write(directory: &Path, name: &str, text: &str) -> PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, text).expect("write scratch file");
    path
}

fn chio(allowances: Option<&Path>, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    if let Some(allowances) = allowances {
        command.arg("--egress-allowance-file").arg(allowances);
    }
    command
        .args(args)
        .env("CHIO_EGRESS_FLAG_SECRET", "flag-secret")
        .output()
        .expect("spawn chio")
}

#[test]
fn every_command_loads_the_allowance_file_before_it_runs() {
    let directory = scratch("loaded");
    let allowances = write(&directory, "egress.toml", RESERVED_ALLOWANCES);
    let access = directory.join("access.toml");
    let access = access.to_str().expect("utf8 path");
    let profile = directory.join("profile.json");
    let profile = profile.to_str().expect("utf8 path");
    let missing = directory.join("missing.yaml");
    let missing = missing.to_str().expect("utf8 path");
    let init_target = directory.join("scaffold");
    let init_target = init_target.to_str().expect("utf8 path");
    let loader_refusal = format!(
        "error [urn:chio:error:cli:other]: {}",
        PrivateNetworkAllowanceError::CidrIncludesReservedAddress {
            cidr: "169.254.0.0/16".to_string(),
            reserved: "169.254.0.0/16".to_string(),
        }
    );
    let cases: [&[&str]; 13] = [
        &["trust", "serve", "--access-config", access],
        &["trust", "config", "check", "--access-config", access],
        &["start", "--listen", "127.0.0.1:0"],
        &["api", "protect", "--upstream", "http://127.0.0.1:9"],
        &["mcp", "wrap", "--server-id", "fs", "--", "true"],
        &["finding", "operator", "serve", "--profile", profile],
        &["finding", "operator", "tick", "--profile", missing],
        &["run", "--policy", missing, "--", "true"],
        &["trust", "revoke", "--capability-id", "cap-1"],
        &["trust", "status", "--capability-id", "cap-1"],
        &["receipt", "list"],
        &[
            "trust",
            "config",
            "credential",
            "--deployment",
            "dep-a",
            "--secret-env",
            "CHIO_EGRESS_FLAG_SECRET",
            "--id",
            "entry",
            "--role",
            "operator",
        ],
        &["init", init_target],
    ];
    for args in cases {
        let output = chio(Some(&allowances), args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert_eq!(
            stderr.lines().next(),
            Some(loader_refusal.as_str()),
            "{args:?}: {stderr}"
        );
        assert!(output.stdout.is_empty(), "{args:?}: stdout was written");
    }
    assert!(
        !Path::new(init_target).exists(),
        "init ran before the allowance file was refused"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

const EGRESS_REFUSED: &str = "trust-control egress refused by the HttpEgressContract";
const TRANSPORT_FAILED: &str = "trust control service transport failed";

/// A loopback port with no listener, so a dial is refused at once.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("address").port()
}

#[test]
fn control_plane_commands_dial_under_the_allowance_file() {
    let directory = scratch("dialed");
    let port = closed_port();
    let allowances = write(
        &directory,
        "egress.toml",
        &format!("[[allow]]\nhost = \"localhost\"\nport = {port}\ncidr = \"10.20.0.0/24\"\n"),
    );
    let control_url = format!("https://localhost:{port}");
    let control = [
        "--control-url",
        control_url.as_str(),
        "--control-token",
        "egress-flag-token",
    ];
    let commands: [&[&str]; 3] = [
        &["trust", "revoke", "--capability-id", "cap-1"],
        &["trust", "status", "--capability-id", "cap-1"],
        &["receipt", "list"],
    ];
    for command in commands {
        let args: Vec<&str> = control.iter().chain(command).copied().collect();

        let pinned = chio(Some(&allowances), &args);
        let stderr = String::from_utf8_lossy(&pinned.stderr);
        assert_eq!(pinned.status.code(), Some(1), "{command:?}: {stderr}");
        assert!(stderr.contains(EGRESS_REFUSED), "{command:?}: {stderr}");

        let unpinned = chio(None, &args);
        let stderr = String::from_utf8_lossy(&unpinned.stderr);
        assert_eq!(unpinned.status.code(), Some(1), "{command:?}: {stderr}");
        assert!(!stderr.contains(EGRESS_REFUSED), "{command:?}: {stderr}");
        assert!(stderr.contains(TRANSPORT_FAILED), "{command:?}: {stderr}");
    }
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn trust_config_check_reports_the_digest_of_the_consumed_allowance_file() {
    let directory = scratch("config-check");
    let allowances = write(&directory, "egress.toml", VALID_ALLOWANCES);
    let access = write(
        &directory,
        "access.toml",
        &format!(
            "deployment = \"dep-a\"\ninternal_listen = \"127.0.0.1:9101\"\n\
             [[credentials]]\nid = \"reader\"\nkind = \"caller\"\nsecret_sha256 = \"{}\"\n\
             scopes = [\"receipts:read\"]\ndeployment = \"dep-a\"\n\
             tenant_authority = \"deployment\"\n",
            chio_core::sha256_hex(b"reader-secret"),
        ),
    );
    let access = access.to_str().expect("utf8 path");
    let output = chio(
        Some(&allowances),
        &["trust", "config", "check", "--access-config", access],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let set = EgressAllowanceSet::load_file(&allowances).expect("valid allowance file");
    let digest = private_network_allowance_digest(set.entries()).expect("digest");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("egress allowances: {digest}\n")),
        "{stdout}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}
