//! Access configuration files for `chio trust serve` in integration tests.
#![allow(dead_code)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chio_control_plane::trust_control::caller_credentials::Scope;
use chio_control_plane::trust_control::credential_roles::CredentialRole;

/// Deployment id every test access configuration names.
pub const TEST_DEPLOYMENT: &str = "cli-test-deployment";

/// One extra credential beside the full test client.
pub struct TestCredential<'a> {
    pub id: &'a str,
    pub kind: &'a str,
    pub secret: &'a str,
    pub scopes: &'a [&'a str],
    pub tenant: Option<&'a str>,
}

/// One pinned peer of a clustered test node.
pub struct TestPeer<'a> {
    pub node_id: &'a str,
    pub internal_url: &'a str,
    pub public_key_hex: &'a str,
}

/// This node's cluster identity and pinned peers.
pub struct TestCluster<'a> {
    pub node_id: &'a str,
    pub node_key_file: &'a Path,
    pub peers: &'a [TestPeer<'a>],
}

/// Every caller scope, for the test-only credential standing in for every
/// operator and service client at once.
pub fn all_caller_scopes() -> Vec<&'static str> {
    Scope::ALL
        .iter()
        .filter(|scope| !scope.is_cluster())
        .map(|scope| scope.as_str())
        .collect()
}

/// The secret of the kernel-host credential every test access configuration
/// holds beside the full test client whose secret is `token`.
pub fn kernel_host_token(token: &str) -> String {
    format!("{token}.kernel-host")
}

/// The scopes of the `kernel-host` role preset.
pub fn kernel_host_scopes() -> Vec<&'static str> {
    CredentialRole::KernelHost
        .scopes()
        .iter()
        .map(|scope| scope.as_str())
        .collect()
}

fn credential_entry(out: &mut String, credential: &TestCredential<'_>) {
    let scopes = credential
        .scopes
        .iter()
        .map(|scope| format!("\"{scope}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let tenant_authority = match credential.tenant {
        None => "\"deployment\"".to_string(),
        Some(tenant) => format!("{{ tenant = \"{tenant}\" }}"),
    };
    let _ = write!(
        out,
        "[[credentials]]\nid = \"{}\"\nkind = \"{}\"\nsecret_sha256 = \"{}\"\nscopes = [{scopes}]\ndeployment = \"{TEST_DEPLOYMENT}\"\ntenant_authority = {tenant_authority}\n",
        credential.id,
        credential.kind,
        chio_core::sha256_hex(credential.secret.as_bytes()),
    );
}

/// The access configuration text: a deployment credential for `token`
/// holding every caller scope, the `kernel-host` preset credential for
/// `kernel_host_token(token)`, then `extra`, then the cluster identity.
pub fn access_config_text(
    token: &str,
    extra: &[TestCredential<'_>],
    internal_listen: &str,
    cluster: Option<&TestCluster<'_>>,
) -> String {
    let mut out =
        format!("deployment = \"{TEST_DEPLOYMENT}\"\ninternal_listen = \"{internal_listen}\"\n");
    credential_entry(
        &mut out,
        &TestCredential {
            id: "test-client",
            kind: "deployment",
            secret: token,
            scopes: &all_caller_scopes(),
            tenant: None,
        },
    );
    credential_entry(
        &mut out,
        &TestCredential {
            id: "kernel-host",
            kind: "deployment",
            secret: &kernel_host_token(token),
            scopes: &kernel_host_scopes(),
            tenant: None,
        },
    );
    for credential in extra {
        credential_entry(&mut out, credential);
    }
    if let Some(cluster) = cluster {
        let _ = write!(
            out,
            "[cluster]\nnode_id = \"{}\"\nnode_key_file = \"{}\"\n",
            cluster.node_id,
            cluster.node_key_file.display()
        );
        for peer in cluster.peers {
            let _ = write!(
                out,
                "[[cluster.peers]]\nnode_id = \"{}\"\ninternal_url = \"{}\"\npublic_key = \"{}\"\nscopes = [\"cluster:replicate\", \"cluster-openings:replicate\"]\n",
                peer.node_id, peer.internal_url, peer.public_key_hex
            );
        }
    }
    out
}

fn unique_path(extension: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let index = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "chio-trust-access-{}-{index}.{extension}",
        std::process::id()
    ))
}

/// Write `text` to a fresh owner-only file and return its path.
pub fn write_private(text: &str, extension: &str) -> PathBuf {
    let path = unique_path(extension);
    write_private_at(&path, text);
    path
}

/// Write `text` to `path` with owner-only permissions.
pub fn write_private_at(path: &Path, text: &str) {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) => panic!("create {}: {error}", path.display()),
    };
    if let Err(error) = file.write_all(text.as_bytes()) {
        panic!("write {}: {error}", path.display());
    }
}

/// Access configuration for one unclustered node: the full client credential
/// for `token`, `extra` credentials and an ephemeral loopback internal listener.
pub fn write_access_config(token: &str, extra: &[TestCredential<'_>]) -> String {
    let text = access_config_text(token, extra, "127.0.0.1:0", None);
    write_private(&text, "toml").display().to_string()
}

fn internal_listens() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static REGISTRY: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, String>>,
    > = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// The internal listener address reserved for the trust service whose public
/// listener is `public` (`host:port` or `http://host:port`).
pub fn internal_listen_for(public: &str) -> String {
    let key = public
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let mut registry = match internal_listens().lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    registry
        .entry(key.clone())
        .or_insert_with(|| loop {
            // A reserved port is released before the service binds it, so a
            // later reservation can return the public port itself.
            let internal = chio_test_support::loopback::reserve_listen_addr().to_string();
            if internal != key {
                break internal;
            }
        })
        .clone()
}

/// The internal listener URL of the trust service at `public`.
pub fn internal_url_for(public: &str) -> String {
    format!("http://{}", internal_listen_for(public))
}

/// Access configuration for the trust service listening on `public_listen`,
/// with its internal listener at `internal_listen_for(public_listen)`.
pub fn write_access_config_for(
    public_listen: &str,
    token: &str,
    extra: &[TestCredential<'_>],
) -> String {
    let text = access_config_text(token, extra, &internal_listen_for(public_listen), None);
    write_private(&text, "toml").display().to_string()
}
