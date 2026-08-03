use super::super::super::report_validation::normalize_cluster_url;
use super::super::*;
use super::validation::{normalize_control_endpoint, validate_control_token};
use std::fs;
use std::io::Read as _;
use std::path::Path;

const CONTROL_TLS_ROOT_CA_FILE_ENV: &str = "CHIO_CONTROL_TLS_ROOT_CA_FILE";
const CONTROL_TLS_ROOT_CA_FILE_MAX_BYTES: usize = 1024 * 1024;

pub fn build_client(
    control_url: &str,
    control_token: &str,
) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(
        control_url,
        control_token,
        None,
        ControlClientAuthKind::Service,
    )
}

pub fn build_public_client(control_url: &str) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(control_url, "", None, ControlClientAuthKind::Public)
}

pub(crate) fn build_cluster_peer_client(
    control_url: &str,
    config: &TrustServiceConfig,
    node_id: &str,
) -> Result<TrustControlClient, CliError> {
    let node_id = normalize_cluster_url(node_id)?;
    let seed_path = config.cluster_node_seed_path.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "cluster peer client requires a configured node identity seed".to_string(),
        )
    })?;
    let signing_key = load_strict_cluster_node_keypair(seed_path).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to load strict cluster node identity seed: {error}"
        ))
    })?;
    let pinned_self_key = config
        .cluster_members
        .iter()
        .find_map(|member| {
            normalize_cluster_url(&member.node_url)
                .ok()
                .filter(|member_url| member_url == &node_id)
                .map(|_| member.public_key.clone())
        })
        .ok_or_else(|| {
            CliError::cli_other_error(
                "cluster peer client identity is absent from pinned membership".to_string(),
            )
        })?;
    if pinned_self_key != signing_key.public_key() {
        return Err(CliError::cli_other_error(
            "cluster peer client seed does not match its pinned membership key".to_string(),
        ));
    }
    build_client_with_cluster_peer(
        control_url,
        "",
        Some(ClusterPeerClientAuth {
            node_id: Arc::<str>::from(node_id),
            signing_key: Arc::new(signing_key),
        }),
        ControlClientAuthKind::Public,
    )
}

#[derive(Clone, Copy)]
enum ControlClientAuthKind {
    Service,
    Public,
}

fn build_client_with_cluster_peer(
    control_url: &str,
    control_token: &str,
    cluster_peer_auth: Option<ClusterPeerClientAuth>,
    auth_kind: ControlClientAuthKind,
) -> Result<TrustControlClient, CliError> {
    let tls_root_ca_path = std::env::var_os(CONTROL_TLS_ROOT_CA_FILE_ENV);
    build_client_with_cluster_peer_and_tls_root(
        control_url,
        control_token,
        cluster_peer_auth,
        auth_kind,
        tls_root_ca_path.as_deref().map(Path::new),
    )
}

fn build_client_with_cluster_peer_and_tls_root(
    control_url: &str,
    control_token: &str,
    cluster_peer_auth: Option<ClusterPeerClientAuth>,
    auth_kind: ControlClientAuthKind,
    tls_root_ca_path: Option<&Path>,
) -> Result<TrustControlClient, CliError> {
    if matches!(auth_kind, ControlClientAuthKind::Service) {
        validate_control_token(control_token)?;
    }
    let endpoints = control_url
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_control_endpoint)
        .collect::<Result<Vec<_>, _>>()?;
    if endpoints.is_empty() {
        return Err(CliError::cli_other_error(
            "control URL must not be empty".to_string(),
        ));
    }
    let http = build_control_http_agent(tls_root_ca_path)?;
    Ok(TrustControlClient {
        endpoints: Arc::new(endpoints),
        preferred_index: Arc::new(Mutex::new(0)),
        token: Arc::<str>::from(control_token.to_string()),
        http,
        cluster_peer_auth,
    })
}

fn build_control_http_agent(tls_root_ca_path: Option<&Path>) -> Result<Agent, CliError> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .redirects(0);
    if let Some(path) = tls_root_ca_path {
        let tls_config = build_control_tls_config(path)?;
        builder = builder.tls_config(Arc::new(tls_config));
    }
    Ok(builder.build())
}

fn build_control_tls_config(path: &Path) -> Result<ureq::rustls::ClientConfig, CliError> {
    let _ = ureq::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let roots = load_control_tls_root_store(path)?;
    Ok(ureq::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn load_control_tls_root_store(path: &Path) -> Result<ureq::rustls::RootCertStore, CliError> {
    let pem = read_control_tls_root_ca_file(path)?;
    let mut reader = pem.as_slice();
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            control_tls_root_error(format!("contains malformed PEM certificate data: {error}"))
        })?;
    if certificates.is_empty() {
        return Err(control_tls_root_error(
            "does not contain a PEM certificate".to_string(),
        ));
    }

    // Deliberately start empty. Configuring a private control-plane CA must not
    // retain the ambient public WebPKI root set.
    let mut roots = ureq::rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(|error| {
            control_tls_root_error(format!("contains an invalid CA certificate: {error}"))
        })?;
    }
    Ok(roots)
}

fn read_control_tls_root_ca_file(path: &Path) -> Result<Vec<u8>, CliError> {
    if path.as_os_str().is_empty() {
        return Err(control_tls_root_error(
            "must not be an empty path".to_string(),
        ));
    }
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        control_tls_root_error(format!("must name an existing regular file: {error}"))
    })?;
    validate_control_tls_root_ca_metadata(&path_metadata)?;
    validate_control_tls_root_ca_size(path_metadata.len())?;

    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{open, Mode, OFlags};

        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| control_tls_root_error(format!("could not be opened: {error}")))?;
        std::fs::File::from(descriptor)
    };
    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| control_tls_root_error(format!("could not be opened: {error}")))?;

    let opened_metadata = file.metadata().map_err(|error| {
        control_tls_root_error(format!("metadata could not be read after open: {error}"))
    })?;
    validate_control_tls_root_ca_metadata(&opened_metadata)?;
    validate_control_tls_root_ca_size(opened_metadata.len())?;
    #[cfg(unix)]
    validate_same_control_tls_root_ca_file(&path_metadata, &opened_metadata)?;

    let read_limit = u64::try_from(CONTROL_TLS_ROOT_CA_FILE_MAX_BYTES)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or_else(|| control_tls_root_error("has an invalid byte limit".to_string()))?;
    let mut pem = Vec::with_capacity(CONTROL_TLS_ROOT_CA_FILE_MAX_BYTES);
    std::io::Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut pem)
        .map_err(|error| control_tls_root_error(format!("could not be read: {error}")))?;
    if pem.len() > CONTROL_TLS_ROOT_CA_FILE_MAX_BYTES {
        return Err(control_tls_root_error(format!(
            "exceeds the {CONTROL_TLS_ROOT_CA_FILE_MAX_BYTES}-byte limit"
        )));
    }
    if pem.is_empty() {
        return Err(control_tls_root_error("must not be empty".to_string()));
    }

    let final_path_metadata = fs::symlink_metadata(path).map_err(|error| {
        control_tls_root_error(format!("could not be revalidated after read: {error}"))
    })?;
    validate_control_tls_root_ca_metadata(&final_path_metadata)?;
    #[cfg(unix)]
    {
        validate_same_control_tls_root_ca_file(&path_metadata, &final_path_metadata)?;
        let final_opened_metadata = file.metadata().map_err(|error| {
            control_tls_root_error(format!("could not be revalidated after read: {error}"))
        })?;
        validate_same_control_tls_root_ca_file(&path_metadata, &final_opened_metadata)?;
    }
    Ok(pem)
}

fn validate_control_tls_root_ca_metadata(metadata: &fs::Metadata) -> Result<(), CliError> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(control_tls_root_error(
            "must name a regular file and must not be a symlink".to_string(),
        ));
    }
    Ok(())
}

fn validate_control_tls_root_ca_size(size: u64) -> Result<(), CliError> {
    if size == 0 {
        return Err(control_tls_root_error("must not be empty".to_string()));
    }
    let maximum = u64::try_from(CONTROL_TLS_ROOT_CA_FILE_MAX_BYTES)
        .map_err(|_| control_tls_root_error("has an invalid byte limit".to_string()))?;
    if size > maximum {
        return Err(control_tls_root_error(format!(
            "exceeds the {CONTROL_TLS_ROOT_CA_FILE_MAX_BYTES}-byte limit"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_same_control_tls_root_ca_file(
    expected: &fs::Metadata,
    observed: &fs::Metadata,
) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;

    if expected.dev() != observed.dev() || expected.ino() != observed.ino() {
        return Err(control_tls_root_error(
            "changed while it was being opened or read".to_string(),
        ));
    }
    Ok(())
}

fn control_tls_root_error(reason: String) -> CliError {
    CliError::cli_other_error(format!("{CONTROL_TLS_ROOT_CA_FILE_ENV} {reason}"))
}

#[cfg(test)]
pub(crate) fn build_control_http_agent_for_test(
    tls_root_ca_path: Option<&Path>,
) -> Result<Agent, CliError> {
    build_control_http_agent(tls_root_ca_path)
}

#[cfg(test)]
pub(crate) fn load_control_tls_root_store_for_test(
    path: &Path,
) -> Result<ureq::rustls::RootCertStore, CliError> {
    load_control_tls_root_store(path)
}

#[cfg(test)]
pub(crate) const fn control_tls_root_ca_file_max_bytes_for_test() -> usize {
    CONTROL_TLS_ROOT_CA_FILE_MAX_BYTES
}
