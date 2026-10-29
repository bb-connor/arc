use super::super::super::report_validation::{normalize_cluster_config_url, normalize_cluster_url};
use super::super::*;
use super::validation::{normalize_control_endpoint, validate_control_token};

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

/// A client for one pinned peer's internal listener. Requests are signed with
/// this node's key for that peer; no bearer secret is sent.
pub(crate) fn build_cluster_peer_client(
    access: &Arc<crate::trust_control::caller_credentials::TrustAccess>,
    peer_node_id: &str,
) -> Result<TrustControlClient, CliError> {
    let recipient = normalize_cluster_url(peer_node_id)?;
    let peer = access.peers().get(&recipient).ok_or_else(|| {
        CliError::cli_other_error(format!("cluster peer {recipient} is not pinned"))
    })?;
    normalize_cluster_config_url(&peer.internal_url, true)?;
    build_client_with_cluster_peer(
        &peer.internal_url,
        "",
        Some(ClusterPeerClientAuth {
            access: Arc::clone(access),
            recipient: Arc::<str>::from(recipient),
        }),
        ControlClientAuthKind::Peer,
    )
}

#[derive(Clone, Copy)]
enum ControlClientAuthKind {
    Service,
    Public,
    Peer,
}

fn build_client_with_cluster_peer(
    control_url: &str,
    control_token: &str,
    cluster_peer_auth: Option<ClusterPeerClientAuth>,
    auth_kind: ControlClientAuthKind,
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
    // Credential-bearing and public clients use the same fixed authority boundary.
    // CHIO_EGRESS_LINT_ALLOW_DIRECT_UREQ: trust-control client for the operator-configured control
    // endpoints, redirects off
    let http = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .redirects(0)
        .build();
    Ok(TrustControlClient {
        endpoints: Arc::new(endpoints),
        preferred_index: Arc::new(Mutex::new(0)),
        token: Arc::<str>::from(control_token.to_string()),
        http,
        cluster_peer_auth,
    })
}
