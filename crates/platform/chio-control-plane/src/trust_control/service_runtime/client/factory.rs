use std::collections::BTreeSet;

use chio_egress_contract::{
    system_lookup, BlockingContractAgent, ContractLookup, EgressAllowanceSet, HttpEgressContract,
    HttpEgressError,
};
use chio_errors::_generated::error_codes::POLICY_DECISION_DENIED;

use super::super::super::report_validation::{normalize_cluster_config_url, normalize_cluster_url};
use super::super::*;
use super::validation::{normalize_control_endpoint, validate_control_token};

pub fn build_client(
    control_url: &str,
    control_token: &str,
    allowances: &EgressAllowanceSet,
) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(
        control_url,
        control_token,
        allowances,
        system_lookup(),
        None,
        ControlClientAuthKind::Service,
    )
}

/// As [`build_client`], resolving names through `lookup`.
#[cfg(test)]
pub(super) fn build_client_with_lookup(
    control_url: &str,
    control_token: &str,
    allowances: &EgressAllowanceSet,
    lookup: ContractLookup,
) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(
        control_url,
        control_token,
        allowances,
        lookup,
        None,
        ControlClientAuthKind::Service,
    )
}

pub fn build_public_client(
    control_url: &str,
    allowances: &EgressAllowanceSet,
) -> Result<TrustControlClient, CliError> {
    build_client_with_cluster_peer(
        control_url,
        "",
        allowances,
        system_lookup(),
        None,
        ControlClientAuthKind::Public,
    )
}

/// A client for one pinned peer's internal listener. Requests are signed with
/// this node's key for that peer; no bearer secret is sent.
pub(crate) fn build_cluster_peer_client(
    access: &Arc<crate::trust_control::caller_credentials::TrustAccess>,
    peer_node_id: &str,
    allowances: &EgressAllowanceSet,
) -> Result<TrustControlClient, CliError> {
    let recipient = normalize_cluster_url(peer_node_id)?;
    let peer = access.peers().get(&recipient).ok_or_else(|| {
        CliError::cli_other_error(format!("cluster peer {recipient} is not pinned"))
    })?;
    normalize_cluster_config_url(&peer.internal_url)?;
    build_client_with_cluster_peer(
        &peer.internal_url,
        "",
        allowances,
        system_lookup(),
        Some(ClusterPeerClientAuth {
            access: Arc::clone(access),
            recipient: Arc::<str>::from(recipient),
        }),
        ControlClientAuthKind::Peer,
    )
}

/// A refusal by the client's egress contract, which aborts the request
/// instead of failing over to another endpoint.
pub(crate) fn egress_refusal(error: HttpEgressError) -> CliError {
    CliError::with_public_source(
        &POLICY_DECISION_DENIED,
        "trust-control egress refused by the HttpEgressContract",
        error,
    )
}

/// A control endpoint list naming a loopback literal beside another endpoint.
/// One contract covers the whole list, so admitting loopback for the literal
/// would admit it for every DNS name in the list too.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "control endpoints mix loopback `{loopback}` with non-loopback `{other}`; \
     a client dials loopback literals only or no loopback at all"
)]
pub(crate) struct MixedLoopbackControlEndpoints {
    pub(crate) loopback: String,
    pub(crate) other: String,
}

/// Only a transport failure lets the client try its next endpoint.
pub(crate) fn is_transport_failure(error: &HttpEgressError) -> bool {
    matches!(
        error,
        HttpEgressError::Transport(_) | HttpEgressError::DnsResolutionFailed { .. }
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
    allowances: &EgressAllowanceSet,
    lookup: ContractLookup,
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
    let contract = control_client_contract(&endpoints, allowances)?;
    for endpoint in &endpoints {
        contract.enforce_url(endpoint, 0).map_err(egress_refusal)?;
    }
    let http = BlockingContractAgent::with_lookup(
        &contract,
        CONTROL_HTTP_TIMEOUT,
        CONTROL_HTTP_TIMEOUT,
        lookup,
    )
    .map_err(egress_refusal)?;
    Ok(TrustControlClient {
        endpoints: Arc::new(endpoints),
        preferred_index: Arc::new(Mutex::new(0)),
        token: Arc::<str>::from(control_token.to_string()),
        http,
        cluster_peer_auth,
    })
}

/// One contract per client: exactly its endpoints' schemes and authorities,
/// loopback only when every endpoint is a loopback literal, no redirects, the
/// peer response ceiling, and the operator allowances that pin one of its
/// endpoints. A list mixing a loopback literal with any other endpoint is
/// refused.
pub(super) fn control_client_contract(
    endpoints: &[String],
    allowances: &EgressAllowanceSet,
) -> Result<HttpEgressContract, CliError> {
    let mut allowed_schemes = BTreeSet::new();
    let mut allowed_authority_set = BTreeSet::new();
    let mut first_loopback = None;
    let mut first_other = None;
    for endpoint in endpoints {
        let url = Url::parse(endpoint).map_err(|error| {
            CliError::cli_other_error(format!("control URL must be a valid URL: {error}"))
        })?;
        let (host, is_loopback) = match url.host() {
            Some(Host::Domain(domain)) => {
                let domain = domain.trim_end_matches('.').to_ascii_lowercase();
                let is_loopback = domain == "localhost";
                (domain, is_loopback)
            }
            Some(Host::Ipv4(address)) => (address.to_string(), address.is_loopback()),
            Some(Host::Ipv6(address)) => (format!("[{address}]"), address.is_loopback()),
            None => {
                return Err(egress_refusal(HttpEgressError::MissingAuthority));
            }
        };
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        };
        let first = if is_loopback {
            &mut first_loopback
        } else {
            &mut first_other
        };
        first.get_or_insert_with(|| authority.clone());
        allowed_schemes.insert(url.scheme().to_owned());
        allowed_authority_set.insert(authority);
    }
    if let (Some(loopback), Some(other)) = (&first_loopback, &first_other) {
        return Err(CliError::with_public_source(
            &POLICY_DECISION_DENIED,
            "trust-control endpoints mix loopback and non-loopback hosts",
            MixedLoopbackControlEndpoints {
                loopback: loopback.clone(),
                other: other.clone(),
            },
        ));
    }
    let contract = HttpEgressContract {
        tenant_egress_namespace: "trust-control-client".to_owned(),
        allowed_schemes,
        allowed_authority_set,
        deny_loopback: first_loopback.is_none(),
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: MAX_PEER_RESPONSE_BYTES,
        private_network_allowances: BTreeSet::new(),
    }
    .with_private_network_allowances(allowances);
    contract.validate().map_err(egress_refusal)?;
    Ok(contract)
}
