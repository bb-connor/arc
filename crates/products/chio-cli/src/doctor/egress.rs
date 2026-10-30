//! Egress contract for the doctor network probes.
//!
//! A probe uses the runtime's own single-endpoint contract for the URL the
//! operator configured: `https`, or plaintext `http` to a loopback host,
//! that authority only, no redirects, no proxy, and no private, unique-local,
//! link-local or special-use address. An endpoint the runtime would refuse
//! is reported as a finding and never dialed.

use std::time::Duration;

use chio_egress_contract::{
    BlockingContractAgent, BlockingContractResponse, EndpointSource, HttpEgressContract,
    HttpEgressError,
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_DEADLINE: Duration = Duration::from_secs(10);
/// Ceiling on the probe response body. A registry `/v2/` answer is empty or a
/// short JSON error, and the gauge probe reads one metrics exposition; a body
/// above this is refused by the contract and reported as a policy refusal.
const MAX_PROBE_BODY_BYTES: u64 = 1024 * 1024;

/// Help attached to every egress refusal of a doctor probe.
pub(super) const REFUSAL_HELP: &str = "The doctor probe uses the runtime's egress contract: \
     https, or http to a loopback host, no redirects, and no private, unique-local, \
     link-local or special-use address. A name that resolves into private address \
     space is refused. The runtime refuses this endpoint too.";

fn probe_contract(url: &str) -> Result<HttpEgressContract, HttpEgressError> {
    HttpEgressContract::single_endpoint(
        EndpointSource::Operator,
        "chio-doctor",
        url,
        MAX_PROBE_BODY_BYTES,
    )
}

/// True when the contract refused the target, as opposed to the target being
/// unreachable.
pub(super) fn is_policy_refusal(error: &HttpEgressError) -> bool {
    match error {
        HttpEgressError::Transport(_) | HttpEgressError::DnsResolutionFailed { .. } => false,
        HttpEgressError::MissingContract
        | HttpEgressError::InvalidContract(_)
        | HttpEgressError::InvalidUrl(_)
        | HttpEgressError::MissingAuthority
        | HttpEgressError::UserinfoDenied
        | HttpEgressError::SchemeDenied { .. }
        | HttpEgressError::AuthorityDenied { .. }
        | HttpEgressError::LoopbackDenied { .. }
        | HttpEgressError::LinkLocalDenied { .. }
        | HttpEgressError::Ipv6UlaDenied { .. }
        | HttpEgressError::PrivateNetworkDenied { .. }
        | HttpEgressError::RedirectLimitExceeded { .. }
        | HttpEgressError::ResponseTooLarge { .. }
        | HttpEgressError::InvalidAllowance(_)
        | HttpEgressError::PrivateNetworkAllowanceMismatch { .. }
        | HttpEgressError::PrivateNetworkAllowanceSchemeMismatch { .. }
        | HttpEgressError::ReservedAddressDenied { .. }
        | HttpEgressError::LoopbackNameResolvedOffHost { .. } => true,
    }
}

/// The finding for a refused endpoint. A scheme refusal names the scheme,
/// because the runtime refuses it for the same reason.
pub(super) fn refusal_finding(error: &HttpEgressError) -> String {
    match error {
        HttpEgressError::SchemeDenied { scheme } => format!(
            "uses {scheme}, which the runtime refuses: only https, or http to a loopback host, is admitted"
        ),
        error => format!("refused by the egress contract: {error}"),
    }
}

/// GET `url` under a contract that admits only its own authority.
pub(super) fn probe_get(url: &str) -> Result<BlockingContractResponse, HttpEgressError> {
    let contract = probe_contract(url)?;
    BlockingContractAgent::new(&contract, PROBE_TIMEOUT, PROBE_DEADLINE)?
        .get(url)?
        .call()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod test_support {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Loopback server that answers every request with `response` and counts requests.
    pub(crate) struct LoopbackServer {
        pub(crate) port: u16,
        pub(crate) hits: Arc<AtomicUsize>,
    }

    pub(crate) fn serve(response: String) -> LoopbackServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buffer = [0u8; 2048];
                let _ = stream.read(&mut buffer);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        LoopbackServer { port, hits }
    }

    pub(crate) fn redirect_to(location: &str) -> String {
        format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn link_local_target_is_refused_as_link_local() {
        assert!(matches!(
            probe_get("https://169.254.169.254/latest/meta-data"),
            Err(HttpEgressError::LinkLocalDenied { .. })
        ));
    }

    #[test]
    fn plaintext_http_to_a_remote_host_is_a_refused_scheme() {
        let error = probe_get("http://metrics.example.com:9100/metrics").expect_err("http");
        assert_eq!(
            error,
            HttpEgressError::SchemeDenied {
                scheme: "http".to_string()
            }
        );
        assert!(is_policy_refusal(&error));
        assert!(refusal_finding(&error).starts_with("uses http, which the runtime refuses"));
    }

    #[test]
    fn private_and_unique_local_literals_are_refused() {
        assert!(matches!(
            probe_get("https://10.0.0.5:9100/metrics"),
            Err(HttpEgressError::PrivateNetworkDenied { .. })
        ));
        assert!(matches!(
            probe_get("https://[fd12:3456::7]:9100/metrics"),
            Err(HttpEgressError::Ipv6UlaDenied { .. })
        ));
    }

    #[test]
    fn a_configured_name_never_reaches_private_address_space() {
        let contract = probe_contract("https://metrics.example.com:9100/metrics").unwrap();
        for address in ["10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1"] {
            let error = contract
                .enforce_resolved_address(
                    "metrics.example.com",
                    SocketAddr::new(address.parse().unwrap(), 9100),
                )
                .expect_err("rebound name");
            assert!(matches!(
                error,
                HttpEgressError::PrivateNetworkDenied { .. }
            ));
            assert!(is_policy_refusal(&error));
        }
    }

    #[test]
    fn only_a_loopback_url_may_use_plaintext_http() {
        assert!(
            !probe_contract("http://localhost.:9100/metrics")
                .unwrap()
                .deny_loopback
        );
        assert!(
            probe_contract("https://registry.example.com./v2/")
                .unwrap()
                .deny_loopback
        );
    }
}
