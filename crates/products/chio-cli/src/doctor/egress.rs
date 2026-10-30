//! Egress contract for the doctor network probes.
//!
//! A probe targets one user-configured URL. The contract admits exactly that
//! authority, never follows redirects, ignores proxy variables, pins the
//! resolved addresses and refuses link-local answers. A non-loopback
//! authority also refuses loopback answers. A private IPv4 or unique-local
//! IPv6 literal is reachable through an allowance pinned to that address;
//! a name never reaches private address space.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use chio_egress_contract::{
    BlockingContractAgent, BlockingContractResponse, HttpEgressContract, HttpEgressError,
    PrivateNetworkAllowance,
};
use url::{Host, Url};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_DEADLINE: Duration = Duration::from_secs(10);
/// Ceiling on the probe response body. A registry `/v2/` answer is empty or a
/// short JSON error, and the gauge probe reads one metrics exposition; a body
/// above this is refused by the contract and reported as a policy refusal.
const MAX_PROBE_BODY_BYTES: u64 = 1024 * 1024;

fn probe_contract(url: &str) -> Result<HttpEgressContract, HttpEgressError> {
    let parsed = Url::parse(url)
        .map_err(|err| HttpEgressError::InvalidContract(format!("invalid probe url: {err}")))?;
    let host = parsed
        .host()
        .ok_or_else(|| HttpEgressError::InvalidContract("probe url has no host".to_string()))?;
    let loopback = match &host {
        Host::Domain(name) => name.trim_end_matches('.').eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => IpAddr::V4(*address).is_loopback(),
        Host::Ipv6(address) => IpAddr::V6(*address).is_loopback(),
    };
    let authority = match (host, parsed.port()) {
        (Host::Ipv6(address), Some(port)) => format!("[{address}]:{port}"),
        (Host::Ipv6(address), None) => format!("[{address}]"),
        (Host::Domain(name), Some(port)) => {
            format!("{}:{port}", name.trim_end_matches('.').to_ascii_lowercase())
        }
        (Host::Domain(name), None) => name.trim_end_matches('.').to_ascii_lowercase(),
        (host, Some(port)) => format!("{host}:{port}"),
        (host, None) => host.to_string(),
    };
    Ok(HttpEgressContract {
        tenant_egress_namespace: "chio-doctor".to_string(),
        allowed_schemes: BTreeSet::from([parsed.scheme().to_string()]),
        allowed_authority_set: BTreeSet::from([authority]),
        deny_loopback: !loopback,
        deny_link_local: true,
        max_redirect_chain: 0,
        max_response_bytes: MAX_PROBE_BODY_BYTES,
        private_network_allowances: PrivateNetworkAllowance::for_private_ipv4_literal(&parsed)
            .or_else(|| PrivateNetworkAllowance::for_ipv6_ula_literal(&parsed))
            .into_iter()
            .collect(),
    })
}

/// True when the contract refused the target, as opposed to the target being
/// unreachable. Private and special-use addresses are always refused by the
/// contract, so a probe of a private-network endpoint reports a refusal.
pub(super) fn is_policy_refusal(error: &HttpEgressError) -> bool {
    !matches!(
        error,
        HttpEgressError::Transport(_) | HttpEgressError::DnsResolutionFailed { .. }
    )
}

/// GET `url` under a contract that admits only its own authority.
pub(super) fn probe_get(url: &str) -> Result<BlockingContractResponse, HttpEgressError> {
    let contract = probe_contract(url)?;
    BlockingContractAgent::new(&contract, PROBE_TIMEOUT, PROBE_DEADLINE)?
        .get(url)?
        .call()
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Loopback server that answers every request with `response` and counts requests.
    pub(crate) struct Stub {
        pub(crate) port: u16,
        pub(crate) hits: Arc<AtomicUsize>,
    }

    pub(crate) fn serve(response: String) -> Stub {
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
        Stub { port, hits }
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
            probe_get("http://169.254.169.254/latest/meta-data"),
            Err(HttpEgressError::LinkLocalDenied { .. })
        ));
    }

    fn resolved(
        contract: &HttpEgressContract,
        host: &str,
        address: &str,
        port: u16,
    ) -> Result<(), HttpEgressError> {
        contract.enforce_resolved_address(host, SocketAddr::new(address.parse().unwrap(), port))
    }

    #[test]
    fn a_configured_name_never_reaches_private_address_space() {
        let contract = probe_contract("http://metrics.example.com:9100/metrics").unwrap();
        assert!(contract.private_network_allowances.is_empty());
        for address in ["10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1"] {
            let error = resolved(&contract, "metrics.example.com", address, 9100)
                .expect_err("rebound name");
            assert!(matches!(error, HttpEgressError::PrivateNetworkDenied { .. }));
            assert!(is_policy_refusal(&error));
        }
        assert!(resolved(&contract, "metrics.example.com", "93.184.216.34", 9100).is_ok());
    }

    #[test]
    fn a_private_literal_is_reached_only_at_its_pinned_address() {
        let contract = probe_contract("http://10.0.0.5:9100/metrics").unwrap();
        assert_eq!(contract.private_network_allowances.len(), 1);
        assert!(contract.enforce_url("http://10.0.0.5:9100/metrics", 0).is_ok());
        assert!(resolved(&contract, "10.0.0.5", "10.0.0.5", 9100).is_ok());
        for address in ["10.0.0.6", "10.1.2.3", "192.168.1.1", "93.184.216.34"] {
            let error = resolved(&contract, "10.0.0.5", address, 9100).expect_err("off pin");
            assert!(
                matches!(
                    error,
                    HttpEgressError::PrivateNetworkAllowanceMismatch { .. }
                ),
                "{address}"
            );
        }
    }

    #[test]
    fn a_unique_local_literal_is_pinned_and_other_private_space_stays_refused() {
        let contract = probe_contract("http://[fd12:3456::7]:9100/metrics").unwrap();
        assert_eq!(contract.private_network_allowances.len(), 1);
        assert!(resolved(&contract, "fd12:3456::7", "fd12:3456::7", 9100).is_ok());
        assert!(resolved(&contract, "fd12:3456::7", "fd12:3456::8", 9100).is_err());
    }

    #[test]
    fn metadata_and_public_literals_get_no_allowance() {
        for url in [
            "http://169.254.169.254/latest/meta-data",
            "http://100.100.100.200/",
            "http://93.184.216.34/",
        ] {
            assert!(probe_contract(url)
                .unwrap()
                .private_network_allowances
                .is_empty());
        }
        assert!(matches!(
            probe_get("http://100.100.100.200/"),
            Err(HttpEgressError::PrivateNetworkDenied { .. })
        ));
    }

    #[test]
    fn trailing_dot_authority_matches_its_contract() {
        let contract = probe_contract("http://localhost.:9100/metrics").unwrap();
        assert!(!contract.deny_loopback);
        assert!(contract.allowed_authority_set.contains("localhost:9100"));
        let contract = probe_contract("https://registry.example.com./v2/").unwrap();
        assert!(contract.deny_loopback);
        assert!(contract.allowed_authority_set.contains("registry.example.com"));
        assert!(contract
            .enforce_url("https://registry.example.com./v2/", 0)
            .is_ok());
    }
}
