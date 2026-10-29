//! Egress contract for the doctor network probes.
//!
//! A probe targets one user-configured URL. The contract admits exactly that
//! authority, never follows redirects, ignores proxy variables, pins the
//! resolved addresses and refuses link-local answers. The operator named the
//! target, so a private-network authority is admitted; loopback and
//! unique-local answers are refused unless the configured host is one.

use std::time::Duration;

use chio_egress_contract::{
    BlockingContractAgent, BlockingContractResponse, HttpEgressContract, HttpEgressError,
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_DEADLINE: Duration = Duration::from_secs(10);
/// Ceiling on the probe response body. A registry `/v2/` answer is empty or a
/// short JSON error, and the gauge probe reads one metrics exposition; a body
/// above this is refused by the contract and reported as a policy refusal.
const MAX_PROBE_BODY_BYTES: u64 = 1024 * 1024;

/// True when the contract refused the target, as opposed to the target being
/// unreachable: a scheme, authority, address-class or size refusal.
pub(super) fn is_policy_refusal(error: &HttpEgressError) -> bool {
    !matches!(
        error,
        HttpEgressError::Transport(_) | HttpEgressError::DnsResolutionFailed { .. }
    )
}

/// GET `url` under a contract that admits only its own authority.
pub(super) fn probe_get(url: &str) -> Result<BlockingContractResponse, HttpEgressError> {
    let contract = HttpEgressContract::for_configured_url("chio-doctor", url, MAX_PROBE_BODY_BYTES)?;
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
mod tests {
    use super::*;

    #[test]
    fn link_local_target_is_refused_as_link_local() {
        assert!(matches!(
            probe_get("http://169.254.169.254/latest/meta-data"),
            Err(HttpEgressError::LinkLocalDenied { .. })
        ));
    }

    #[test]
    fn private_network_target_is_admitted_by_the_contract() {
        for url in ["http://10.0.0.5:9100/metrics", "http://100.64.0.1/"] {
            let Ok(contract) = HttpEgressContract::for_configured_url("chio-doctor", url, 64)
            else {
                panic!("contract for {url}");
            };
            assert!(contract.enforce_url(url, 0).is_ok(), "{url}");
        }
    }
}
