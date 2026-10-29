//! Egress contract for the doctor network probes.
//!
//! A probe targets one user-configured URL. The contract admits exactly that
//! authority, never follows redirects, ignores proxy variables, pins the
//! resolved addresses and refuses link-local and unique-local answers. A
//! non-loopback authority also refuses loopback answers.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use chio_egress_contract::{
    BlockingContractAgent, BlockingContractResponse, HttpEgressContract, HttpEgressError,
};
use url::{Host, Url};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_DEADLINE: Duration = Duration::from_secs(10);
const MAX_PROBE_BODY_BYTES: u64 = 1024 * 1024;

fn probe_contract(url: &str) -> Result<HttpEgressContract, HttpEgressError> {
    let parsed = Url::parse(url)
        .map_err(|err| HttpEgressError::InvalidContract(format!("invalid probe url: {err}")))?;
    let host = parsed
        .host()
        .ok_or_else(|| HttpEgressError::InvalidContract("probe url has no host".to_string()))?;
    let loopback = match &host {
        Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => IpAddr::V4(*address).is_loopback(),
        Host::Ipv6(address) => IpAddr::V6(*address).is_loopback(),
    };
    let authority = match (host, parsed.port()) {
        (Host::Ipv6(address), Some(port)) => format!("[{address}]:{port}"),
        (Host::Ipv6(address), None) => format!("[{address}]"),
        (host, Some(port)) => format!("{host}:{port}").to_ascii_lowercase(),
        (host, None) => host.to_string().to_ascii_lowercase(),
    };
    Ok(HttpEgressContract {
        tenant_egress_namespace: "chio-doctor".to_string(),
        allowed_schemes: BTreeSet::from([parsed.scheme().to_string()]),
        allowed_authority_set: BTreeSet::from([authority]),
        deny_loopback: !loopback,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: MAX_PROBE_BODY_BYTES,
    })
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
