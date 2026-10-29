use std::collections::BTreeSet;

use chio_egress_contract::HttpEgressContract;
use url::Url;

pub(crate) fn strict_https_contract(
    endpoint: &Url,
    namespace: &str,
    max_response_bytes: u64,
) -> Result<HttpEgressContract, String> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| "anchor URL must include a host".to_owned())?;
    let normalized_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host.to_ascii_lowercase())
    } else {
        host.trim_end_matches('.').to_ascii_lowercase()
    };
    let authority = match endpoint.port() {
        Some(port) => format!("{normalized_host}:{port}"),
        None => normalized_host,
    };
    let contract = HttpEgressContract {
        tenant_egress_namespace: namespace.to_owned(),
        allowed_schemes: BTreeSet::from(["https".to_owned()]),
        allowed_authority_set: BTreeSet::from([authority]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes,
    };
    contract
        .validate_dispatchable_with_pinned_dns()
        .map_err(|error| error.to_string())?;
    contract
        .enforce_url(endpoint.as_str(), 0)
        .map_err(|error| error.to_string())?;
    Ok(contract)
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::io::ErrorKind;
    use std::net::{SocketAddr, TcpListener};

    use chio_egress_contract::ContractLookup;

    /// A lookup that answers every name with `addr`.
    pub(crate) fn answer_with(addr: SocketAddr) -> ContractLookup {
        ContractLookup::new(move |_host: &str, _port: u16| Ok(vec![addr]))
    }

    /// A loopback listener that never accepts. The kernel still completes and
    /// queues any TCP handshake, so `connected` sees every dial that reached it.
    pub(crate) struct SilentListener {
        listener: TcpListener,
        addr: SocketAddr,
    }

    impl SilentListener {
        pub(crate) fn bind() -> Result<Self, String> {
            let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
            let addr = listener.local_addr().map_err(|error| error.to_string())?;
            Ok(Self { listener, addr })
        }

        pub(crate) fn addr(&self) -> SocketAddr {
            self.addr
        }

        pub(crate) fn connected(&self) -> Result<bool, String> {
            self.listener
                .set_nonblocking(true)
                .map_err(|error| error.to_string())?;
            match self.listener.accept() {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(false),
                Err(error) => Err(error.to_string()),
            }
        }
    }
}

#[cfg(test)]
#[path = "anchor_egress_tests.rs"]
mod tests;
