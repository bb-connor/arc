use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use chio_egress_contract::{
    BlockingContractAgent, BlockingContractRequest, BlockingContractResponse, ContractLookup,
    HttpEgressContract, HttpEgressError,
};
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
        private_network_allowances: Default::default(),
    };
    contract
        .validate_dispatchable_with_pinned_dns()
        .map_err(|error| error.to_string())?;
    contract
        .enforce_url(endpoint.as_str(), 0)
        .map_err(|error| error.to_string())?;
    Ok(contract)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AnchorHttpError {
    #[error(transparent)]
    Egress(#[from] HttpEgressError),
    #[error("anchor returned HTTP {0}")]
    Status(u16),
}

/// Bearer-authenticated client for one operator-configured HTTPS anchor. Each
/// request resolves the anchor name again, checks every address in that
/// answer against the strict contract and dials only those addresses, so an
/// anchor whose addresses rotate stays reachable. Redirects are never followed
/// and proxy environment variables are ignored.
#[derive(Clone)]
pub(crate) struct AnchorClient {
    contract: HttpEgressContract,
    timeout: Duration,
    lookup: ContractLookup,
    authorization: Arc<str>,
}

impl std::fmt::Debug for AnchorClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AnchorClient")
            .field("contract", &self.contract)
            .field("timeout", &self.timeout)
            .field("authorization", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl AnchorClient {
    /// `timeout` bounds each request from name resolution through the last
    /// body byte.
    pub(crate) fn new(
        endpoint: &Url,
        namespace: &str,
        max_response_bytes: u64,
        bearer_token: &str,
        timeout: Duration,
        lookup: ContractLookup,
    ) -> Result<Self, String> {
        let contract = strict_https_contract(endpoint, namespace, max_response_bytes)?;
        Self::with_contract(contract, bearer_token, timeout, lookup)
    }

    fn with_contract(
        contract: HttpEgressContract,
        bearer_token: &str,
        timeout: Duration,
        lookup: ContractLookup,
    ) -> Result<Self, String> {
        let client = Self {
            contract,
            timeout,
            lookup,
            authorization: Arc::from(format!("Bearer {bearer_token}")),
        };
        client.agent().map_err(|error| error.to_string())?;
        Ok(client)
    }

    /// A fresh agent, so the addresses it pins serve one request only.
    fn agent(&self) -> Result<BlockingContractAgent, HttpEgressError> {
        BlockingContractAgent::with_lookup(
            &self.contract,
            self.timeout,
            self.timeout,
            self.lookup.clone(),
        )
    }

    pub(crate) fn get(&self, url: &str) -> Result<Vec<u8>, AnchorHttpError> {
        let request = self.agent()?.get(url)?;
        successful_body(self.authorized(request).call()?)
    }

    pub(crate) fn post_json(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, AnchorHttpError> {
        let request = self
            .authorized(self.agent()?.post(url)?)
            .header("Content-Type", "application/json");
        successful_body(request.send_bytes(body)?)
    }

    fn authorized(&self, request: BlockingContractRequest) -> BlockingContractRequest {
        request.header("Authorization", &self.authorization)
    }
}

fn successful_body(response: BlockingContractResponse) -> Result<Vec<u8>, AnchorHttpError> {
    if !(200..300).contains(&response.status()) {
        return Err(AnchorHttpError::Status(response.status()));
    }
    Ok(response.body().to_vec())
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
