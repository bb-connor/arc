//! Blocking ureq transport that dispatches only under an [`HttpEgressContract`].

use crate::{HttpEgressContract, HttpEgressError, PreparedHttpEgressContract, RequestFailure};
use std::error::Error;
use std::io::{self, Read};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// Name lookup for one host and port. Every address it returns still passes
/// the contract address checks before a socket opens.
pub type ContractLookup = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

/// The system resolver as a [`ContractLookup`].
#[must_use]
pub fn system_lookup() -> ContractLookup {
    Arc::new(|host: &str, port: u16| (host, port).to_socket_addrs().map(Iterator::collect))
}

/// Blocking HTTP agent whose only constructor is [`BlockingContractAgent::new`].
/// It never follows redirects, ignores proxy environment variables, checks
/// every request URL against the contract, and resolves through a resolver
/// that refuses hosts outside the contract and addresses in denied classes
/// before a socket opens.
#[derive(Debug, Clone)]
pub struct BlockingContractAgent {
    agent: ureq::Agent,
    prepared: PreparedHttpEgressContract,
}

impl BlockingContractAgent {
    /// `timeout` bounds connect, each read and each write. `deadline` bounds
    /// the request from connect through the last body byte. Name resolution
    /// runs before the deadline applies and is bounded only by the system
    /// resolver.
    pub fn new(
        contract: &HttpEgressContract,
        timeout: Duration,
        deadline: Duration,
    ) -> Result<Self, HttpEgressError> {
        Self::with_lookup(contract, timeout, deadline, system_lookup())
    }

    /// As [`Self::new`], resolving names through `lookup`.
    pub fn with_lookup(
        contract: &HttpEgressContract,
        timeout: Duration,
        deadline: Duration,
        lookup: ContractLookup,
    ) -> Result<Self, HttpEgressError> {
        let prepared = contract.prepare()?;
        prepared.validate_dispatchable_with_pinned_dns()?;
        let agent = ureq::AgentBuilder::new()
            .timeout(deadline)
            .timeout_connect(timeout)
            .timeout_read(timeout)
            .timeout_write(timeout)
            .redirects(0)
            .try_proxy_from_env(false)
            .resolver(ContractResolver {
                prepared: prepared.clone(),
                lookup,
            })
            .build();
        Ok(Self { agent, prepared })
    }

    pub fn get(&self, url: &str) -> Result<BlockingContractRequest, HttpEgressError> {
        self.request("GET", url)
    }

    pub fn post(&self, url: &str) -> Result<BlockingContractRequest, HttpEgressError> {
        self.request("POST", url)
    }

    fn request(&self, method: &str, url: &str) -> Result<BlockingContractRequest, HttpEgressError> {
        self.prepared.enforce_url(url, 0)?;
        Ok(BlockingContractRequest {
            request: self.agent.request(method, url),
            prepared: self.prepared.clone(),
        })
    }
}

/// A request whose URL passed the contract. Sending it reads the whole body
/// under the contract byte ceiling, whatever the status.
pub struct BlockingContractRequest {
    request: ureq::Request,
    prepared: PreparedHttpEgressContract,
}

impl std::fmt::Debug for BlockingContractRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BlockingContractRequest")
            .field("method", &self.request.method())
            .finish_non_exhaustive()
    }
}

impl BlockingContractRequest {
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.request = self.request.set(name, value);
        self
    }

    #[must_use]
    pub fn query(mut self, name: &str, value: &str) -> Self {
        self.request = self.request.query(name, value);
        self
    }

    pub fn call(self) -> Result<BlockingContractResponse, HttpEgressError> {
        collect_capped_response(&self.prepared, self.request.call())
    }

    pub fn send_bytes(self, body: &[u8]) -> Result<BlockingContractResponse, HttpEgressError> {
        collect_capped_response(&self.prepared, self.request.send_bytes(body))
    }
}

/// Status and body of a contract dispatch. A redirect status is returned
/// unfollowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockingContractResponse {
    status: u16,
    body: Vec<u8>,
}

impl BlockingContractResponse {
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

fn collect_capped_response(
    prepared: &PreparedHttpEgressContract,
    outcome: Result<ureq::Response, ureq::Error>,
) -> Result<BlockingContractResponse, HttpEgressError> {
    let response = match outcome {
        Ok(response) | Err(ureq::Error::Status(_, response)) => response,
        Err(ureq::Error::Transport(transport)) => return Err(transport_failure(transport)),
    };
    let status = response.status();
    let mut body = Vec::new();
    response
        .into_reader()
        .take(prepared.max_response_bytes().saturating_add(1))
        .read_to_end(&mut body)
        .map_err(RequestFailure::new)?;
    prepared.enforce_response_bytes(u64::try_from(body.len()).unwrap_or(u64::MAX))?;
    Ok(BlockingContractResponse { status, body })
}

fn transport_failure(transport: ureq::Transport) -> HttpEgressError {
    contract_refusal(&transport).unwrap_or_else(|| RequestFailure::new(transport).into())
}

/// The resolver reports a refusal through `io::Error`, which ureq keeps as
/// the transport source.
fn contract_refusal(error: &(dyn Error + 'static)) -> Option<HttpEgressError> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(refusal) = error.downcast_ref::<HttpEgressError>() {
            return Some(refusal.clone());
        }
        if let Some(refusal) = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .and_then(|inner| inner.downcast_ref::<HttpEgressError>())
        {
            return Some(refusal.clone());
        }
        current = error.source();
    }
    None
}

struct ContractResolver {
    prepared: PreparedHttpEgressContract,
    lookup: ContractLookup,
}

impl ureq::Resolver for ContractResolver {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        resolve_with_contract(&self.prepared, &self.lookup, netloc)
            .map_err(|refusal| io::Error::new(io::ErrorKind::PermissionDenied, refusal))
    }
}

fn resolve_with_contract(
    prepared: &PreparedHttpEgressContract,
    lookup: &ContractLookup,
    netloc: &str,
) -> Result<Vec<SocketAddr>, HttpEgressError> {
    let (host, port) = netloc
        .rsplit_once(':')
        .ok_or(HttpEgressError::MissingAuthority)?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = port
        .parse::<u16>()
        .map_err(|error| HttpEgressError::InvalidUrl(error.to_string()))?;
    prepared.enforce_resolver_hostname(host)?;
    let addresses = lookup(host, port).map_err(|error| HttpEgressError::DnsResolutionFailed {
        host: host.to_string(),
        details: error.to_string(),
    })?;
    enforce_resolved_addresses(prepared, host, addresses)
}

/// Every address in the answer must pass, so one private record refuses the
/// host.
fn enforce_resolved_addresses(
    prepared: &PreparedHttpEgressContract,
    host: &str,
    addresses: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, HttpEgressError> {
    if addresses.is_empty() {
        return Err(HttpEgressError::DnsResolutionFailed {
            host: host.to_string(),
            details: "resolver returned no addresses".to_string(),
        });
    }
    for address in &addresses {
        prepared
            .contract()
            .enforce_resolved_ip(host, address.ip())?;
    }
    Ok(addresses)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "ureq_helper_tests.rs"]
mod tests;
