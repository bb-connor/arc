//! Bearer-authenticated JSON posts to one operator-configured endpoint.

use std::fmt;
use std::time::Duration;

use chio_egress_contract::{
    BlockingContractAgent, BlockingContractResponse, ContractLookup, HttpEgressContract,
    HttpEgressError,
};
use zeroize::Zeroizing;

/// Each post resolves the endpoint name again, checks every address in that
/// answer against the contract and dials only those addresses, so an endpoint
/// whose addresses rotate stays reachable and a rotated answer is still
/// checked. Redirects are returned unfollowed and proxy environment variables
/// are ignored.
pub(super) struct RemoteJsonClient {
    contract: HttpEgressContract,
    base_url: String,
    authorization: Zeroizing<String>,
    timeout: Duration,
    lookup: ContractLookup,
}

impl fmt::Debug for RemoteJsonClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteJsonClient")
            .field("contract", &self.contract)
            .field("base_url", &self.base_url)
            .field("authorization", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl RemoteJsonClient {
    /// `timeout` bounds each post from name resolution through the last body
    /// byte.
    pub(super) fn new(
        contract: HttpEgressContract,
        base_url: &str,
        bearer_token: &str,
        timeout: Duration,
        lookup: ContractLookup,
    ) -> Result<Self, HttpEgressError> {
        let client = Self {
            contract,
            base_url: base_url.trim_end_matches('/').to_owned(),
            authorization: Zeroizing::new(format!("Bearer {bearer_token}")),
            timeout,
            lookup,
        };
        client.agent()?;
        Ok(client)
    }

    /// A fresh agent, so the addresses it pins serve one post only.
    fn agent(&self) -> Result<BlockingContractAgent, HttpEgressError> {
        BlockingContractAgent::with_lookup(
            &self.contract,
            self.timeout,
            self.timeout,
            self.lookup.clone(),
        )
    }

    /// The response to `body` posted at `path` under the base URL, read
    /// under the contract response ceiling whatever its status.
    pub(super) fn post_json(
        &self,
        path: &str,
        body: &[u8],
    ) -> Result<BlockingContractResponse, HttpEgressError> {
        self.agent()?
            .post(&format!("{}{path}", self.base_url))?
            .header("Authorization", &self.authorization)
            .header("Content-Type", "application/json")
            .send_bytes(body)
    }
}

/// The media type of `response` without parameters.
pub(super) fn media_type(response: &BlockingContractResponse) -> Option<&str> {
    response
        .header("content-type")
        .and_then(|value| value.split(';').next())
        .map(str::trim)
}

/// Whether `error` is a reachability failure that a later post may not
/// repeat, as opposed to a contract refusal.
pub(super) fn unreachable(error: &HttpEgressError) -> bool {
    matches!(
        error,
        HttpEgressError::Transport(_) | HttpEgressError::DnsResolutionFailed { .. }
    )
}
