//! JWKS retrieval through the HTTP egress contract.

use std::time::Duration;

use chio_core::root_authority::HttpsUrl;
use chio_egress_contract::{
    client_builder_with_contract, send_with_contract, ContractClient, HttpEgressContract,
    HttpEgressError,
};

use super::MAX_JWKS_DOCUMENT_BYTES;

const JWKS_FETCH_TIMEOUT_SECS: u64 = 10;

/// Why a JWKS fetch produced no document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwksFetchError {
    #[error("JWKS fetch refused by the egress contract: {0}")]
    Egress(#[from] HttpEgressError),
    #[error("JWKS endpoint answered HTTP {0}")]
    Status(u16),
    #[error("JWKS HTTP client could not be built")]
    Client,
}

/// Retrieves the raw JWKS document published at a pinned URL.
#[async_trait::async_trait]
pub trait JwksFetcher: Send + Sync {
    async fn fetch(&self, url: &HttpsUrl) -> Result<Vec<u8>, JwksFetchError>;
}

/// The production fetcher: `https` only, redirects and body size bounded by
/// the egress contract, and the body capped at [`MAX_JWKS_DOCUMENT_BYTES`].
pub struct ContractJwksFetcher {
    contract: HttpEgressContract,
    client: ContractClient,
}

impl ContractJwksFetcher {
    /// Narrow `contract` to `https` and the JWKS size cap, then build its client.
    pub fn new(mut contract: HttpEgressContract) -> Result<Self, JwksFetchError> {
        contract.allowed_schemes.retain(|scheme| scheme == "https");
        contract.max_response_bytes = contract
            .max_response_bytes
            .min(MAX_JWKS_DOCUMENT_BYTES as u64);
        contract.validate()?;
        let client = client_builder_with_contract(&contract)
            .timeout(Duration::from_secs(JWKS_FETCH_TIMEOUT_SECS))
            .build()
            .map_err(|_| JwksFetchError::Client)?;
        Ok(Self { contract, client })
    }
}

#[async_trait::async_trait]
impl JwksFetcher for ContractJwksFetcher {
    async fn fetch(&self, url: &HttpsUrl) -> Result<Vec<u8>, JwksFetchError> {
        let request = self
            .client
            .get(url.as_str())
            .build()
            .map_err(|_| JwksFetchError::Client)?;
        let response = send_with_contract(&self.contract, &self.client, request).await?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(JwksFetchError::Status(status));
        }
        Ok(response.body().to_vec())
    }
}
