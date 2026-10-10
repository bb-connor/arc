//! Bounded health probes for trusted operator configuration, not agent tool egress.

use std::time::Duration;

const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// One immutable, operator-selected HTTP GET readiness target.
///
/// This host-management profile permits private service addresses. It is not a
/// tenant egress policy and must never authorize an agent-selected destination.
/// Preparation fixes the URL and bearer; probing accepts no replacement client,
/// target, method or body and returns no response data. Redirects and proxies
/// are disabled, and DNS, transport and body reads share a two-second timeout.
pub struct OperatorReadinessProbe {
    client: reqwest::Client,
    request: reqwest::Request,
}

/// Invalid operator configuration is rejected before a service is launched.
#[derive(Debug, thiserror::Error)]
pub enum OperatorReadinessError {
    #[error("readiness requires an HTTP(S) URL with a nonzero port and no userinfo or fragment")]
    InvalidTarget,
    #[error("the readiness HTTP client or request could not be built: {0}")]
    Client(#[from] reqwest::Error),
}

impl OperatorReadinessProbe {
    /// Validate and retain a trusted operator's target and optional bearer.
    pub fn prepare(raw_url: &str, bearer: Option<&str>) -> Result<Self, OperatorReadinessError> {
        let url =
            reqwest::Url::parse(raw_url).map_err(|_| OperatorReadinessError::InvalidTarget)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.port() == Some(0)
        {
            return Err(OperatorReadinessError::InvalidTarget);
        }
        let client = client_builder().build()?;
        let mut request = client.get(url);
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        Ok(Self {
            client,
            request: request.build()?,
        })
    }

    /// Return readiness only for a complete success response no larger than 64 KiB.
    /// Transport, timeout, redirect and body errors all deny readiness.
    pub async fn probe(&self) -> bool {
        let Some(request) = self.request.try_clone() else {
            return false;
        };
        let Ok(mut response) = self.client.execute(request).await else {
            return false;
        };
        if response.url() != self.request.url() || !response.status().is_success() {
            return false;
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE_BYTES)
        {
            return false;
        }
        let mut observed = 0_u64;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let Some(size) = observed.checked_add(chunk.len() as u64) else {
                        return false;
                    };
                    if size > MAX_RESPONSE_BYTES {
                        return false;
                    }
                    observed = size;
                }
                Ok(None) => return true,
                Err(_) => return false,
            }
        }
    }
}

fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PROBE_TIMEOUT)
}

#[cfg(test)]
#[path = "operator_readiness_tests.rs"]
mod tests;
