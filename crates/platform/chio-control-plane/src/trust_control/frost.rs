use std::time::Duration;

use chio_egress_contract::{system_lookup, ContractLookup};
use chio_federation::frost::{
    FrostAnchorError, FrostAnchoredAuthorizationSlot, FrostAuthorizationSlotAnchor,
    FrostAuthorizationSlotAnchorWriter, FrostEpochAnchor, FrostEpochAnchorWriter,
    FrostEpochCheckpointV1, VerifiedFrostAuthorizationSlotBind, VerifiedFrostAuthorizationSlotBurn,
    VerifiedFrostAuthorizationSlotCompletion, VerifiedFrostEpochAdvance,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use url::Url;

use crate::anchor_egress::{AnchorClient, AnchorHttpError};

#[path = "frost/coordinator.rs"]
mod coordinator;

pub use coordinator::*;

const MAX_ANCHOR_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct RemoteFrostAnchorConfig {
    pub base_url: String,
    pub bearer_token: String,
    pub timeout: Duration,
}

impl std::fmt::Debug for RemoteFrostAnchorConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteFrostAnchorConfig")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteFrostAnchorConfigError {
    #[error("invalid FROST anchor URL: {0}")]
    Url(String),
    #[error("FROST anchor URL must use HTTPS")]
    InsecureTransport,
    #[error("FROST anchor URL must not contain credentials, query, or fragment")]
    AmbiguousUrl,
    #[error("FROST anchor bearer token is invalid")]
    InvalidToken,
    #[error("FROST anchor timeout must be non-zero")]
    InvalidTimeout,
    #[error("invalid FROST anchor HTTP egress contract: {0}")]
    InvalidEgressContract(String),
}

#[derive(Clone)]
pub struct RemoteFrostAnchorClient {
    http: AnchorClient,
    base_url: Url,
}

impl std::fmt::Debug for RemoteFrostAnchorClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteFrostAnchorClient")
            .field("base_url", &self.base_url)
            .field("http", &self.http)
            .finish()
    }
}

impl RemoteFrostAnchorClient {
    pub fn new(config: RemoteFrostAnchorConfig) -> Result<Self, RemoteFrostAnchorConfigError> {
        Self::with_lookup(config, system_lookup())
    }

    fn with_lookup(
        config: RemoteFrostAnchorConfig,
        lookup: ContractLookup,
    ) -> Result<Self, RemoteFrostAnchorConfigError> {
        let base_url = Url::parse(&config.base_url)
            .map_err(|error| RemoteFrostAnchorConfigError::Url(error.to_string()))?;
        if base_url.scheme() != "https" {
            return Err(RemoteFrostAnchorConfigError::InsecureTransport);
        }
        if base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(RemoteFrostAnchorConfigError::AmbiguousUrl);
        }
        if config.bearer_token.is_empty()
            || config.bearer_token.trim() != config.bearer_token
            || config
                .bearer_token
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(RemoteFrostAnchorConfigError::InvalidToken);
        }
        if config.timeout.is_zero() {
            return Err(RemoteFrostAnchorConfigError::InvalidTimeout);
        }
        let http = AnchorClient::new(
            &base_url,
            "control-plane.frost-anchor",
            crate::integer::count(MAX_ANCHOR_RESPONSE_BYTES),
            &config.bearer_token,
            config.timeout,
            lookup,
        )
        .map_err(RemoteFrostAnchorConfigError::InvalidEgressContract)?;
        Ok(Self { http, base_url })
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, FrostAnchorError> {
        let mut url = self.base_url.clone();
        let mut path = url.path_segments_mut().map_err(|()| {
            FrostAnchorError::InvalidResponse("anchor URL cannot carry path segments".to_string())
        })?;
        path.pop_if_empty();
        path.extend(segments.iter().copied());
        drop(path);
        Ok(url)
    }

    fn get_json<T: DeserializeOwned>(&self, url: Url) -> Result<T, FrostAnchorError> {
        decode_response(&self.http.get(url.as_str()).map_err(anchor_error)?)
    }

    fn post_json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        url: Url,
        body: &B,
    ) -> Result<T, FrostAnchorError> {
        let body = serde_json::to_vec(body).map_err(|error| {
            FrostAnchorError::Unavailable(format!("anchor request encoding failed: {error}"))
        })?;
        decode_response(
            &self
                .http
                .post_json(url.as_str(), &body)
                .map_err(anchor_error)?,
        )
    }
}

impl FrostEpochAnchor for RemoteFrostAnchorClient {
    fn resolve_epoch_checkpoint(
        &self,
        scope_id: &str,
    ) -> Result<FrostEpochCheckpointV1, FrostAnchorError> {
        self.get_json(self.endpoint(&["v1", "frost", "epochs", scope_id])?)
    }
}

impl FrostEpochAnchorWriter for RemoteFrostAnchorClient {
    fn compare_and_swap_epoch(
        &self,
        expected_checkpoint_digest: &str,
        advance: &VerifiedFrostEpochAdvance,
    ) -> Result<FrostEpochCheckpointV1, FrostAnchorError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Request<'a> {
            namespace: &'static str,
            expected_checkpoint_digest: &'a str,
            predecessor: &'a FrostEpochCheckpointV1,
            target_roster: &'a chio_federation::frost::FrostRosterV1,
            rotation_authorization_digest: &'a str,
            burn_summary: &'a chio_federation::frost::FrostSessionBurnSummaryV1,
            activation_fence: u64,
            clock_high_water: u64,
        }

        self.post_json(
            self.endpoint(&[
                "v1",
                "frost",
                "epochs",
                &advance.target_roster().scope_id,
                "compare-and-swap",
            ])?,
            &Request {
                namespace: "epoch",
                expected_checkpoint_digest,
                predecessor: advance.predecessor(),
                target_roster: advance.target_roster(),
                rotation_authorization_digest: advance.rotation_authorization_digest(),
                burn_summary: advance.burn_summary(),
                activation_fence: advance.activation_fence(),
                clock_high_water: advance.clock_high_water(),
            },
        )
    }
}

impl FrostAuthorizationSlotAnchor for RemoteFrostAnchorClient {
    fn resolve_authorization_slot(
        &self,
        scope_id: &str,
        slot_id: &str,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        self.get_json(self.endpoint(&["v1", "frost", "authorization-slots", scope_id, slot_id])?)
    }
}

impl FrostAuthorizationSlotAnchorWriter for RemoteFrostAnchorClient {
    fn compare_and_swap_bind(
        &self,
        bind: &VerifiedFrostAuthorizationSlotBind,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        self.post_json(
            self.endpoint(&[
                "v1",
                "frost",
                "authorization-slots",
                bind.request().scope_id(),
                bind.request().slot_id(),
                "bind",
            ])?,
            bind.request(),
        )
    }

    fn compare_and_swap_complete(
        &self,
        completion: &VerifiedFrostAuthorizationSlotCompletion,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        self.post_json(
            self.endpoint(&[
                "v1",
                "frost",
                "authorization-slot-transitions",
                completion.request().expected_bound_checkpoint_digest(),
                "complete",
            ])?,
            completion.request(),
        )
    }

    fn compare_and_swap_burn(
        &self,
        burn: &VerifiedFrostAuthorizationSlotBurn,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError> {
        self.post_json(
            self.endpoint(&[
                "v1",
                "frost",
                "authorization-slot-transitions",
                burn.request().expected_bound_checkpoint_digest(),
                "burn",
            ])?,
            burn.request(),
        )
    }
}

fn decode_response<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, FrostAnchorError> {
    chio_core::canonical::UntrustedJsonText::from_wire(bytes, MAX_ANCHOR_RESPONSE_BYTES)
        .and_then(|input| input.decode_signed())
        .map_err(|error| FrostAnchorError::UntrustedInput(error.into()))
}

fn anchor_error(error: AnchorHttpError) -> FrostAnchorError {
    match error {
        AnchorHttpError::Egress(
            error @ chio_egress_contract::HttpEgressError::ResponseTooLarge { .. },
        ) => FrostAnchorError::InvalidResponse(error.to_string()),
        error => FrostAnchorError::Unavailable(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor_egress::test_support::{answer_with, SilentListener};

    #[test]
    fn anchor_name_answering_loopback_is_refused_before_connecting() -> Result<(), String> {
        let listener = SilentListener::bind()?;
        let client = RemoteFrostAnchorClient::with_lookup(
            RemoteFrostAnchorConfig {
                base_url: "https://anchor.example/api".to_string(),
                bearer_token: "token".to_string(),
                timeout: Duration::from_secs(5),
            },
            answer_with(listener.addr()),
        )
        .map_err(|error| error.to_string())?;

        let error = match client.resolve_epoch_checkpoint("scope-1") {
            Ok(checkpoint) => return Err(format!("loopback answer was dialed: {checkpoint:?}")),
            Err(error) => error,
        };

        assert!(
            matches!(
                error,
                FrostAnchorError::Unavailable(ref details)
                    if details == "loopback egress target denied: anchor.example resolved to 127.0.0.1"
            ),
            "{error:?}"
        );
        assert!(!listener.connected()?);
        Ok(())
    }

    #[test]
    fn production_client_requires_https_auth_and_timeout() {
        for config in [
            RemoteFrostAnchorConfig {
                base_url: "http://anchor.example".to_string(),
                bearer_token: "token".to_string(),
                timeout: Duration::from_secs(1),
            },
            RemoteFrostAnchorConfig {
                base_url: "https://anchor.example".to_string(),
                bearer_token: String::new(),
                timeout: Duration::from_secs(1),
            },
            RemoteFrostAnchorConfig {
                base_url: "https://anchor.example".to_string(),
                bearer_token: "token".to_string(),
                timeout: Duration::ZERO,
            },
        ] {
            assert!(RemoteFrostAnchorClient::new(config).is_err());
        }
        assert!(RemoteFrostAnchorClient::new(RemoteFrostAnchorConfig {
            base_url: "https://anchor.example/api".to_string(),
            bearer_token: "token".to_string(),
            timeout: Duration::from_secs(1),
        })
        .is_ok());
    }
}
