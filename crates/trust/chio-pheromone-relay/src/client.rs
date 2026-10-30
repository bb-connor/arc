use crate::validation::is_loopback_host;
use crate::{
    sign_relay_http_request, PeerDirectory, PheromoneRelayError, RelayHttpSigningInput,
    RelayProfile, PHEROMONE_BATCH_RELAY_PATH,
};
use chio_core_types::canonical::UntrustedJsonError;
use chio_core_types::Keypair;
use chio_egress_contract::{
    client_builder_with_contract, send_with_contract, HttpEgressContract, HttpEgressError,
};
use chio_federation::pheromone_gossip::PheromoneGossipBatch;
use chio_pheromone_runtime::PheromoneReceiveReport;
use std::collections::BTreeSet;
use std::time::Duration;
use url::{Host, Url};

const RELAY_EGRESS_NAMESPACE: &str = "chio-pheromone-relay";
const TRANSPORT_FAILED: &str = "urn:chio:error:transport:http-failed";

pub struct PheromoneRelayClient {
    directory: PeerDirectory,
    keypair: Keypair,
    now_unix_ms: u64,
    freshness_window_ms: u64,
    profile: RelayProfile,
}

impl PheromoneRelayClient {
    #[must_use]
    pub fn new(
        directory: PeerDirectory,
        keypair: Keypair,
        now_unix_ms: u64,
        freshness_window_ms: u64,
        profile: RelayProfile,
    ) -> Self {
        Self {
            directory,
            keypair,
            now_unix_ms,
            freshness_window_ms,
            profile,
        }
    }

    pub async fn post_batch(
        &self,
        sender_kernel_id: &str,
        recipient_kernel_id: &str,
        batch: &PheromoneGossipBatch,
        nonce: &str,
    ) -> Result<PheromoneReceiveReport, PheromoneRelayError> {
        let url = self
            .directory
            .endpoint_for(recipient_kernel_id, PHEROMONE_BATCH_RELAY_PATH)?;
        let contract = peer_egress_contract(self.profile, &url)?;
        let request = sign_relay_http_request(RelayHttpSigningInput {
            sender_kernel_id,
            recipient_kernel_id,
            method: "POST",
            path: PHEROMONE_BATCH_RELAY_PATH,
            nonce,
            sent_at_unix_ms: self.now_unix_ms,
            payload: batch,
            keypair: &self.keypair,
        })?;
        let client = client_builder_with_contract(&contract)
            .timeout(Duration::from_millis(self.freshness_window_ms.max(1)))
            .build()
            .map_err(|_| transport_failure())?;
        let request = client
            .post(url.as_str())
            .json(&request)
            .build()
            .map_err(|_| transport_failure())?;
        let response = send_with_contract(&contract, &client, request)
            .await
            .map_err(egress_error)?;
        if !response.status().is_success() {
            let status = response.status();
            return Err(PheromoneRelayError::TransportError(format!(
                "relay POST failed with {status}"
            )));
        }
        crate::decode_delivery_report(response.body(), batch, Some(sender_kernel_id))
    }

    #[must_use]
    pub fn freshness_window_ms(&self) -> u64 {
        self.freshness_window_ms
    }
}

/// Production admits only HTTPS to the peer's exact authority, denies
/// loopback, link-local, unique-local and private targets after resolution,
/// and follows no redirects. LocalDev additionally admits plain HTTP and
/// loopback addresses for a peer whose endpoint names a loopback host.
fn peer_egress_contract(
    profile: RelayProfile,
    endpoint: &str,
) -> Result<HttpEgressContract, PheromoneRelayError> {
    let url = Url::parse(endpoint)
        .map_err(|error| PheromoneRelayError::EndpointDenied(error.to_string()))?;
    let host = match url.host() {
        Some(Host::Domain(domain)) => domain.trim_end_matches('.').to_ascii_lowercase(),
        Some(Host::Ipv4(address)) => address.to_string(),
        Some(Host::Ipv6(address)) => format!("[{address}]"),
        None => {
            return Err(PheromoneRelayError::EndpointDenied(
                "peer endpoint has no host".to_string(),
            ))
        }
    };
    let port = url.port_or_known_default().ok_or_else(|| {
        PheromoneRelayError::EndpointDenied("peer endpoint has no port".to_string())
    })?;
    let loopback_dev_peer = profile == RelayProfile::LocalDev && is_loopback_host(&url);
    let mut allowed_schemes = BTreeSet::from(["https".to_string()]);
    if loopback_dev_peer {
        allowed_schemes.insert("http".to_string());
    }
    Ok(HttpEgressContract {
        tenant_egress_namespace: RELAY_EGRESS_NAMESPACE.to_string(),
        allowed_schemes,
        allowed_authority_set: BTreeSet::from([format!("{host}:{port}")]),
        deny_loopback: !loopback_dev_peer,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: u64::try_from(crate::input::MAX_DOCUMENT_BYTES).unwrap_or(u64::MAX),
    })
}

fn egress_error(error: HttpEgressError) -> PheromoneRelayError {
    match error {
        HttpEgressError::Transport(_) | HttpEgressError::DnsResolutionFailed { .. } => {
            transport_failure()
        }
        HttpEgressError::ResponseTooLarge { observed, max } => UntrustedJsonError::TooLarge {
            bytes: usize::try_from(observed).unwrap_or(usize::MAX),
            bound: usize::try_from(max).unwrap_or(usize::MAX),
        }
        .into(),
        refused => PheromoneRelayError::EndpointDenied(refused.to_string()),
    }
}

fn transport_failure() -> PheromoneRelayError {
    PheromoneRelayError::TransportError(TRANSPORT_FAILED.to_string())
}
