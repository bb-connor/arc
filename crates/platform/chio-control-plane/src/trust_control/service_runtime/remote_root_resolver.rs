use std::io::Read as _;

use chio_core::canonical::canonical_json_bytes_from_str;
use chio_core::capability::aggregate_budget::{
    verify_direct_aggregate_root_record, AggregateFamilyRootResolution,
    AggregateFamilyRootResolutionError, AggregateFamilyRootResolver,
};
use chio_core::capability::token::CapabilityToken;
use chio_core::{canonical_json_bytes, Keypair};

use super::client::{build_client, path_with_encoded_param};
use super::*;

pub struct RemoteAggregateFamilyRootResolver {
    client: TrustControlClient,
    authority_trust: RemoteRootAuthorityTrust,
}

enum RemoteRootAuthorityTrust {
    Verified(Arc<super::remote_authority::RemoteControlAuthorityTrust>),
    Static(Box<PinnedControlAuthority>),
}

enum RemoteFetchError {
    Unavailable,
    Corrupt(String),
}

impl RemoteAggregateFamilyRootResolver {
    pub fn new(
        control_url: &str,
        control_token: &str,
        authority_trust: Arc<super::remote_authority::RemoteControlAuthorityTrust>,
    ) -> Result<Self, CliError> {
        Self::new_with_transport(
            control_url,
            control_token,
            RemoteRootAuthorityTrust::Verified(authority_trust),
            false,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        control_url: &str,
        control_token: &str,
        pinned_authority: PinnedControlAuthority,
    ) -> Result<Self, CliError> {
        Self::new_with_transport(
            control_url,
            control_token,
            RemoteRootAuthorityTrust::Static(Box::new(pinned_authority)),
            true,
        )
    }

    pub fn new_with_pinned_authority(
        control_url: &str,
        control_token: &str,
        pinned_authority: PinnedControlAuthority,
    ) -> Result<Self, CliError> {
        Self::new_with_transport(
            control_url,
            control_token,
            RemoteRootAuthorityTrust::Static(Box::new(pinned_authority)),
            false,
        )
    }

    fn new_with_transport(
        control_url: &str,
        control_token: &str,
        authority_trust: RemoteRootAuthorityTrust,
        allow_loopback_http: bool,
    ) -> Result<Self, CliError> {
        let client = build_client(control_url, control_token)?;
        for endpoint in client.endpoints.iter() {
            require_authenticated_lookup_transport(endpoint, allow_loopback_http)?;
        }
        Ok(Self {
            client,
            authority_trust,
        })
    }

    pub(crate) fn resolve_with_nonce(
        &self,
        root_capability_id: &str,
        nonce: &str,
    ) -> Result<AggregateFamilyRootResolution, AggregateFamilyRootResolutionError> {
        validate_lookup_nonce(nonce).map_err(AggregateFamilyRootResolutionError::Corrupt)?;
        if root_capability_id.is_empty()
            || root_capability_id.len() > AGGREGATE_FAMILY_ROOT_ID_MAX_BYTES
        {
            return Err(AggregateFamilyRootResolutionError::Corrupt(
                "aggregate family-root identifier is outside the supported bound".to_string(),
            ));
        }

        let mut corrupt = None;
        for index in self.client.endpoint_order() {
            let signed = match self.fetch_lookup(index, root_capability_id, nonce) {
                Ok(signed) => signed,
                Err(RemoteFetchError::Unavailable) => continue,
                Err(RemoteFetchError::Corrupt(error)) => {
                    corrupt = Some(error);
                    continue;
                }
            };
            let (current_signer, trusted_root_issuers) = match self.authority_keys() {
                Ok(keys) => keys,
                Err(error) => {
                    corrupt = Some(error);
                    continue;
                }
            };
            match verify_remote_lookup(
                &current_signer,
                &trusted_root_issuers,
                signed,
                root_capability_id,
                nonce,
            ) {
                Ok(resolution) => {
                    self.client.mark_preferred(index);
                    return Ok(resolution);
                }
                Err(AggregateFamilyRootResolutionError::Corrupt(error)) => {
                    corrupt = Some(error);
                }
                Err(AggregateFamilyRootResolutionError::Unavailable(_)) => {}
                Err(AggregateFamilyRootResolutionError::Missing) => {}
                Err(_) => {}
            }
        }

        if let Some(error) = corrupt {
            return Err(AggregateFamilyRootResolutionError::Corrupt(error));
        }

        Err(AggregateFamilyRootResolutionError::Unavailable(
            "no aggregate family-root authority endpoint completed the lookup".to_string(),
        ))
    }

    fn authority_keys(&self) -> Result<(PublicKey, Vec<PublicKey>), String> {
        match &self.authority_trust {
            RemoteRootAuthorityTrust::Verified(trust) => {
                let epoch = trust
                    .epoch_snapshot()
                    .map_err(|error| format!("verified authority epoch is unavailable: {error}"))?;
                Ok((epoch.public_key, epoch.trusted_public_keys))
            }
            RemoteRootAuthorityTrust::Static(pinned) => Ok((
                pinned.current_signer().clone(),
                pinned.trusted_root_issuers().to_vec(),
            )),
        }
    }

    fn fetch_lookup(
        &self,
        index: usize,
        root_capability_id: &str,
        nonce: &str,
    ) -> Result<SignedAggregateFamilyRootLookup, RemoteFetchError> {
        let path = path_with_encoded_param(
            AGGREGATE_FAMILY_ROOT_LOOKUP_PATH,
            "root_capability_id",
            root_capability_id,
        );
        let query = serde_urlencoded::to_string(AggregateFamilyRootLookupQuery {
            nonce: nonce.to_string(),
        })
        .map_err(|error| {
            RemoteFetchError::Corrupt(format!(
                "aggregate family-root lookup query encoding failed: {error}"
            ))
        })?;
        let url = format!("{}{}?{}", self.client.endpoints[index], path, query);
        let response = self
            .client
            .http
            .get(&url)
            .set(
                AUTHORIZATION.as_str(),
                &format!("Bearer {}", self.client.token),
            )
            .call()
            .map_err(|_| RemoteFetchError::Unavailable)?;
        let bytes = read_bounded_response(response, AGGREGATE_FAMILY_ROOT_LOOKUP_MAX_BYTES)?;
        decode_canonical_lookup(&bytes)
    }
}

impl AggregateFamilyRootResolver for RemoteAggregateFamilyRootResolver {
    fn resolve_aggregate_family_root(
        &self,
        root_capability_id: &str,
    ) -> Result<AggregateFamilyRootResolution, AggregateFamilyRootResolutionError> {
        let nonce = chio_core::sha256_hex(Keypair::generate().public_key().to_hex().as_bytes());
        self.resolve_with_nonce(root_capability_id, &nonce)
    }
}

pub fn build_remote_aggregate_family_root_resolver(
    control_url: &str,
    control_token: &str,
    authority_trust: Arc<super::remote_authority::RemoteControlAuthorityTrust>,
) -> Result<Arc<dyn AggregateFamilyRootResolver + Send + Sync>, CliError> {
    Ok(Arc::new(RemoteAggregateFamilyRootResolver::new(
        control_url,
        control_token,
        authority_trust,
    )?))
}

pub fn build_remote_aggregate_family_root_resolver_with_pinned_authority(
    control_url: &str,
    control_token: &str,
    pinned_authority: PinnedControlAuthority,
) -> Result<Arc<dyn AggregateFamilyRootResolver + Send + Sync>, CliError> {
    Ok(Arc::new(
        RemoteAggregateFamilyRootResolver::new_with_pinned_authority(
            control_url,
            control_token,
            pinned_authority,
        )?,
    ))
}

fn verify_remote_lookup(
    current_signer: &PublicKey,
    trusted_root_issuers: &[PublicKey],
    signed: SignedAggregateFamilyRootLookup,
    requested_root_capability_id: &str,
    nonce: &str,
) -> Result<AggregateFamilyRootResolution, AggregateFamilyRootResolutionError> {
    signed
        .verify_signature(current_signer)
        .map_err(AggregateFamilyRootResolutionError::Corrupt)?;
    if signed.body.request_nonce != nonce {
        return Err(AggregateFamilyRootResolutionError::Corrupt(
            "aggregate family-root lookup nonce mismatch".to_string(),
        ));
    }
    if signed.body.requested_root_capability_id != requested_root_capability_id {
        return Err(AggregateFamilyRootResolutionError::Corrupt(
            "aggregate family-root lookup identifier mismatch".to_string(),
        ));
    }
    let now = unix_timestamp_now();
    if signed.body.issued_at > now || signed.body.expires_at <= now {
        return Err(AggregateFamilyRootResolutionError::Corrupt(
            "aggregate family-root lookup response is outside its validity window".to_string(),
        ));
    }

    match signed.body.outcome {
        AggregateFamilyRootLookupOutcome::Found {
            canonical_token_json,
            token_digest,
            ..
        } => {
            if canonical_token_json.len() > chio_store_sqlite::MAX_AGGREGATE_FAMILY_ROOT_TOKEN_BYTES
            {
                return Err(AggregateFamilyRootResolutionError::Corrupt(
                    "aggregate family-root token exceeds its byte bound".to_string(),
                ));
            }
            let canonical =
                canonical_json_bytes_from_str(&canonical_token_json).map_err(|error| {
                    AggregateFamilyRootResolutionError::Corrupt(format!(
                        "aggregate family-root token is not strict I-JSON: {error}"
                    ))
                })?;
            if canonical.as_slice() != canonical_token_json.as_bytes() {
                return Err(AggregateFamilyRootResolutionError::Corrupt(
                    "aggregate family-root token is not canonical".to_string(),
                ));
            }
            if chio_store_sqlite::aggregate_family_root_token_digest(&canonical) != token_digest {
                return Err(AggregateFamilyRootResolutionError::Corrupt(
                    "aggregate family-root token digest mismatch".to_string(),
                ));
            }
            let token: CapabilityToken = serde_json::from_slice(&canonical).map_err(|error| {
                AggregateFamilyRootResolutionError::Corrupt(format!(
                    "aggregate family-root token cannot be decoded: {error}"
                ))
            })?;
            let typed_canonical = canonical_json_bytes(&token).map_err(|error| {
                AggregateFamilyRootResolutionError::Corrupt(format!(
                    "aggregate family-root token cannot be recanonicalized: {error}"
                ))
            })?;
            if typed_canonical != canonical {
                return Err(AggregateFamilyRootResolutionError::Corrupt(
                    "aggregate family-root token contains non-schema fields".to_string(),
                ));
            }
            if token.id != requested_root_capability_id {
                return Err(AggregateFamilyRootResolutionError::Corrupt(
                    "aggregate family-root token identifier mismatch".to_string(),
                ));
            }
            verify_direct_aggregate_root_record(&token, trusted_root_issuers).map_err(|error| {
                AggregateFamilyRootResolutionError::Corrupt(format!(
                    "aggregate family-root token authentication failed: {error}"
                ))
            })
        }
        AggregateFamilyRootLookupOutcome::Missing => {
            Err(AggregateFamilyRootResolutionError::Unavailable(
                "aggregate family-root authority did not provide a durable completeness proof"
                    .to_string(),
            ))
        }
        AggregateFamilyRootLookupOutcome::Corrupt { .. } => {
            Err(AggregateFamilyRootResolutionError::Corrupt(
                "aggregate family-root authority reported corrupt state".to_string(),
            ))
        }
    }
}

fn decode_canonical_lookup(
    bytes: &[u8],
) -> Result<SignedAggregateFamilyRootLookup, RemoteFetchError> {
    let raw = core::str::from_utf8(bytes).map_err(|error| {
        RemoteFetchError::Corrupt(format!(
            "aggregate family-root lookup response is not UTF-8: {error}"
        ))
    })?;
    let canonical = canonical_json_bytes_from_str(raw).map_err(|error| {
        RemoteFetchError::Corrupt(format!(
            "aggregate family-root lookup response is not strict I-JSON: {error}"
        ))
    })?;
    if canonical.as_slice() != bytes {
        return Err(RemoteFetchError::Corrupt(
            "aggregate family-root lookup response is not canonical".to_string(),
        ));
    }
    let signed: SignedAggregateFamilyRootLookup =
        serde_json::from_slice(&canonical).map_err(|error| {
            RemoteFetchError::Corrupt(format!(
                "aggregate family-root lookup response cannot be decoded: {error}"
            ))
        })?;
    let typed_canonical = canonical_json_bytes(&signed).map_err(|error| {
        RemoteFetchError::Corrupt(format!(
            "aggregate family-root lookup response cannot be recanonicalized: {error}"
        ))
    })?;
    if typed_canonical != canonical {
        return Err(RemoteFetchError::Corrupt(
            "aggregate family-root lookup response contains non-schema fields".to_string(),
        ));
    }
    Ok(signed)
}

fn read_bounded_response(response: ureq::Response, cap: u64) -> Result<Vec<u8>, RemoteFetchError> {
    let read_limit = cap.checked_add(1).ok_or_else(|| {
        RemoteFetchError::Corrupt("aggregate family-root response bound overflow".to_string())
    })?;
    let mut reader = response.into_reader().take(read_limit);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| RemoteFetchError::Unavailable)?;
    let length = u64::try_from(bytes.len()).map_err(|_| {
        RemoteFetchError::Corrupt("aggregate family-root response length overflow".to_string())
    })?;
    if length > cap {
        return Err(RemoteFetchError::Corrupt(format!(
            "aggregate family-root response exceeded the {cap}-byte bound"
        )));
    }
    Ok(bytes)
}

fn require_authenticated_lookup_transport(
    endpoint: &str,
    allow_loopback_http: bool,
) -> Result<(), CliError> {
    let parsed = Url::parse(endpoint).map_err(|error| {
        CliError::cli_other_error(format!(
            "aggregate family-root endpoint is invalid: {error}"
        ))
    })?;
    if parsed.scheme() == "https" {
        return Ok(());
    }
    let is_loopback = match parsed.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    if allow_loopback_http && parsed.scheme() == "http" && is_loopback {
        return Ok(());
    }
    Err(CliError::cli_other_error(
        "aggregate family-root resolution requires HTTPS".to_string(),
    ))
}
