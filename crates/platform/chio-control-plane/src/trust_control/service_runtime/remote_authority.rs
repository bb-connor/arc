use std::io::Read as _;

use chio_core::canonical::canonical_json_bytes_from_str;

use super::client::build_client;
use super::*;

const AUTHORITY_STATUS_MAX_BYTES: u64 = 64 * 1024;

pub fn build_remote_capability_authority(
    control_url: &str,
    control_token: &str,
    pinned_authority: PinnedControlAuthority,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    build_remote_capability_authority_with_transport(
        control_url,
        control_token,
        pinned_authority,
        false,
    )
}

#[cfg(test)]
pub(crate) fn build_remote_capability_authority_for_test(
    control_url: &str,
    control_token: &str,
    pinned_authority: PinnedControlAuthority,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    build_remote_capability_authority_with_transport(
        control_url,
        control_token,
        pinned_authority,
        true,
    )
}

fn build_remote_capability_authority_with_transport(
    control_url: &str,
    control_token: &str,
    pinned_authority: PinnedControlAuthority,
    allow_loopback_http: bool,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    let mut client = build_client(control_url, control_token)?;
    for endpoint in client.endpoints.iter() {
        require_authenticated_authority_transport(endpoint, allow_loopback_http)?;
    }
    client.http = ureq::AgentBuilder::new()
        .timeout(CONTROL_HTTP_TIMEOUT)
        .redirects(0)
        .https_only(!allow_loopback_http)
        .build();
    validate_pinned_status_at_any_endpoint(&client, pinned_authority.current_signer())?;
    Ok(Box::new(RemoteCapabilityAuthority {
        client,
        pinned_current: pinned_authority.current_signer().clone(),
    }))
}

fn validate_pinned_status_at_any_endpoint(
    client: &TrustControlClient,
    pinned_current: &PublicKey,
) -> Result<(), CliError> {
    let mut last_error = None;
    for index in client.endpoint_order() {
        let result = fetch_authority_status(client, index)
            .and_then(|status| validate_current_authority_pin(&status, pinned_current));
        match result {
            Ok(()) => {
                client.mark_preferred(index);
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        CliError::cli_other_error(
            "no remote capability authority endpoint matched the current pin".to_string(),
        )
    }))
}

fn fetch_authority_status(
    client: &TrustControlClient,
    index: usize,
) -> Result<TrustAuthorityStatus, CliError> {
    let url = format!("{}{}", client.endpoints[index], AUTHORITY_PATH);
    let response = client
        .http
        .get(&url)
        .set(AUTHORIZATION.as_str(), &format!("Bearer {}", client.token))
        .call()
        .map_err(|_| {
            CliError::cli_other_error(
                "remote capability authority status endpoint is unavailable".to_string(),
            )
        })?;
    let bytes = read_bounded_body(response, AUTHORITY_STATUS_MAX_BYTES).map_err(|reason| {
        CliError::cli_other_error(format!(
            "remote capability authority status is invalid: {reason}"
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        CliError::cli_other_error(
            "remote capability authority status cannot be decoded".to_string(),
        )
    })
}

fn validate_current_authority_pin(
    status: &TrustAuthorityStatus,
    pinned_current: &PublicKey,
) -> Result<(), CliError> {
    if !status.configured {
        return Err(CliError::cli_other_error(
            "trust control service does not have an authority configured".to_string(),
        ));
    }
    let advertised_current = status.public_key.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "trust control service returned no current authority public key".to_string(),
        )
    })?;
    let advertised_current = PublicKey::from_hex(advertised_current).map_err(|_| {
        CliError::cli_other_error(
            "trust control service returned an invalid current authority public key".to_string(),
        )
    })?;
    if &advertised_current != pinned_current {
        return Err(CliError::cli_other_error(
            "trust control service current authority does not match the pinned current signer"
                .to_string(),
        ));
    }
    Ok(())
}

fn require_authenticated_authority_transport(
    endpoint: &str,
    allow_loopback_http: bool,
) -> Result<(), CliError> {
    let parsed = Url::parse(endpoint).map_err(|error| {
        CliError::cli_other_error(format!(
            "remote capability authority endpoint is invalid: {error}"
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
        "remote capability authority requires HTTPS".to_string(),
    ))
}

impl CapabilityAuthority for RemoteCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.pinned_current.clone()
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        vec![self.pinned_current.clone()]
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        self.issue_capability_with_attestation(subject, scope, ttl_seconds, None)
    }

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        let requested_at = checked_unix_timestamp_now()?;
        let nonce = sha256_hex(Keypair::generate().public_key().to_hex().as_bytes());
        let request = IssueCapabilityRequest::new(
            nonce,
            requested_at,
            subject,
            scope,
            ttl_seconds,
            runtime_attestation,
        );
        request
            .validate_at(requested_at)
            .map_err(issuance_failure)?;

        let mut last_error = None;
        for index in self.client.endpoint_order() {
            let result = fetch_signed_capability_response(&self.client, index, &request)
                .map_err(issuance_failure)
                .and_then(|response| {
                    let validation_time = checked_unix_timestamp_now()?;
                    response
                        .verify(&self.pinned_current, &request, validation_time)
                        .map_err(issuance_failure)?;
                    validate_remote_issued_capability(
                        &response.body.capability,
                        &request,
                        response.body.issued_at,
                        &self.pinned_current,
                    )?;
                    Ok(response.body.capability)
                });
            match result {
                Ok(capability) => {
                    self.client.mark_preferred(index);
                    return Ok(capability);
                }
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            issuance_failure("no remote capability authority endpoint returned a valid response")
        }))
    }
}

fn fetch_signed_capability_response(
    client: &TrustControlClient,
    index: usize,
    request: &IssueCapabilityRequest,
) -> Result<SignedIssueCapabilityResponse, String> {
    let url = format!("{}{}", client.endpoints[index], ISSUE_CAPABILITY_PATH);
    let json = serde_json::to_value(request)
        .map_err(|_| "capability issuance request serialization failed".to_string())?;
    let response = client
        .http
        .post(&url)
        .set(AUTHORIZATION.as_str(), &format!("Bearer {}", client.token))
        .send_json(json)
        .map_err(|_| "capability issuance endpoint is unavailable".to_string())?;
    let bytes = read_bounded_body(response, CAPABILITY_ISSUANCE_RESPONSE_MAX_BYTES)?;
    decode_canonical_capability_response(&bytes)
}

fn decode_canonical_capability_response(
    bytes: &[u8],
) -> Result<SignedIssueCapabilityResponse, String> {
    let raw = core::str::from_utf8(bytes)
        .map_err(|_| "capability issuance response is not UTF-8".to_string())?;
    let canonical = canonical_json_bytes_from_str(raw)
        .map_err(|_| "capability issuance response is not strict I-JSON".to_string())?;
    if canonical.as_slice() != bytes {
        return Err("capability issuance response is not canonical".to_string());
    }
    let response: SignedIssueCapabilityResponse = serde_json::from_slice(&canonical)
        .map_err(|_| "capability issuance response cannot be decoded".to_string())?;
    let typed = canonical_json_bytes(&response)
        .map_err(|_| "capability issuance response cannot be recanonicalized".to_string())?;
    if typed != canonical {
        return Err("capability issuance response contains non-schema fields".to_string());
    }
    Ok(response)
}

fn read_bounded_body(response: ureq::Response, cap: u64) -> Result<Vec<u8>, String> {
    let read_limit = cap
        .checked_add(1)
        .ok_or_else(|| "capability authority response bound overflow".to_string())?;
    let mut reader = response.into_reader().take(read_limit);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| "capability authority response could not be read".to_string())?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| "capability authority response length overflow".to_string())?;
    if length > cap {
        return Err("capability authority response exceeds its byte bound".to_string());
    }
    Ok(bytes)
}

fn validate_remote_issued_capability(
    capability: &CapabilityToken,
    request: &IssueCapabilityRequest,
    response_issued_at: u64,
    pinned_current: &PublicKey,
) -> Result<(), chio_kernel::KernelError> {
    if &capability.issuer != pinned_current {
        return Err(issuance_failure(
            "issued capability is not signed by the current pinned signer",
        ));
    }
    let expected_subject = PublicKey::from_hex(&request.subject_public_key)
        .map_err(|_| issuance_failure("requested capability subject is invalid"))?;
    if capability.subject != expected_subject {
        return Err(issuance_failure(
            "issued capability subject does not match the request",
        ));
    }
    if !capability.scope.is_subset_of(&request.scope) {
        return Err(issuance_failure(
            "issued capability scope exceeds the requested scope",
        ));
    }
    if !capability.delegation_chain.is_empty() {
        return Err(issuance_failure(
            "direct remote issuance returned a delegated capability",
        ));
    }
    if !matches!(
        capability.expires_at.checked_sub(capability.issued_at),
        Some(lifetime) if lifetime > 0 && lifetime <= request.ttl_seconds
    ) {
        return Err(issuance_failure(
            "issued capability lifetime exceeds the requested TTL",
        ));
    }
    if capability.issued_at
        < request
            .requested_at
            .saturating_sub(CAPABILITY_ISSUANCE_MAX_CLOCK_SKEW_SECS)
        || capability.issued_at > response_issued_at
        || capability.expires_at <= response_issued_at
    {
        return Err(issuance_failure(
            "issued capability is not fresh for the bound request",
        ));
    }
    let verified = capability
        .verify_signature_at(response_issued_at)
        .map_err(|error| {
            issuance_failure(format!(
                "issued capability signature or validity verification failed: {error}"
            ))
        })?;
    if !verified {
        return Err(issuance_failure(
            "issued capability signature verification failed",
        ));
    }
    Ok(())
}

fn checked_unix_timestamp_now() -> Result<u64, chio_kernel::KernelError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| issuance_failure("system clock is before the Unix epoch"))
}

fn issuance_failure(reason: impl Into<String>) -> chio_kernel::KernelError {
    chio_kernel::KernelError::CapabilityIssuanceFailed(reason.into())
}
