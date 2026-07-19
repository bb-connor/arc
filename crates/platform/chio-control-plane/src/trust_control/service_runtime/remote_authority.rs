use std::io::Read as _;

use chio_core::canonical::{canonical_json_bytes, canonical_json_bytes_from_str};

use super::client::build_client;
#[cfg(test)]
use super::remote_capability_request_store::BoundedMemoryRemoteCapabilityRequestStore;
use super::remote_capability_request_store::{
    request_recovery_expiry, RemoteCapabilityIssuanceClock, RemoteCapabilityRequestStore,
    SqliteRemoteCapabilityRequestStore, StoredRemoteCapabilityRequest,
    SystemRemoteCapabilityIssuanceClock,
};
use super::*;

const AUTHORITY_STATUS_MAX_BYTES: u64 = 64 * 1024;
const AUTHORITY_KEY_LOG_SYNC_MAX_BYTES: u64 = chio_keyring::MAX_CANONICAL_RECORD_BYTES as u64;
const AUTHORITY_KEY_LOG_MAX_SYNC_ROUNDS: usize = 4_096;
const PENDING_CAPABILITY_REQUEST_DOMAIN: &str = "chio.remote-capability-pending-request.v1\0";

/// One durable, independently verified view of the remote authority epoch.
/// The service bearer used here is deliberately separate from the workload
/// bearer used for capability issuance.
pub struct RemoteControlAuthorityTrust {
    client: TrustControlClient,
    pinned_authority: PinnedControlAuthority,
    verifier: chio_keyring::SqlitePinnedKeyLogVerifier,
    pending_requests: Arc<dyn RemoteCapabilityRequestStore>,
    active_epoch: Mutex<RemoteAuthorityEpoch>,
}

impl RemoteControlAuthorityTrust {
    pub fn open(
        control_url: &str,
        service_token: &str,
        pinned_authority: PinnedControlAuthority,
        policy_path: &Path,
        verifier_database_path: &Path,
    ) -> Result<Arc<Self>, CliError> {
        let policy = chio_keyring::load_key_log_policy(policy_path).map_err(|error| {
            CliError::cli_other_error(format!(
                "remote authority key-log policy is invalid: {error}"
            ))
        })?;
        let verifier = chio_keyring::SqlitePinnedKeyLogVerifier::open(
            verifier_database_path,
            policy,
            Arc::new(chio_keyring::SystemTrustedClock),
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "remote authority verifier database is unavailable: {error}"
            ))
        })?;
        let pending_requests = Arc::new(
            SqliteRemoteCapabilityRequestStore::open(verifier_database_path).map_err(|error| {
                CliError::cli_other_error(format!(
                    "remote capability pending-request database is unavailable: {error}"
                ))
            })?,
        );
        Self::open_with_verifier(
            control_url,
            service_token,
            pinned_authority,
            verifier,
            pending_requests,
            false,
        )
    }

    fn open_with_verifier(
        control_url: &str,
        service_token: &str,
        pinned_authority: PinnedControlAuthority,
        verifier: chio_keyring::SqlitePinnedKeyLogVerifier,
        pending_requests: Arc<dyn RemoteCapabilityRequestStore>,
        allow_loopback_http: bool,
    ) -> Result<Arc<Self>, CliError> {
        let client = build_client(control_url, service_token)?;
        for endpoint in client.endpoints.iter() {
            require_authenticated_authority_transport(endpoint, allow_loopback_http)?;
        }
        let initial_unverified_epoch = RemoteAuthorityEpoch {
            public_key: pinned_authority.current_signer().clone(),
            generation: 0,
            trusted_public_keys: Vec::new(),
        };
        let trust = Arc::new(Self {
            client,
            pinned_authority,
            verifier,
            pending_requests,
            active_epoch: Mutex::new(initial_unverified_epoch),
        });
        let epoch = trust.synchronize_to_live_epoch()?;
        *trust.active_epoch.lock().map_err(|_| {
            CliError::cli_other_error(
                "remote authority verified epoch lock is unavailable".to_string(),
            )
        })? = epoch;
        Ok(trust)
    }

    pub(crate) fn epoch_snapshot(&self) -> Result<RemoteAuthorityEpoch, CliError> {
        self.active_epoch
            .lock()
            .map(|epoch| epoch.clone())
            .map_err(|_| {
                CliError::cli_other_error(
                    "remote authority verified epoch lock is unavailable".to_string(),
                )
            })
    }

    pub(crate) fn pinned_authority(&self) -> &PinnedControlAuthority {
        &self.pinned_authority
    }

    fn pending_request_store(&self) -> Arc<dyn RemoteCapabilityRequestStore> {
        Arc::clone(&self.pending_requests)
    }

    pub(crate) fn synchronize_to_live_epoch(&self) -> Result<RemoteAuthorityEpoch, CliError> {
        let mut last_error = None;
        for _ in 0..AUTHORITY_KEY_LOG_MAX_SYNC_ROUNDS {
            let before = self.verifier.pin().map_err(key_log_verifier_error)?;
            let mut applied = false;
            for index in self.client.endpoint_order() {
                let result = fetch_authority_status(&self.client, index).and_then(|status| {
                    validate_authority_status_liveness(&status)?;
                    let response = fetch_key_log_sync(&self.client, index, before.as_ref())?;
                    if before.is_none()
                        && (response.event_envelopes.is_empty() || response.checkpoints.is_empty())
                    {
                        return Err(CliError::cli_other_error(
                            "remote authority key-log genesis page is empty".to_string(),
                        ));
                    }
                    let after = self
                        .verifier
                        .apply_sync(&response)
                        .map_err(key_log_verifier_error)?;
                    let state = self
                        .verifier
                        .witnessed_state()
                        .map_err(key_log_verifier_error)?
                        .ok_or_else(|| {
                            CliError::cli_other_error(
                                "remote authority verifier has no witnessed state".to_string(),
                            )
                        })?;
                    let epoch = verified_epoch_from_state(&state, &status, &self.pinned_authority);
                    Ok((after, epoch))
                });
                match result {
                    Ok((_after, Ok(epoch))) => {
                        self.client.mark_preferred(index);
                        return Ok(epoch);
                    }
                    Ok((after, Err(error))) => {
                        applied = before.as_ref() != Some(&after);
                        last_error = Some(error);
                        if applied {
                            break;
                        }
                    }
                    Err(error) => {
                        let current = self.verifier.pin().map_err(key_log_verifier_error)?;
                        applied = current != before;
                        last_error = Some(error);
                        if applied {
                            break;
                        }
                    }
                }
            }
            if !applied {
                return Err(last_error.unwrap_or_else(|| {
                    CliError::cli_other_error(
                        "remote authority key-log made no verified progress".to_string(),
                    )
                }));
            }
        }
        Err(CliError::cli_other_error(
            "remote authority key-log exceeded its synchronization page limit".to_string(),
        ))
    }

    pub(crate) fn refresh(&self) -> Result<RemoteAuthorityEpoch, CliError> {
        let epoch = self.synchronize_to_live_epoch()?;
        let mut active = self.active_epoch.lock().map_err(|_| {
            CliError::cli_other_error(
                "remote authority verified epoch lock is unavailable".to_string(),
            )
        })?;
        if epoch.generation < active.generation {
            return Err(CliError::cli_other_error(
                "remote authority verified epoch regressed".to_string(),
            ));
        }
        *active = epoch.clone();
        Ok(epoch)
    }

    fn verify_issuance_response_artifact(
        &self,
        response: &SignedIssueCapabilityResponse,
    ) -> Result<(), CliError> {
        self.refresh()?;
        let evidence = response
            .keyring_artifact_signature
            .as_ref()
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "remote capability response omitted keyring artifact evidence".to_string(),
                )
            })?;
        let time_anchor = response.artifact_time_anchor.as_ref().ok_or_else(|| {
            CliError::cli_other_error(
                "remote capability response omitted trusted-time evidence".to_string(),
            )
        })?;
        if evidence.signing_epoch.checked_add(1) != Some(response.body.authority_generation) {
            return Err(CliError::cli_other_error(
                "remote capability response evidence has the wrong signing epoch".to_string(),
            ));
        }
        let signing_bytes = response.signing_bytes().map_err(|error| {
            CliError::cli_other_error(format!(
                "remote capability response signing payload is invalid: {error}"
            ))
        })?;
        let record = self
            .verifier
            .verify_artifact_signing_evidence(&signing_bytes, evidence, time_anchor)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "remote capability response trusted-time evidence is invalid: {error}"
                ))
            })?;
        if record.public_key != response.signer_public_key
            || evidence.artifact_signature != response.signature
        {
            return Err(CliError::cli_other_error(
                "remote capability response evidence does not match its signer".to_string(),
            ));
        }
        Ok(())
    }
}

pub fn build_remote_capability_authority(
    control_url: &str,
    workload_token: &str,
    pinned_authority: PinnedControlAuthority,
    verified_trust: Arc<RemoteControlAuthorityTrust>,
    tenant_id: &str,
    workload_id: &str,
    server_id: &str,
    workload_signer: Keypair,
    session_admission_signer: Keypair,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    let pending_requests = verified_trust.pending_request_store();
    build_remote_capability_authority_with_transport(
        control_url,
        workload_token,
        pinned_authority,
        Some(verified_trust),
        tenant_id,
        workload_id,
        server_id,
        workload_signer,
        session_admission_signer,
        pending_requests,
        Arc::new(SystemRemoteCapabilityIssuanceClock),
        false,
    )
}

#[cfg(test)]
pub(crate) fn build_remote_capability_authority_for_test(
    control_url: &str,
    workload_token: &str,
    pinned_authority: PinnedControlAuthority,
    tenant_id: &str,
    workload_id: &str,
    server_id: &str,
    workload_signer: Keypair,
    session_admission_signer: Keypair,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    build_remote_capability_authority_for_test_with_runtime(
        control_url,
        workload_token,
        pinned_authority,
        tenant_id,
        workload_id,
        server_id,
        RemoteCapabilityAuthorityTestRuntime {
            workload_signer,
            session_admission_signer,
            pending_requests: Arc::new(BoundedMemoryRemoteCapabilityRequestStore::for_test()),
            issuance_clock: Arc::new(SystemRemoteCapabilityIssuanceClock),
        },
    )
}

#[cfg(test)]
pub(crate) struct RemoteCapabilityAuthorityTestRuntime {
    pub(crate) workload_signer: Keypair,
    pub(crate) session_admission_signer: Keypair,
    pub(crate) pending_requests: Arc<dyn RemoteCapabilityRequestStore>,
    pub(crate) issuance_clock: Arc<dyn RemoteCapabilityIssuanceClock>,
}

#[cfg(test)]
pub(crate) fn build_remote_capability_authority_for_test_with_runtime(
    control_url: &str,
    workload_token: &str,
    pinned_authority: PinnedControlAuthority,
    tenant_id: &str,
    workload_id: &str,
    server_id: &str,
    runtime: RemoteCapabilityAuthorityTestRuntime,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    let RemoteCapabilityAuthorityTestRuntime {
        workload_signer,
        session_admission_signer,
        pending_requests,
        issuance_clock,
    } = runtime;
    build_remote_capability_authority_with_transport(
        control_url,
        workload_token,
        pinned_authority,
        None,
        tenant_id,
        workload_id,
        server_id,
        workload_signer,
        session_admission_signer,
        pending_requests,
        issuance_clock,
        true,
    )
}

fn build_remote_capability_authority_with_transport(
    control_url: &str,
    workload_token: &str,
    pinned_authority: PinnedControlAuthority,
    verified_trust: Option<Arc<RemoteControlAuthorityTrust>>,
    tenant_id: &str,
    workload_id: &str,
    server_id: &str,
    workload_signer: Keypair,
    session_admission_signer: Keypair,
    pending_requests: Arc<dyn RemoteCapabilityRequestStore>,
    issuance_clock: Arc<dyn RemoteCapabilityIssuanceClock>,
    allow_loopback_http: bool,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    if tenant_id.is_empty()
        || tenant_id.trim() != tenant_id
        || workload_id.is_empty()
        || workload_id.trim() != workload_id
        || server_id.is_empty()
        || server_id.trim() != server_id
    {
        return Err(CliError::cli_other_error(
            "remote capability authority requires fixed tenant, workload, and server identities"
                .to_string(),
        ));
    }
    let client = build_client(control_url, workload_token)?;
    for endpoint in client.endpoints.iter() {
        require_authenticated_authority_transport(endpoint, allow_loopback_http)?;
    }
    if workload_signer.public_key() == session_admission_signer.public_key() {
        return Err(CliError::cli_other_error(
            "remote capability workload and session-admission signers must be distinct".to_string(),
        ));
    }
    let initial_epoch = match verified_trust.as_ref() {
        Some(trust) => {
            if trust.pinned_authority() != &pinned_authority {
                return Err(CliError::cli_other_error(
                    "remote authority verifier and workload pin schedules differ".to_string(),
                ));
            }
            trust.epoch_snapshot()?
        }
        None => {
            #[cfg(test)]
            {
                resolve_initial_pinned_epoch(&client, &pinned_authority, allow_loopback_http)?
            }
            #[cfg(not(test))]
            {
                return Err(CliError::cli_other_error(
                    "remote capability authority requires a durable key-log verifier".to_string(),
                ));
            }
        }
    };
    Ok(Box::new(RemoteCapabilityAuthority {
        client,
        verified_trust,
        active_epoch: Mutex::new(initial_epoch),
        tenant_id: tenant_id.to_string(),
        workload_id: workload_id.to_string(),
        server_id: server_id.to_string(),
        workload_signer,
        session_admission_signer,
        pending_requests,
        issuance_clock,
    }))
}

#[cfg(test)]
fn resolve_initial_pinned_epoch(
    client: &TrustControlClient,
    pinned_authority: &PinnedControlAuthority,
    allow_test_backend: bool,
) -> Result<RemoteAuthorityEpoch, CliError> {
    let mut last_error = None;
    for index in client.endpoint_order() {
        let result = fetch_authority_status(client, index).and_then(|status| {
            let advertised = status
                .public_key
                .as_deref()
                .ok_or_else(|| {
                    CliError::cli_other_error(
                        "trust control service returned no current authority public key"
                            .to_string(),
                    )
                })
                .and_then(|value| {
                    PublicKey::from_hex(value).map_err(|_| {
                        CliError::cli_other_error(
                            "trust control service returned an invalid current authority public key"
                                .to_string(),
                        )
                    })
                })?;
            let (expected_generation, expected_key) = if advertised
                == *pinned_authority.current_signer()
            {
                let generation = validate_current_authority_pin(
                    &status,
                    pinned_authority.current_signer(),
                    allow_test_backend,
                )?;
                if let Some(first) = pinned_authority.successors().first() {
                    let base_generation = first.generation.checked_sub(1).ok_or_else(|| {
                        CliError::cli_other_error(
                            "pinned authority successor schedule has no base generation"
                                .to_string(),
                        )
                    })?;
                    pinned_authority.validate_successor_schedule_from(base_generation)?;
                    if generation != base_generation {
                        return Err(CliError::cli_other_error(
                            "live authority generation does not match the pinned successor schedule base"
                                .to_string(),
                        ));
                    }
                }
                (generation, pinned_authority.current_signer().clone())
            } else {
                let successor = pinned_authority
                    .successors()
                    .iter()
                    .find(|successor| successor.public_key == advertised)
                    .ok_or_else(|| {
                        CliError::cli_other_error(
                            "live authority key is neither the current pin nor a configured successor"
                                .to_string(),
                        )
                    })?;
                let first_generation = pinned_authority
                    .successors()
                    .first()
                    .and_then(|first| first.generation.checked_sub(1))
                    .ok_or_else(|| {
                        CliError::cli_other_error(
                            "pinned authority successor schedule has no base generation"
                                .to_string(),
                        )
                    })?;
                pinned_authority.validate_successor_schedule_from(first_generation)?;
                let generation = validate_current_authority_pin(
                    &status,
                    &successor.public_key,
                    allow_test_backend,
                )?;
                if generation != successor.generation {
                    return Err(CliError::cli_other_error(
                        "live authority successor generation does not match its operator pin"
                            .to_string(),
                    ));
                }
                if !allow_test_backend {
                    let witnessed = status
                        .trusted_public_keys
                        .iter()
                        .filter_map(|value| PublicKey::from_hex(value).ok())
                        .collect::<Vec<_>>();
                    let required = pinned_authority
                        .trusted_roots_through_generation(generation);
                    if required.iter().any(|key| !witnessed.contains(key)) {
                        return Err(CliError::cli_other_error(
                            "live authority successor is missing contiguous witnessed key history"
                                .to_string(),
                        ));
                    }
                }
                (generation, successor.public_key.clone())
            };
            Ok(RemoteAuthorityEpoch {
                public_key: expected_key,
                generation: expected_generation,
                trusted_public_keys: pinned_authority
                    .trusted_roots_through_generation(expected_generation),
            })
        });
        match result {
            Ok(epoch) => {
                client.mark_preferred(index);
                return Ok(epoch);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        CliError::cli_other_error(
            "no remote capability authority endpoint matched the pinned epoch schedule".to_string(),
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

fn fetch_key_log_sync(
    client: &TrustControlClient,
    index: usize,
    base: Option<&chio_keyring::KeyLogPin>,
) -> Result<chio_keyring::KeyLogSyncResponse, CliError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Request<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        base: Option<&'a chio_keyring::KeyLogPin>,
    }

    let url = format!("{}{}", client.endpoints[index], AUTHORITY_KEY_LOG_SYNC_PATH);
    let request = serde_json::to_value(Request { base }).map_err(|_| {
        CliError::cli_other_error("remote authority key-log request cannot be encoded".to_string())
    })?;
    let response = client
        .http
        .post(&url)
        .set(AUTHORIZATION.as_str(), &format!("Bearer {}", client.token))
        .send_json(request)
        .map_err(|_| {
            CliError::cli_other_error(
                "remote authority key-log synchronization endpoint is unavailable".to_string(),
            )
        })?;
    let bytes =
        read_bounded_body(response, AUTHORITY_KEY_LOG_SYNC_MAX_BYTES).map_err(|reason| {
            CliError::cli_other_error(format!(
                "remote authority key-log synchronization response is invalid: {reason}"
            ))
        })?;
    let raw = core::str::from_utf8(&bytes).map_err(|_| {
        CliError::cli_other_error(
            "remote authority key-log synchronization response is not UTF-8".to_string(),
        )
    })?;
    let canonical = canonical_json_bytes_from_str(raw).map_err(|_| {
        CliError::cli_other_error(
            "remote authority key-log synchronization response is not strict I-JSON".to_string(),
        )
    })?;
    if canonical != bytes {
        return Err(CliError::cli_other_error(
            "remote authority key-log synchronization response is not canonical".to_string(),
        ));
    }
    let response = chio_keyring::KeyLogSyncResponse::from_canonical_bytes(&canonical)
        .map_err(key_log_verifier_error)?;
    if canonical_json_bytes(&response).map_err(|error| {
        CliError::cli_other_error(format!(
            "remote authority key-log synchronization response cannot be recanonicalized: {error}"
        ))
    })? != canonical
    {
        return Err(CliError::cli_other_error(
            "remote authority key-log synchronization response contains non-schema fields"
                .to_string(),
        ));
    }
    Ok(response)
}

fn validate_authority_status_liveness(status: &TrustAuthorityStatus) -> Result<(), CliError> {
    if !status.configured || status.backend.as_deref() != Some("enterprise_keyring") {
        return Err(CliError::cli_other_error(
            "remote authority liveness does not report an enterprise keyring".to_string(),
        ));
    }
    let public_key = status.public_key.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "remote authority liveness omitted its current public key".to_string(),
        )
    })?;
    PublicKey::from_hex(public_key).map_err(|_| {
        CliError::cli_other_error(
            "remote authority liveness returned an invalid public key".to_string(),
        )
    })?;
    if status.generation.is_none_or(|generation| generation == 0) {
        return Err(CliError::cli_other_error(
            "remote authority liveness omitted its generation".to_string(),
        ));
    }
    Ok(())
}

fn verified_epoch_from_state(
    state: &chio_keyring::KeyLogState,
    status: &TrustAuthorityStatus,
    pinned_authority: &PinnedControlAuthority,
) -> Result<RemoteAuthorityEpoch, CliError> {
    let generation = state.signing_epoch().checked_add(1).ok_or_else(|| {
        CliError::cli_other_error("remote authority generation overflow".to_string())
    })?;
    let active = state
        .active_signing_key()
        .map_err(key_log_verifier_error)?
        .public_key
        .clone();
    let advertised = status
        .public_key
        .as_deref()
        .and_then(|value| PublicKey::from_hex(value).ok())
        .ok_or_else(|| {
            CliError::cli_other_error(
                "remote authority liveness omitted a valid current key".to_string(),
            )
        })?;
    if status.generation != Some(generation) || advertised != active {
        return Err(CliError::cli_other_error(
            "remote authority liveness is ahead of or conflicts with witnessed key-log state"
                .to_string(),
        ));
    }

    if active == *pinned_authority.current_signer() {
        if let Some(first) = pinned_authority.successors().first() {
            let base_generation = first.generation.checked_sub(1).ok_or_else(|| {
                CliError::cli_other_error(
                    "pinned authority successor schedule has no base generation".to_string(),
                )
            })?;
            pinned_authority.validate_successor_schedule_from(base_generation)?;
            if generation != base_generation {
                return Err(CliError::cli_other_error(
                    "witnessed authority generation does not match the operator-pinned base"
                        .to_string(),
                ));
            }
        }
    } else {
        let Some(successor) = pinned_authority
            .successors()
            .iter()
            .find(|successor| successor.generation == generation)
        else {
            return Err(CliError::cli_other_error(
                "witnessed authority key is not an operator-pinned successor".to_string(),
            ));
        };
        if successor.public_key != active {
            return Err(CliError::cli_other_error(
                "witnessed authority generation conflicts with its operator-pinned successor"
                    .to_string(),
            ));
        }
        let base_generation = pinned_authority
            .successors()
            .first()
            .and_then(|first| first.generation.checked_sub(1))
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "pinned authority successor schedule has no base generation".to_string(),
                )
            })?;
        pinned_authority.validate_successor_schedule_from(base_generation)?;
    }

    let witnessed = state
        .witnessed_verification_keys()
        .into_iter()
        .map(|record| record.public_key)
        .collect::<Vec<_>>();
    let trusted_public_keys = pinned_authority.trusted_roots_through_generation(generation);
    if trusted_public_keys
        .iter()
        .any(|key| !witnessed.contains(key))
        || witnessed
            .iter()
            .any(|key| !trusted_public_keys.contains(key))
    {
        return Err(CliError::cli_other_error(
            "witnessed authority history conflicts with the bounded operator pin set".to_string(),
        ));
    }
    Ok(RemoteAuthorityEpoch {
        public_key: active,
        generation,
        trusted_public_keys,
    })
}

fn key_log_verifier_error(error: chio_keyring::KeyringError) -> CliError {
    CliError::cli_other_error(format!(
        "remote authority key-log verification failed: {error}"
    ))
}

#[cfg(test)]
fn validate_current_authority_pin(
    status: &TrustAuthorityStatus,
    pinned_current: &PublicKey,
    allow_test_backend: bool,
) -> Result<u64, CliError> {
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
    if !allow_test_backend && status.backend.as_deref() != Some("enterprise_keyring") {
        return Err(CliError::cli_other_error(
            "remote capability authority requires the enterprise keyring backend".to_string(),
        ));
    }
    let generation = status.generation.ok_or_else(|| {
        CliError::cli_other_error(
            "trust control service omitted the witnessed authority generation".to_string(),
        )
    })?;
    if generation == 0 {
        return Err(CliError::cli_other_error(
            "trust control service current authority generation is zero".to_string(),
        ));
    }
    if !allow_test_backend && !matches!(status.rotated_at, Some(rotated_at) if rotated_at > 0) {
        return Err(CliError::cli_other_error(
            "trust control service omitted the witnessed authority activation time".to_string(),
        ));
    }
    let current_is_witnessed = status
        .trusted_public_keys
        .iter()
        .filter_map(|value| PublicKey::from_hex(value).ok())
        .any(|key| key == advertised_current);
    if !allow_test_backend && !current_is_witnessed {
        return Err(CliError::cli_other_error(
            "trust control service current authority is absent from witnessed key history"
                .to_string(),
        ));
    }
    Ok(generation)
}

pub(super) fn require_authenticated_authority_transport(
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

struct PendingCapabilityRequestKeyInput<'a> {
    subject: &'a PublicKey,
    scope: &'a ChioScope,
    ttl_seconds: u64,
    runtime_attestation: &'a Option<RuntimeAttestationEvidence>,
    security_context: &'a chio_kernel::CapabilityIssuanceContext,
    security_session_id: &'a str,
    principal_id: &'a str,
    isolation_epoch_id: &'a str,
    context_generation: u64,
}

impl RemoteCapabilityAuthority {
    fn epoch_snapshot(&self) -> Result<RemoteAuthorityEpoch, chio_kernel::KernelError> {
        if let Some(trust) = self.verified_trust.as_ref() {
            return trust.epoch_snapshot().map_err(|error| {
                issuance_failure(format!("remote authority verifier is unavailable: {error}"))
            });
        }
        self.active_epoch
            .lock()
            .map(|epoch| epoch.clone())
            .map_err(|_| issuance_failure("remote capability authority epoch lock is unavailable"))
    }

    fn pending_request_key(
        &self,
        input: PendingCapabilityRequestKeyInput<'_>,
    ) -> Result<String, chio_kernel::KernelError> {
        let identity = json!({
            "schema": "chio.remote-capability-pending-request.v1",
            "tenantId": input.security_context.tenant_id.as_str(),
            "lineageId": input.security_context.lineage_id.as_str(),
            "securitySessionId": input.security_session_id,
            "principalId": input.principal_id,
            "isolationEpochId": input.isolation_epoch_id,
            "contextGeneration": input.context_generation,
            "workloadId": self.workload_id,
            "serverId": self.server_id,
            "subjectPublicKey": input.subject.to_hex(),
            "scope": input.scope,
            "ttlSeconds": input.ttl_seconds,
            "runtimeAttestation": input.runtime_attestation,
            "workloadSignerPublicKey": self.workload_signer.public_key().to_hex(),
            "sessionAdmissionSignerPublicKey": self
                .session_admission_signer
                .public_key()
                .to_hex(),
        });
        let canonical = canonical_json_bytes(&identity).map_err(|error| {
            issuance_failure(format!(
                "remote capability pending-request identity is invalid: {error}"
            ))
        })?;
        let mut preimage =
            Vec::with_capacity(PENDING_CAPABILITY_REQUEST_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(PENDING_CAPABILITY_REQUEST_DOMAIN.as_bytes());
        preimage.extend_from_slice(&canonical);
        Ok(sha256_hex(&preimage))
    }

    fn validate_stored_pending_request(
        &self,
        pending_key: &str,
        stored: &StoredRemoteCapabilityRequest,
    ) -> Result<(), chio_kernel::KernelError> {
        stored
            .request
            .validate_structure_and_signature()
            .map_err(issuance_failure)?;
        if stored.request.workload_id != self.workload_id
            || stored.request.server_id != self.server_id
            || stored.request.workload_signer_public_key != self.workload_signer.public_key()
            || stored.request.session_admission.signer_public_key
                != self.session_admission_signer.public_key()
        {
            return Err(issuance_failure(
                "remote capability pending request does not match local workload custody",
            ));
        }
        let subject = PublicKey::from_hex(&stored.request.subject_public_key).map_err(|_| {
            issuance_failure("remote capability pending request subject is invalid")
        })?;
        let security_context = chio_kernel::CapabilityIssuanceContext {
            tenant_id: stored.request.tenant_id.clone(),
            lineage_id: stored.request.lineage_id.clone(),
            session_id: Some(
                chio_security_types::ports::SessionId::new(
                    stored.request.security_session_id.clone(),
                )
                .map_err(|error| issuance_failure(error.to_string()))?,
            ),
            principal_id: Some(
                chio_security_types::PrincipalId::new(stored.request.principal_id.clone())
                    .map_err(|error| issuance_failure(error.to_string()))?,
            ),
            isolation_epoch_id: Some(
                chio_security_types::ports::IsolationEpochId::new(
                    stored.request.isolation_epoch_id.clone(),
                )
                .map_err(|error| issuance_failure(error.to_string()))?,
            ),
            context_generation: Some(stored.request.context_generation),
        };
        let observed_key = self.pending_request_key(PendingCapabilityRequestKeyInput {
            subject: &subject,
            scope: &stored.request.scope,
            ttl_seconds: stored.request.ttl_seconds,
            runtime_attestation: &stored.request.runtime_attestation,
            security_context: &security_context,
            security_session_id: &stored.request.security_session_id,
            principal_id: &stored.request.principal_id,
            isolation_epoch_id: &stored.request.isolation_epoch_id,
            context_generation: stored.request.context_generation,
        })?;
        if observed_key != pending_key {
            return Err(issuance_failure(
                "remote capability pending request has the wrong canonical identity",
            ));
        }
        if request_recovery_expiry(&stored.request).map_err(issuance_failure)?
            != stored.recovery_expires_at
        {
            return Err(issuance_failure(
                "remote capability pending request has the wrong recovery expiry",
            ));
        }
        Ok(())
    }
}

impl CapabilityAuthority for RemoteCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.epoch_snapshot().map_or_else(
            |_| Keypair::generate().public_key(),
            |epoch| epoch.public_key,
        )
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        self.epoch_snapshot()
            .map(|epoch| epoch.trusted_public_keys)
            .unwrap_or_default()
    }

    fn workload_binding(&self) -> Option<chio_kernel::CapabilityAuthorityWorkloadBinding> {
        Some(chio_kernel::CapabilityAuthorityWorkloadBinding {
            tenant_id: self.tenant_id.clone(),
            workload_id: self.workload_id.clone(),
            server_id: self.server_id.clone(),
            signer_public_key: self.workload_signer.public_key(),
        })
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
        _subject: &PublicKey,
        _scope: ChioScope,
        _ttl_seconds: u64,
        _runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        Err(chio_kernel::KernelError::CapabilityIssuanceDenied(
            "remote capability issuance requires authoritative tenant and lineage context"
                .to_string(),
        ))
    }

    fn issue_capability_with_security_context(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
        security_context: &chio_kernel::CapabilityIssuanceContext,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        if security_context.tenant_id.as_str() != self.tenant_id {
            return Err(issuance_failure(
                "remote capability issuance tenant does not match the pinned workload identity",
            ));
        }
        let security_session_id = security_context.session_id.as_ref().ok_or_else(|| {
            issuance_failure("remote capability issuance requires a security session binding")
        })?;
        let principal_id = security_context.principal_id.as_ref().ok_or_else(|| {
            issuance_failure("remote capability issuance requires a principal binding")
        })?;
        let isolation_epoch_id = security_context
            .isolation_epoch_id
            .as_ref()
            .ok_or_else(|| {
                issuance_failure("remote capability issuance requires an isolation-epoch binding")
            })?;
        let context_generation = security_context.context_generation.ok_or_else(|| {
            issuance_failure("remote capability issuance requires a context generation")
        })?;
        let attempt_time = self
            .issuance_clock
            .now_unix_seconds()
            .map_err(issuance_failure)?;
        let pending_key = self.pending_request_key(PendingCapabilityRequestKeyInput {
            subject,
            scope: &scope,
            ttl_seconds,
            runtime_attestation: &runtime_attestation,
            security_context,
            security_session_id: security_session_id.as_str(),
            principal_id: principal_id.as_str(),
            isolation_epoch_id: isolation_epoch_id.as_str(),
            context_generation,
        })?;
        let stored = match self
            .pending_requests
            .load(&pending_key, attempt_time)
            .map_err(issuance_failure)?
        {
            Some(stored) => stored,
            None => {
                let epoch = match self.verified_trust.as_ref() {
                    Some(trust) => trust.refresh().map_err(|error| {
                        issuance_failure(format!(
                            "remote authority verifier refresh failed: {error}"
                        ))
                    })?,
                    None => self.epoch_snapshot()?,
                };
                let request = IssueCapabilityRequest::new(
                    Keypair::generate().public_key().to_hex(),
                    attempt_time,
                    security_context.tenant_id.clone(),
                    security_context.lineage_id.clone(),
                    security_session_id.as_str().to_string(),
                    principal_id.as_str().to_string(),
                    isolation_epoch_id.as_str().to_string(),
                    context_generation,
                    self.workload_id.clone(),
                    self.server_id.clone(),
                    epoch.public_key,
                    epoch.generation,
                    subject,
                    scope,
                    ttl_seconds,
                    runtime_attestation,
                    &self.workload_signer,
                    &self.session_admission_signer,
                )
                .map_err(issuance_failure)?;
                request
                    .validate_at(attempt_time)
                    .map_err(issuance_failure)?;
                let recovery_expires_at =
                    request_recovery_expiry(&request).map_err(issuance_failure)?;
                let selection = self
                    .pending_requests
                    .load_or_insert(&pending_key, &request, recovery_expires_at, attempt_time)
                    .map_err(issuance_failure)?;
                if selection.inserted {
                    selection
                        .stored
                        .request
                        .validate_freshness_at(attempt_time)
                        .map_err(issuance_failure)?;
                }
                selection.stored
            }
        };
        self.validate_stored_pending_request(&pending_key, &stored)?;
        let request = stored.request.clone();
        let mut last_error = None;
        for index in self.client.endpoint_order() {
            let result = fetch_signed_capability_response(&self.client, index, &request)
                .map_err(issuance_failure)
                .and_then(|response| {
                    let validation_time = self
                        .issuance_clock
                        .now_unix_seconds()
                        .map_err(issuance_failure)?;
                    response
                        .verify(
                            &request.expected_authority_public_key,
                            request.expected_authority_generation,
                            &request,
                            validation_time,
                        )
                        .map_err(issuance_failure)?;
                    if let Some(trust) = self.verified_trust.as_ref() {
                        trust
                            .verify_issuance_response_artifact(&response)
                            .map_err(|error| {
                                issuance_failure(format!(
                                    "remote capability response keyring verification failed: {error}"
                                ))
                            })?;
                    }
                    validate_remote_issued_capability(
                        &response.body.capability,
                        &request,
                        response.body.issued_at,
                        validation_time,
                        &request.expected_authority_public_key,
                    )?;
                    Ok(response.body.capability)
                });
            match result {
                Ok(capability) => {
                    self.pending_requests
                        .remove_if_exact(
                            &pending_key,
                            &stored.canonical_request,
                            stored.recovery_expires_at,
                        )
                        .map_err(issuance_failure)?;
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
    validation_time: u64,
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
    let binding = capability
        .security_binding()
        .map_err(|error| {
            issuance_failure(format!("issued capability binding is invalid: {error}"))
        })?
        .ok_or_else(|| issuance_failure("issued capability omitted its security binding"))?;
    if binding.tenant_id != request.tenant_id.as_str()
        || binding.lineage_id != request.lineage_id.as_str()
        || binding.session_id != request.security_session_id
        || binding.principal_id != request.principal_id
        || binding.isolation_epoch_id != request.isolation_epoch_id
        || binding.context_generation != request.context_generation
        || binding.workload_id != request.workload_id
        || binding.server_id != request.server_id
        || binding.workload_signer_public_key != request.workload_signer_public_key.to_hex()
    {
        return Err(issuance_failure(
            "issued capability binding does not match the authenticated request",
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
    if capability.issued_at > response_issued_at || capability.expires_at <= validation_time {
        return Err(issuance_failure(
            "issued capability is not fresh for the bound request",
        ));
    }
    let verified = capability
        .verify_signature_at(validation_time)
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

fn issuance_failure(reason: impl Into<String>) -> chio_kernel::KernelError {
    chio_kernel::KernelError::CapabilityIssuanceFailed(reason.into())
}
