use super::*;

pub(super) fn install_health_routes(
    router: Router<TrustServiceState>,
) -> Router<TrustServiceState> {
    router.route(HEALTH_PATH, get(handle_health))
}

async fn handle_health(State(state): State<TrustServiceState>) -> Response {
    let leader_url = current_leader_url(&state);
    let self_url = cluster_self_url(&state);
    Json(json!({
        "ok": true,
        "leaderUrl": leader_url.clone(),
        "selfUrl": self_url.clone(),
        "clustered": state.cluster.is_some(),
        "authority": trust_authority_health_snapshot(&state.config),
        "stores": trust_store_health_snapshot(&state.config),
        "federation": trust_federation_health_snapshot(&state),
        "cluster": trust_cluster_health_snapshot(&state, leader_url, self_url),
    }))
    .into_response()
}

fn trust_authority_health_snapshot(config: &TrustServiceConfig) -> Value {
    let backend_hint = if config.authority_db_path.is_some() {
        Some("sqlite")
    } else if config.authority_seed_path.is_some() {
        Some("seed_file")
    } else {
        None
    };
    match load_authority_status(config) {
        Ok(status) => json!({
            "configured": status.configured,
            "available": true,
            "backend": status.backend,
            "publicKey": status.public_key,
            "generation": status.generation,
            "rotatedAt": status.rotated_at,
            "appliesToFutureSessionsOnly": status.applies_to_future_sessions_only,
            "trustedKeyCount": status.trusted_public_keys.len(),
        }),
        Err(_) => json!({
            "configured": backend_hint.is_some(),
            "available": false,
            "backend": backend_hint,
            "publicKey": Value::Null,
            "generation": Value::Null,
            "rotatedAt": Value::Null,
            "appliesToFutureSessionsOnly": true,
            "trustedKeyCount": 0,
        }),
    }
}

fn trust_store_health_snapshot(config: &TrustServiceConfig) -> Value {
    json!({
        "receiptsConfigured": config.receipt_db_path.is_some(),
        "revocationsConfigured": config.revocation_db_path.is_some(),
        "budgetsConfigured": config.budget_db_path.is_some(),
        "verifierChallengesConfigured": config.verifier_challenge_db_path.is_some(),
    })
}

fn trust_federation_health_snapshot(state: &TrustServiceState) -> Value {
    let loaded_enterprise_provider_summary = state
        .enterprise_provider_registry()
        .map(|registry| {
            let enabled_count = registry
                .providers
                .values()
                .filter(|record| record.enabled)
                .count();
            let validated_count = registry
                .providers
                .values()
                .filter(|record| record.is_validated_enabled())
                .count();
            let invalid_count = registry
                .providers
                .values()
                .filter(|record| !record.validation_errors.is_empty())
                .count();
            (
                registry.providers.len(),
                enabled_count,
                validated_count,
                invalid_count,
            )
        })
        .unwrap_or((0, 0, 0, 0));

    let enterprise_provider_summary =
        if let Some(path) = state.config.enterprise_providers_file.as_deref() {
            match EnterpriseProviderRegistry::load(path) {
                Ok(registry) => {
                    let enabled_count = registry
                        .providers
                        .values()
                        .filter(|record| record.enabled)
                        .count();
                    let validated_count = registry
                        .providers
                        .values()
                        .filter(|record| record.is_validated_enabled())
                        .count();
                    let invalid_count = registry
                        .providers
                        .values()
                        .filter(|record| !record.validation_errors.is_empty())
                        .count();
                    json!({
                        "configured": true,
                        "available": true,
                        "count": registry.providers.len(),
                        "enabledCount": enabled_count,
                        "validatedCount": validated_count,
                        "invalidCount": invalid_count,
                        "loadedCount": loaded_enterprise_provider_summary.0,
                        "loadedValidatedCount": loaded_enterprise_provider_summary.2,
                    })
                }
                Err(_) => json!({
                    "configured": true,
                    "available": false,
                    "count": 0,
                    "enabledCount": 0,
                    "validatedCount": 0,
                    "invalidCount": 0,
                    "loadedCount": loaded_enterprise_provider_summary.0,
                    "loadedValidatedCount": loaded_enterprise_provider_summary.2,
                }),
            }
        } else {
            json!({
                "configured": false,
                "available": false,
                "count": 0,
                "enabledCount": 0,
                "validatedCount": 0,
                "invalidCount": 0,
                "loadedCount": 0,
                "loadedValidatedCount": 0,
            })
        };

    let loaded_verifier_policy_summary = state
        .verifier_policy_registry()
        .map(|registry| {
            let now = unix_timestamp_now();
            let active_count = registry
                .policies
                .values()
                .filter(|document| {
                    ensure_signed_passport_verifier_policy_active(document, now).is_ok()
                })
                .count();
            (registry.policies.len(), active_count)
        })
        .unwrap_or((0, 0));

    let verifier_policy_summary = if let Some(path) = state.config.verifier_policies_file.as_deref()
    {
        match VerifierPolicyRegistry::load(path) {
            Ok(registry) => {
                let now = unix_timestamp_now();
                let active_count = registry
                    .policies
                    .values()
                    .filter(|document| {
                        ensure_signed_passport_verifier_policy_active(document, now).is_ok()
                    })
                    .count();
                json!({
                    "configured": true,
                    "available": true,
                    "count": registry.policies.len(),
                    "activeCount": active_count,
                    "loadedCount": loaded_verifier_policy_summary.0,
                    "loadedActiveCount": loaded_verifier_policy_summary.1,
                })
            }
            Err(_) => json!({
                "configured": true,
                "available": false,
                "count": 0,
                "activeCount": 0,
                "loadedCount": loaded_verifier_policy_summary.0,
                "loadedActiveCount": loaded_verifier_policy_summary.1,
            }),
        }
    } else {
        json!({
            "configured": false,
            "available": false,
            "count": 0,
            "activeCount": 0,
            "loadedCount": 0,
            "loadedActiveCount": 0,
        })
    };

    let certification_summary =
        if let Some(path) = state.config.certification_registry_file.as_deref() {
            match CertificationRegistry::load(path) {
                Ok(registry) => {
                    let active_count = registry
                        .artifacts
                        .values()
                        .filter(|entry| entry.status == CertificationRegistryState::Active)
                        .count();
                    let superseded_count = registry
                        .artifacts
                        .values()
                        .filter(|entry| entry.status == CertificationRegistryState::Superseded)
                        .count();
                    let revoked_count = registry
                        .artifacts
                        .values()
                        .filter(|entry| entry.status == CertificationRegistryState::Revoked)
                        .count();
                    json!({
                        "configured": true,
                        "available": true,
                        "count": registry.artifacts.len(),
                        "activeCount": active_count,
                        "supersededCount": superseded_count,
                        "revokedCount": revoked_count,
                    })
                }
                Err(_) => json!({
                    "configured": true,
                    "available": false,
                    "count": 0,
                    "activeCount": 0,
                    "supersededCount": 0,
                    "revokedCount": 0,
                }),
            }
        } else {
            json!({
                "configured": false,
                "available": false,
                "count": 0,
                "activeCount": 0,
                "supersededCount": 0,
                "revokedCount": 0,
            })
        };

    let certification_discovery_summary =
        if let Some(path) = state.config.certification_discovery_file.as_deref() {
            match CertificationDiscoveryNetwork::load(path) {
                Ok(network) => {
                    let validated_count = network
                        .operators
                        .values()
                        .filter(|operator| operator.validation_errors.is_empty())
                        .count();
                    let publish_enabled_count = network
                        .operators
                        .values()
                        .filter(|operator| {
                            operator.validation_errors.is_empty() && operator.allow_publish
                        })
                        .count();
                    json!({
                        "configured": true,
                        "available": true,
                        "count": network.operators.len(),
                        "validatedCount": validated_count,
                        "publishEnabledCount": publish_enabled_count,
                    })
                }
                Err(_) => json!({
                    "configured": true,
                    "available": false,
                    "count": 0,
                    "validatedCount": 0,
                    "publishEnabledCount": 0,
                }),
            }
        } else {
            json!({
                "configured": false,
                "available": false,
                "count": 0,
                "validatedCount": 0,
                "publishEnabledCount": 0,
            })
        };

    json!({
        "enterpriseProviders": enterprise_provider_summary,
        "verifierPolicies": verifier_policy_summary,
        "certifications": certification_summary,
        "certificationDiscovery": certification_discovery_summary,
        "issuancePolicyConfigured": state.config.issuance_policy.is_some(),
        "runtimeAssurancePolicyConfigured": state.config.runtime_assurance_policy.is_some(),
    })
}

fn trust_cluster_health_snapshot(
    state: &TrustServiceState,
    leader_url: Option<String>,
    self_url: Option<String>,
) -> Value {
    let Some(cluster) = state.cluster.as_ref() else {
        return json!({
            "peerCount": 0,
            "healthyPeers": 0,
            "unhealthyPeers": 0,
            "unknownPeers": 0,
            "lastErrorCount": 0,
            "leaderUrl": leader_url,
            "selfUrl": self_url,
        });
    };

    let peers = match cluster.lock() {
        Ok(guard) => guard.peers.clone(),
        Err(poisoned) => poisoned.into_inner().peers.clone(),
    };

    let mut healthy = 0usize;
    let mut unhealthy = 0usize;
    let mut unknown = 0usize;
    let mut last_error_count = 0usize;
    for peer in peers.values() {
        match peer.health {
            PeerHealth::Healthy => healthy += 1,
            PeerHealth::Unhealthy(_) => unhealthy += 1,
            PeerHealth::Unknown => unknown += 1,
        }
        if peer.last_error.is_some() {
            last_error_count += 1;
        }
    }

    json!({
        "peerCount": peers.len(),
        "healthyPeers": healthy,
        "unhealthyPeers": unhealthy,
        "unknownPeers": unknown,
        "lastErrorCount": last_error_count,
        "leaderUrl": leader_url,
        "selfUrl": self_url,
    })
}
