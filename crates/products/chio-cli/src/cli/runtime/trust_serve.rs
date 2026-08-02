use super::*;

pub(crate) fn load_roster_policy(
    path: &Path,
) -> Result<trust_control::RosterPolicy, CliError> {
    let bytes = std::fs::read(path).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to read roster policy file `{}`: {error}",
            path.display()
        ))
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to parse roster policy file `{}`: {error}",
            path.display()
        ))
    })
}

fn load_authority_workload_public_key(
    path: &Path,
    description: &str,
) -> Result<chio_core::PublicKey, CliError> {
    let bytes = chio_keyring::read_custody_sensitive_file(path, 64).map_err(|error| {
        CliError::cli_other_error(format!(
            "{description} could not be read through hardened custody: {error}"
        ))
    })?;
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(CliError::cli_other_error(format!(
            "{description} must contain exactly 64 lowercase hex characters"
        )));
    }
    let public_key_hex = std::str::from_utf8(&bytes).map_err(|_| {
        CliError::cli_other_error(format!("{description} is not valid UTF-8"))
    })?;
    chio_core::PublicKey::from_hex(public_key_hex).map_err(CliError::from)
}

pub(crate) fn cmd_trust_serve(
    listen: SocketAddr,
    service_token: &str,
    dashboard_read_token: Option<&str>,
    dashboard_report_origin: Option<&str>,
    dashboard_report_token: Option<&str>,
    dashboard_allow_insecure_report_origin: bool,
    authority_admin_token: Option<&str>,
    authority_workload_token: Option<&str>,
    authority_workload_tenant_id: Option<&str>,
    authority_workload_id: Option<&str>,
    authority_workload_server_id: Option<&str>,
    authority_workload_public_key_file: Option<&Path>,
    authority_session_admission_public_key_file: Option<&Path>,
    authority_keyring_config_path: Option<&Path>,
    tenant_read_tokens: &[String],
    policy_path: Option<&Path>,
    enterprise_providers_file: Option<&Path>,
    federation_policies_file: Option<&Path>,
    scim_lifecycle_file: Option<&Path>,
    verifier_policies_file: Option<&Path>,
    verifier_challenge_db: Option<&Path>,
    passport_statuses_file: Option<&Path>,
    passport_issuance_offers_file: Option<&Path>,
    certification_registry_file: Option<&Path>,
    certification_discovery_file: Option<&Path>,
    fiscal_genesis_policy: Option<&Path>,
    fiscal_anchor_url: Option<&str>,
    fiscal_anchor_token: Option<&str>,
    fiscal_admission_authority_id: &str,
    fiscal_admission_signer_key_epoch: u64,
    fiscal_admission_signing_seed: Option<&Path>,
    fiscal_anchor_timeout_seconds: u64,
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    _session_db_path: Option<&Path>,
    advertise_url: Option<&str>,
    cluster_node_seed_path: Option<&Path>,
    cluster_replay_db_path: Option<&Path>,
    cluster_members: &[String],
    allow_local_peer_urls: bool,
    certification_public_metadata_ttl_seconds: u64,
    peer_urls: &[String],
    cluster_sync_interval_ms: u64,
    roster_policy_file: Option<&Path>,
    partition_escrow_authority_descriptor: Option<&Path>,
    partition_escrow_authority_signer: Option<&chio_core::PublicKey>,
) -> Result<(), CliError> {
    if service_token.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "trust serve requires a non-empty --service-token".to_string(),
        ));
    }
    let tenant_read_tokens = parse_tenant_read_tokens(tenant_read_tokens)?;
    if let Some((tenant_id, _)) = tenant_read_tokens
        .iter()
        .find(|(_, token)| token.as_str() == service_token)
    {
        return Err(CliError::cli_other_error(format!(
            "--tenant-read-token for tenant {tenant_id} must not equal --service-token"
        )));
    }
    let loaded_policy = policy_path.map(load_policy).transpose()?;
    let authority_workload = match (
        authority_workload_token,
        authority_workload_tenant_id,
        authority_workload_id,
        authority_workload_server_id,
        authority_workload_public_key_file,
        authority_session_admission_public_key_file,
    ) {
        (
            Some(token),
            Some(tenant_id),
            Some(workload_id),
            Some(server_id),
            Some(public_key_path),
            Some(session_admission_public_key_path),
        ) => {
            let signer_public_key = load_authority_workload_public_key(
                public_key_path,
                "authority workload public-key file",
            )?;
            let session_admission_public_key =
                load_authority_workload_public_key(
                    session_admission_public_key_path,
                    "authority session-admission public-key file",
                )?;
            let allowed_capabilities = loaded_policy
                .as_ref()
                .ok_or_else(|| {
                    CliError::cli_other_error(
                        "authority workload issuance requires --policy for server-derived scope and TTL"
                            .to_string(),
                    )
                })?
                .default_capabilities
                .clone();
            Some(trust_control::AuthorityWorkloadPolicy {
                credential_token: token.to_string(),
                tenant_id: tenant_id.to_string(),
                workload_id: workload_id.to_string(),
                server_id: server_id.to_string(),
                signer_public_key,
                session_admission_public_key,
                allowed_capabilities,
            })
        }
        (None, None, None, None, None, None) => None,
        _ => {
            return Err(CliError::cli_other_error(
                "authority workload token, tenant, workload, server, request-signer key, and session-admission key must be configured together"
                    .to_string(),
            ));
        }
    };
    let (issuance_policy, runtime_assurance_policy) = loaded_policy
        .map(|loaded| (loaded.issuance_policy, loaded.runtime_assurance_policy))
        .unwrap_or((None, None));
    let roster_policy = roster_policy_file.map(load_roster_policy).transpose()?;
    let fiscal_runtime = match (
        fiscal_genesis_policy,
        fiscal_anchor_url,
        fiscal_anchor_token,
        fiscal_admission_signing_seed,
    ) {
        (Some(policy), Some(anchor_url), Some(anchor_token), Some(admission_seed)) => Some(
            trust_control::TrustFiscalRuntimeConfig::from_policy_file(
                policy,
                anchor_url.to_owned(),
                anchor_token.to_owned(),
                std::time::Duration::from_secs(fiscal_anchor_timeout_seconds),
                fiscal_admission_authority_id.to_owned(),
                fiscal_admission_signer_key_epoch,
                admission_seed.to_path_buf(),
            )?,
        ),
        (None, None, None, None) => None,
        _ => {
            return Err(CliError::cli_other_error(
                "fiscal runtime requires --fiscal-genesis-policy, --fiscal-anchor-url, --fiscal-anchor-token, and --fiscal-admission-signing-seed together"
                    .to_owned(),
            ));
        }
    };
    let cluster_members = parse_cluster_members(cluster_members)?;
    let partition_escrow_authority = match (
        partition_escrow_authority_descriptor,
        partition_escrow_authority_signer,
    ) {
        (None, None) => None,
        (Some(descriptor_path), Some(trusted_signer)) => Some(
            load_partition_escrow_remote_authority(descriptor_path, trusted_signer)?,
        ),
        _ => {
            return Err(CliError::cli_other_error(
                "partition-escrow authority descriptor and pinned signer must be configured together"
                    .to_string(),
            ));
        }
    };
    trust_control::serve(trust_control::TrustServiceConfig {
        listen,
        service_token: service_token.to_string(),
        dashboard_read_token: dashboard_read_token.map(ToOwned::to_owned),
        dashboard_report_origin: dashboard_report_origin.map(ToOwned::to_owned),
        dashboard_report_token: dashboard_report_token.map(ToOwned::to_owned),
        dashboard_allow_insecure_report_origin,
        authority_admin_token: authority_admin_token.map(ToOwned::to_owned),
        authority_workloads: authority_workload.into_iter().collect(),
        tenant_read_tokens,
        receipt_db_path: receipt_db_path.map(Path::to_path_buf),
        revocation_db_path: revocation_db_path.map(Path::to_path_buf),
        authority_seed_path: authority_seed_path.map(Path::to_path_buf),
        authority_db_path: authority_db_path.map(Path::to_path_buf),
        authority_keyring_config_path: authority_keyring_config_path.map(Path::to_path_buf),
        budget_db_path: budget_db_path.map(Path::to_path_buf),
        joint_authority_db_path: _session_db_path.map(Path::to_path_buf),
        fiscal_runtime,
        partition_escrow_authority,
        enterprise_providers_file: enterprise_providers_file.map(Path::to_path_buf),
        federation_policies_file: federation_policies_file.map(Path::to_path_buf),
        scim_lifecycle_file: scim_lifecycle_file.map(Path::to_path_buf),
        verifier_policies_file: verifier_policies_file.map(Path::to_path_buf),
        verifier_challenge_db_path: verifier_challenge_db.map(Path::to_path_buf),
        passport_statuses_file: passport_statuses_file.map(Path::to_path_buf),
        passport_issuance_offers_file: passport_issuance_offers_file.map(Path::to_path_buf),
        certification_registry_file: certification_registry_file.map(Path::to_path_buf),
        certification_discovery_file: certification_discovery_file.map(Path::to_path_buf),
        issuance_policy,
        runtime_assurance_policy,
        advertise_url: advertise_url.map(ToOwned::to_owned),
        allow_local_peer_urls,
        certification_public_metadata_ttl_seconds,
        peer_urls: peer_urls.to_vec(),
        cluster_node_seed_path: cluster_node_seed_path.map(Path::to_path_buf),
        cluster_replay_db_path: cluster_replay_db_path.map(Path::to_path_buf),
        cluster_members,
        cluster_sync_interval: std::time::Duration::from_millis(cluster_sync_interval_ms.max(50)),
        roster_policy,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
    })
}
