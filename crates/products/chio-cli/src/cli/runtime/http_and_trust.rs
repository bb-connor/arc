fn load_manifest_for_mcp_kernel(
    signed_manifest_path: &Path,
    manifest_public_key: &str,
    server_id: &str,
) -> Result<chio_manifest::VerifiedManifestRegistry, CliError> {
    load_existing_verified_manifest_registry(
        signed_manifest_path,
        manifest_public_key,
        server_id,
        RuntimeToolTopology::local(),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("failed to load admitted MCP manifest: {error}"))
    })
}

fn remote_authority_successors_from_env(
) -> Result<Vec<trust_control::service_runtime::PinnedAuthoritySuccessor>, CliError> {
    let Some(value) = std::env::var_os("CHIO_CONTROL_AUTHORITY_SUCCESSORS") else {
        return Ok(Vec::new());
    };
    let value = value.into_string().map_err(|_| {
        CliError::cli_other_error(
            "CHIO_CONTROL_AUTHORITY_SUCCESSORS is not valid UTF-8".to_string(),
        )
    })?;
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|entry| {
            let (generation, public_key) = entry.split_once(':').ok_or_else(|| {
                CliError::cli_other_error(
                    "control-authority successors must use generation:public-key entries"
                        .to_string(),
                )
            })?;
            let generation = generation.parse::<u64>().map_err(|_| {
                CliError::cli_other_error(
                    "control-authority successor generation is invalid".to_string(),
                )
            })?;
            Ok(trust_control::service_runtime::PinnedAuthoritySuccessor {
                generation,
                public_key: chio_core::PublicKey::from_hex(public_key)?,
            })
        })
        .collect()
}

pub(crate) fn cmd_mcp_serve_http(
    policy_path: &Path,
    server_id: &str,
    server_name: Option<&str>,
    server_version: Option<&str>,
    signed_manifest_path: Option<&Path>,
    manifest_public_key: Option<&str>,
    cage_policy_path: &Path,
    cage_policy_signer: &str,
    page_size: usize,
    tools_list_changed: bool,
    shared_hosted_owner: bool,
    listen: SocketAddr,
    auth_token: Option<&str>,
    auth_jwt_public_key: Option<&str>,
    auth_jwt_discovery_url: Option<&str>,
    auth_introspection_url: Option<&str>,
    auth_introspection_client_id: Option<&str>,
    auth_introspection_client_secret: Option<&str>,
    auth_jwt_provider_profile: Option<remote_mcp::JwtProviderProfile>,
    auth_server_seed_file: Option<&Path>,
    identity_federation_seed_file: Option<&Path>,
    enterprise_providers_file: Option<&Path>,
    auth_jwt_issuer: Option<&str>,
    auth_jwt_audience: Option<&str>,
    admin_token: Option<&str>,
    remote_authority_workload_token: Option<&str>,
    public_base_url: Option<&str>,
    auth_servers: &[String],
    auth_authorization_endpoint: Option<&str>,
    auth_token_endpoint: Option<&str>,
    auth_registration_endpoint: Option<&str>,
    auth_jwks_uri: Option<&str>,
    auth_scopes: &[String],
    auth_subject: &str,
    auth_code_ttl_secs: u64,
    auth_access_token_ttl_secs: u64,
    command: &[String],
    receipt_db_path: Option<&Path>,
    revocation_db_path: Option<&Path>,
    authority_seed_path: Option<&Path>,
    keyring_config_path: Option<&Path>,
    broker_config_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    enable_aggregate_invocation_admission: bool,
    admission_operation_db_path: Option<&Path>,
    approval_db_path: Option<&Path>,
    approver_directory_path: Option<&Path>,
    threshold_proposal_authority_public_key: Option<&chio_core::PublicKey>,
    session_db_path: Option<&Path>,
    resume_hmac_keyring_path: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    control_authority_public_key: Option<&chio_core::PublicKey>,
    control_authority_trusted_public_keys: &[chio_core::PublicKey],
) -> Result<(), CliError> {
    let loaded_policy = policy::load_policy_for_runtime(
        policy_path,
        approver_directory_path,
        threshold_proposal_authority_public_key,
    )?;
    info!(
        policy_path = %policy_path.display(),
        policy_format = loaded_policy.format_name(),
        source_policy_hash = %loaded_policy.identity.source_hash,
        runtime_policy_hash = %loaded_policy.identity.runtime_hash,
        server_id = server_id,
        listen_addr = %listen,
        "loaded policy for remote MCP edge"
    );

    let (wrapped_cmd, wrapped_args) = command
        .split_first()
        .ok_or_else(|| CliError::cli_other_error("empty MCP server command".to_string()))?;

    let auth_token = optional_secret_with_env_fallback(auth_token, "CHIO_MCP_AUTH_TOKEN");
    let admin_token = optional_secret_with_env_fallback(admin_token, "CHIO_MCP_ADMIN_TOKEN");
    let egress_contract = remote_mcp_auth_egress_contract(
        server_id,
        auth_jwt_discovery_url,
        auth_introspection_url,
        auth_jwt_provider_profile,
        auth_jwt_issuer,
        auth_jwks_uri,
    )?;

    remote_mcp::serve_http(remote_mcp::RemoteServeHttpConfig {
        listen,
        auth_token,
        auth_jwt_public_key: auth_jwt_public_key.map(ToOwned::to_owned),
        auth_jwt_discovery_url: auth_jwt_discovery_url.map(ToOwned::to_owned),
        auth_introspection_url: auth_introspection_url.map(ToOwned::to_owned),
        auth_introspection_client_id: auth_introspection_client_id.map(ToOwned::to_owned),
        auth_introspection_client_secret: auth_introspection_client_secret.map(ToOwned::to_owned),
        auth_jwt_provider_profile,
        auth_server_seed_path: auth_server_seed_file.map(Path::to_path_buf),
        identity_federation_seed_path: identity_federation_seed_file.map(Path::to_path_buf),
        enterprise_providers_file: enterprise_providers_file.map(Path::to_path_buf),
        auth_jwt_issuer: auth_jwt_issuer.map(ToOwned::to_owned),
        auth_jwt_audience: auth_jwt_audience.map(ToOwned::to_owned),
        admin_token,
        control_url: control_url.map(ToOwned::to_owned),
        control_token: control_token.map(ToOwned::to_owned),
        remote_authority_workload_token: remote_authority_workload_token.map(ToOwned::to_owned),
        control_authority_public_key: control_authority_public_key.cloned(),
        control_authority_trusted_public_keys: control_authority_trusted_public_keys.to_vec(),
        control_authority_successors: remote_authority_successors_from_env()?,
        control_authority_key_log_policy_path: std::env::var_os(
            "CHIO_CONTROL_AUTHORITY_KEY_LOG_POLICY_FILE",
        )
        .map(PathBuf::from),
        control_authority_key_log_verifier_db_path: std::env::var_os(
            "CHIO_CONTROL_AUTHORITY_KEY_LOG_VERIFIER_DB",
        )
        .map(PathBuf::from),
        remote_authority_tenant_id: std::env::var("CHIO_REMOTE_AUTHORITY_TENANT_ID").ok(),
        remote_authority_workload_id: std::env::var("CHIO_REMOTE_AUTHORITY_WORKLOAD_ID").ok(),
        remote_authority_workload_seed_path: std::env::var_os(
            "CHIO_REMOTE_AUTHORITY_WORKLOAD_SEED_FILE",
        )
        .map(PathBuf::from),
        remote_authority_session_admission_seed_path: std::env::var_os(
            "CHIO_REMOTE_AUTHORITY_SESSION_ADMISSION_SEED_FILE",
        )
        .map(PathBuf::from),
        remote_kernel_evidence_seed_path: std::env::var_os(
            "CHIO_REMOTE_KERNEL_EVIDENCE_SEED_FILE",
        )
        .map(PathBuf::from),
        public_base_url: public_base_url.map(ToOwned::to_owned),
        auth_servers: auth_servers.to_vec(),
        auth_authorization_endpoint: auth_authorization_endpoint.map(ToOwned::to_owned),
        auth_token_endpoint: auth_token_endpoint.map(ToOwned::to_owned),
        auth_registration_endpoint: auth_registration_endpoint.map(ToOwned::to_owned),
        auth_jwks_uri: auth_jwks_uri.map(ToOwned::to_owned),
        auth_scopes: auth_scopes.to_vec(),
        auth_subject: auth_subject.to_string(),
        auth_code_ttl_secs,
        auth_access_token_ttl_secs,
        receipt_db_path: receipt_db_path.map(std::path::Path::to_path_buf),
        revocation_db_path: revocation_db_path.map(std::path::Path::to_path_buf),
        authority_seed_path: authority_seed_path.map(std::path::Path::to_path_buf),
        keyring_config_path: keyring_config_path.map(std::path::Path::to_path_buf),
        broker_config_path: broker_config_path.map(std::path::Path::to_path_buf),
        authority_db_path: authority_db_path.map(std::path::Path::to_path_buf),
        budget_db_path: budget_db_path.map(std::path::Path::to_path_buf),
        aggregate_invocation_admission: enable_aggregate_invocation_admission,
        admission_operation_db_path: admission_operation_db_path.map(Path::to_path_buf),
        approval_db_path: approval_db_path.map(Path::to_path_buf),
        approver_directory_path: approver_directory_path.map(Path::to_path_buf),
        threshold_proposal_authority_public_key: threshold_proposal_authority_public_key.cloned(),
        session_db_path: session_db_path.map(std::path::Path::to_path_buf),
        resume_hmac_keyring_path: resume_hmac_keyring_path.map(Path::to_path_buf),
        policy_path: policy_path.to_path_buf(),
        server_id: server_id.to_string(),
        server_name: server_name.unwrap_or(server_id).to_string(),
        server_version: server_version
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .to_string(),
        signed_manifest_path: signed_manifest_path.map(Path::to_path_buf),
        manifest_public_key: manifest_public_key.map(ToOwned::to_owned),
        native_launch_factory: Arc::new(crate::mcp_cli::SignedCagePolicyLaunchFactory::new(
            cage_policy_path.to_path_buf(),
            cage_policy_signer.to_string(),
        )?),
        page_size,
        tools_list_changed,
        shared_hosted_owner,
        wrapped_command: wrapped_cmd.clone(),
        wrapped_args: wrapped_args.to_vec(),
        egress_contract,
    })
}

pub(crate) fn remote_mcp_auth_egress_contract(
    server_id: &str,
    auth_jwt_discovery_url: Option<&str>,
    auth_introspection_url: Option<&str>,
    auth_jwt_provider_profile: Option<remote_mcp::JwtProviderProfile>,
    auth_jwt_issuer: Option<&str>,
    auth_jwks_uri: Option<&str>,
) -> Result<Option<chio_egress_contract::HttpEgressContract>, CliError> {
    let mut urls = Vec::new();
    urls.extend(auth_jwt_discovery_url);
    urls.extend(auth_introspection_url);
    urls.extend(auth_jwks_uri);
    if auth_jwt_provider_profile.is_some() || auth_jwt_discovery_url.is_some() {
        urls.extend(auth_jwt_issuer);
    }
    if urls.is_empty() {
        return Ok(None);
    }

    let mut allowed_schemes = std::collections::BTreeSet::new();
    let mut allowed_authority_set = std::collections::BTreeSet::new();
    let mut deny_loopback = true;
    let mut deny_link_local = true;
    let mut deny_ipv6_ula = true;

    for raw_url in urls {
        let parsed = url::Url::parse(raw_url).map_err(|error| {
            CliError::cli_other_error(format!(
                "remote MCP auth egress URL `{raw_url}` is invalid: {error}"
            ))
        })?;
        allowed_schemes.insert(parsed.scheme().to_ascii_lowercase());
        allowed_authority_set.insert(cli_normalized_url_authority(&parsed)?);

        if let Some(host) = parsed.host() {
            match host {
                url::Host::Domain(domain) => {
                    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
                    if matches!(normalized.as_str(), "localhost" | "localhost.localdomain") {
                        deny_loopback = false;
                    }
                }
                url::Host::Ipv4(address) => {
                    if address.is_loopback() {
                        deny_loopback = false;
                    }
                    if address.is_link_local() {
                        deny_link_local = false;
                    }
                }
                url::Host::Ipv6(address) => {
                    if let Some(mapped) = address.to_ipv4_mapped() {
                        if mapped.is_loopback() {
                            deny_loopback = false;
                        }
                        if mapped.is_link_local() {
                            deny_link_local = false;
                        }
                    }
                    if address.is_loopback() {
                        deny_loopback = false;
                    }
                    if is_cli_ipv6_unicast_link_local(&address) {
                        deny_link_local = false;
                    }
                    if is_cli_ipv6_unique_local(&address) {
                        deny_ipv6_ula = false;
                    }
                }
            }
        }
    }

    let contract = chio_egress_contract::HttpEgressContract {
        tenant_egress_namespace: format!("remote-mcp-auth:{server_id}"),
        allowed_schemes,
        allowed_authority_set,
        deny_loopback,
        deny_link_local,
        deny_ipv6_ula,
        max_redirect_chain: 3,
        max_response_bytes: 1024 * 1024,
    };
    contract.validate().map_err(|error| {
        CliError::cli_other_error(format!(
            "remote MCP auth egress contract is invalid: {error}"
        ))
    })?;
    Ok(Some(contract))
}

pub(crate) fn cli_normalized_url_authority(url: &url::Url) -> Result<String, CliError> {
    let host = url.host_str().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "remote MCP auth egress URL `{url}` is missing an authority"
        ))
    })?;
    let host = match url.host() {
        Some(url::Host::Ipv6(_)) => format!("[{}]", host.to_ascii_lowercase()),
        Some(url::Host::Domain(_)) => host.trim_end_matches('.').to_ascii_lowercase(),
        _ => host.to_ascii_lowercase(),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

pub(crate) fn is_cli_ipv6_unicast_link_local(address: &std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

pub(crate) fn is_cli_ipv6_unique_local(address: &std::net::Ipv6Addr) -> bool {
    (address.segments()[0] & 0xfe00) == 0xfc00
}

pub(crate) fn optional_secret_with_env_fallback(
    value: Option<&str>,
    fallback_env: &str,
) -> Option<String> {
    value.map(ToOwned::to_owned).or_else(|| {
        std::env::var(fallback_env)
            .ok()
            .filter(|value| !value.is_empty())
    })
}

pub(crate) fn require_revocation_db_path(
    revocation_db_path: Option<&Path>,
) -> Result<&Path, CliError> {
    revocation_db_path.ok_or_else(|| {
        CliError::cli_other_error(
            "trust commands require --revocation-db <path> so persisted trust state is explicit"
                .to_string(),
        )
    })
}

pub(crate) fn require_receipt_db_path(receipt_db_path: Option<&Path>) -> Result<&Path, CliError> {
    receipt_db_path.ok_or_else(|| {
        CliError::cli_other_error(
            "shared evidence commands require --receipt-db <path> when --control-url is not set"
                .to_string(),
        )
    })
}

pub(crate) fn parse_cluster_members(
    specs: &[String],
) -> Result<Vec<trust_control::ClusterMemberIdentity>, CliError> {
    specs
        .iter()
        .map(|spec| {
            let (node_url, public_key) = spec.split_once('=').ok_or_else(|| {
                CliError::cli_other_error(
                    "--cluster-member must use URL=ED25519_PUBLIC_KEY form".to_string(),
                )
            })?;
            if node_url.is_empty() || public_key.is_empty() {
                return Err(CliError::cli_other_error(
                    "--cluster-member URL and public key must be non-empty".to_string(),
                ));
            }
            let public_key = chio_core::PublicKey::from_hex(public_key).map_err(|error| {
                CliError::cli_other_error(format!(
                    "--cluster-member has an invalid public key: {error}"
                ))
            })?;
            Ok(trust_control::ClusterMemberIdentity {
                node_url: node_url.to_string(),
                public_key,
            })
        })
        .collect()
}

pub(crate) fn parse_tenant_read_tokens(
    specs: &[String],
) -> Result<std::collections::BTreeMap<String, String>, CliError> {
    let mut parsed = std::collections::BTreeMap::new();
    for spec in specs {
        let (tenant, token) = spec.split_once('=').ok_or_else(|| {
            CliError::cli_other_error("--tenant-read-token must use tenant=token form".to_string())
        })?;
        if tenant.trim() != tenant || token.trim() != token {
            return Err(CliError::cli_other_error(
                "--tenant-read-token tenant and token must not contain surrounding whitespace"
                    .to_string(),
            ));
        }
        if tenant.chars().any(char::is_control) || token.chars().any(char::is_control) {
            return Err(CliError::cli_other_error(
                "--tenant-read-token tenant and token must not contain control characters"
                    .to_string(),
            ));
        }
        if tenant.is_empty() || token.is_empty() {
            return Err(CliError::cli_other_error(
                "--tenant-read-token tenant and token must be non-empty".to_string(),
            ));
        }
        if parsed
            .insert(tenant.to_string(), token.to_string())
            .is_some()
        {
            return Err(CliError::cli_other_error(format!(
                "duplicate --tenant-read-token for tenant {tenant}"
            )));
        }
    }
    Ok(parsed)
}

pub(crate) fn cmd_trust_revoke(
    capability_id: &str,
    json_output: bool,
    revocation_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (newly_revoked, backend_label) = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::service_runtime::client::build_client(url, token)?
            .revoke_capability(capability_id)?;
        (response.newly_revoked, url.to_string())
    } else {
        let path = require_revocation_db_path(revocation_db_path)?;
        let store = chio_store_sqlite::SqliteRevocationStore::open(path)?;
        (store.revoke(capability_id)?, path.display().to_string())
    };

    if json_output {
        let output = serde_json::json!({
            "capability_id": capability_id,
            "revoked": true,
            "newly_revoked": newly_revoked,
            "revocation_backend": backend_label,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("capability_id: {capability_id}");
        println!("revoked:       true");
        println!("newly_revoked: {newly_revoked}");
        println!("backend:       {backend_label}");
    }

    Ok(())
}

pub(crate) fn cmd_trust_status(
    capability_id: &str,
    json_output: bool,
    revocation_db_path: Option<&std::path::Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let (revoked, backend_label) = if let Some(url) = control_url {
        let token = require_control_token(control_token)?;
        let response = trust_control::service_runtime::client::build_client(url, token)?
            .list_revocations(&trust_control::RevocationQuery {
                capability_id: Some(capability_id.to_string()),
                limit: Some(1),
            })?;
        let revoked = response.revoked.ok_or_else(|| {
            CliError::cli_other_error(format!(
                "trust-control revocation response omitted revoked status for {capability_id}"
            ))
        })?;
        (revoked, url.to_string())
    } else {
        let path = require_revocation_db_path(revocation_db_path)?;
        let store = chio_store_sqlite::SqliteRevocationStore::open(path)?;
        (store.is_revoked(capability_id)?, path.display().to_string())
    };

    if json_output {
        let output = serde_json::json!({
            "capability_id": capability_id,
            "revoked": revoked,
            "revocation_backend": backend_label,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else {
        println!("capability_id: {capability_id}");
        println!("revoked:       {revoked}");
        println!("backend:       {backend_label}");
    }

    Ok(())
}
