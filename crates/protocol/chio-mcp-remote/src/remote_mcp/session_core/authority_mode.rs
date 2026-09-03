use super::*;

pub(super) fn uses_pinned_remote_authority(config: &RemoteServeHttpConfig) -> bool {
    config.control_url.is_some()
}

pub(super) fn validate_remote_authority_config(
    config: &RemoteServeHttpConfig,
) -> Result<(), CliError> {
    let remote_only_configured = config.remote_authority_workload_token.is_some()
        || config.control_authority_public_key.is_some()
        || !config.control_authority_trusted_public_keys.is_empty();
    if config.control_url.is_none() {
        if remote_only_configured {
            return Err(CliError::cli_other_error(
                "remote authority workload credentials and key pins require --control-url"
                    .to_string(),
            ));
        }
        return Ok(());
    }

    if config.authority_seed_path.is_some() || config.authority_db_path.is_some() {
        return Err(CliError::cli_other_error(
            "remote capability authority cannot be combined with local authority custody"
                .to_string(),
        ));
    }
    let service_token = config.control_token.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "remote MCP control-plane storage requires --control-token".to_string(),
        )
    })?;
    let workload_token = config
        .remote_authority_workload_token
        .as_deref()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            CliError::cli_other_error(
                "remote MCP capability issuance requires --remote-authority-workload-token"
                    .to_string(),
            )
        })?;
    validated_static_bearer_token(service_token, "--control-token")?;
    validated_static_bearer_token(workload_token, "--remote-authority-workload-token")?;
    if service_token == workload_token
        || config.auth_token.as_deref() == Some(workload_token)
        || config.admin_token.as_deref() == Some(workload_token)
    {
        return Err(CliError::cli_other_error(
            "remote authority workload token must be distinct from service, session, and admin tokens"
                .to_string(),
        ));
    }
    let current = config.control_authority_public_key.as_ref().ok_or_else(|| {
        CliError::cli_other_error(
            "remote MCP capability issuance requires --control-authority-public-key".to_string(),
        )
    })?;
    let mut trusted = config.control_authority_trusted_public_keys.clone();
    trusted.push(current.clone());
    trusted.sort_by_key(PublicKey::to_hex);
    let original_len = trusted.len();
    trusted.dedup();
    if trusted.len() != original_len {
        return Err(CliError::cli_other_error(
            "remote capability-authority key pins must be unique".to_string(),
        ));
    }
    Ok(())
}
