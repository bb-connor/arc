use super::*;

pub(super) fn uses_remote_authority(config: &RemoteServeHttpConfig) -> bool {
    config.control_url.is_some()
        && config.authority_seed_path.is_none()
        && config.authority_db_path.is_none()
        && config.keyring_config_path.is_none()
}

pub(super) fn validate_remote_authority_factory_config(
    config: &RemoteServeHttpConfig,
) -> Result<(), CliError> {
    let remote_identity_configured = config.remote_authority_tenant_id.is_some()
        || config.remote_authority_workload_id.is_some()
        || config.remote_authority_workload_seed_path.is_some()
        || config
            .remote_authority_session_admission_seed_path
            .is_some()
        || config.remote_kernel_evidence_seed_path.is_some();
    let remote_authority_only_configured = remote_identity_configured
        || config.remote_authority_workload_token.is_some()
        || !config.control_authority_successors.is_empty()
        || config.control_authority_key_log_policy_path.is_some()
        || config.control_authority_key_log_verifier_db_path.is_some();
    let shared_remote_control_configured = config.control_token.is_some()
        || config.control_authority_public_key.is_some()
        || !config.control_authority_trusted_public_keys.is_empty();
    let Some(_) = config.control_url.as_deref() else {
        if remote_authority_only_configured || shared_remote_control_configured {
            return Err(CliError::cli_other_error(
                "remote authority identity, signer, token, or pin configuration requires a control URL"
                    .to_string(),
            ));
        }
        return Ok(());
    };

    if !uses_remote_authority(config) {
        if remote_authority_only_configured {
            return Err(CliError::cli_other_error(
                "remote authority workload, signer, successor, or key-log configuration cannot be combined with local authority custody"
                    .to_string(),
            ));
        }
        return Ok(());
    }

    if config.broker_config_path.is_some()
        || config.receipt_db_path.is_some()
        || config.revocation_db_path.is_some()
        || config.budget_db_path.is_some()
        || config.admission_operation_db_path.is_some()
        || config.approval_db_path.is_some()
        || config.aggregate_invocation_admission
    {
        return Err(CliError::cli_other_error(
            "remote authority mode cannot be combined with local receipt, revocation, budget, admission, approval, or broker custody"
                .to_string(),
        ));
    }
    let tenant_id = config.remote_authority_tenant_id.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "remote authority mode requires a fixed workload tenant id".to_string(),
        )
    })?;
    let workload_id = config
        .remote_authority_workload_id
        .as_deref()
        .ok_or_else(|| {
            CliError::cli_other_error(
                "remote authority mode requires a fixed workload id".to_string(),
            )
        })?;
    if tenant_id.is_empty()
        || tenant_id.trim() != tenant_id
        || workload_id.is_empty()
        || workload_id.trim() != workload_id
    {
        return Err(CliError::cli_other_error(
            "remote authority workload tenant and workload ids must be nonempty and canonical"
                .to_string(),
        ));
    }
    if config.control_token.as_deref().is_none_or(str::is_empty)
        || config
            .remote_authority_workload_token
            .as_deref()
            .is_none_or(str::is_empty)
        || config.control_authority_public_key.is_none()
        || config.remote_authority_workload_seed_path.is_none()
        || config
            .remote_authority_session_admission_seed_path
            .is_none()
        || config.remote_kernel_evidence_seed_path.is_none()
        || config.control_authority_key_log_policy_path.is_none()
        || config.control_authority_key_log_verifier_db_path.is_none()
    {
        return Err(CliError::cli_other_error(
            "remote authority mode requires distinct service and workload tokens, an exact current authority pin, workload signer seed, session-admission signer seed, kernel evidence seed, public key-log policy, and existing verifier database"
                .to_string(),
        ));
    }
    if config.control_token == config.remote_authority_workload_token
        || config.auth_token == config.remote_authority_workload_token
        || config.admin_token == config.remote_authority_workload_token
    {
        return Err(CliError::cli_other_error(
            "remote authority workload token must be distinct from service, session, and admin tokens"
                .to_string(),
        ));
    }
    trust_control::service_runtime::PinnedControlAuthority::with_successors(
        config
            .control_authority_public_key
            .clone()
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "remote authority current signer pin is unavailable".to_string(),
                )
            })?,
        config.control_authority_trusted_public_keys.clone(),
        config.control_authority_successors.clone(),
    )?;
    Ok(())
}

pub(super) fn validate_remote_authority_role_keys(
    config: &RemoteServeHttpConfig,
    workload_key: &PublicKey,
    session_admission_key: &PublicKey,
    kernel_evidence_key: &PublicKey,
) -> Result<(), CliError> {
    let authority_role_keys = config
        .control_authority_public_key
        .iter()
        .chain(config.control_authority_trusted_public_keys.iter())
        .chain(
            config
                .control_authority_successors
                .iter()
                .map(|successor| &successor.public_key),
        )
        .collect::<Vec<_>>();
    if workload_key == session_admission_key
        || workload_key == kernel_evidence_key
        || session_admission_key == kernel_evidence_key
        || authority_role_keys.contains(&workload_key)
        || authority_role_keys.contains(&session_admission_key)
        || authority_role_keys.contains(&kernel_evidence_key)
    {
        return Err(CliError::cli_other_error(
            "remote authority, workload request, session-admission, and kernel evidence signer roles require distinct keys"
                .to_string(),
        ));
    }
    Ok(())
}
