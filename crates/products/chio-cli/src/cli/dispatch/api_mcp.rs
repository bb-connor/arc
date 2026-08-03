// Dispatch handlers for the `chio api` and `chio mcp` command groups.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_api(
    command: ApiCommands,
    receipt_db: Option<PathBuf>,
    revocation_db: Option<PathBuf>,
    authority_seed_file: Option<PathBuf>,
    budget_db: Option<PathBuf>,
    control_url: Option<String>,
    control_token: Option<String>,
) -> Result<(), CliError> {
    match command {
        ApiCommands::Protect {
            upstream,
            spec,
            listen,
            receipt_store,
            allow_ephemeral_receipts,
            upstream_timeout_secs,
        } => cmd_api_protect(
            &upstream,
            spec.as_deref(),
            &listen,
            receipt_store.as_deref().or(receipt_db.as_deref()),
            authority_seed_file.as_deref(),
            budget_db.as_deref(),
            revocation_db.as_deref(),
            control_url.as_deref(),
            control_token.as_deref(),
            allow_ephemeral_receipts,
            upstream_timeout_secs,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_mcp(
    command: McpCommands,
    receipt_db: Option<PathBuf>,
    revocation_db: Option<PathBuf>,
    authority_seed_file: Option<PathBuf>,
    keyring_config: Option<PathBuf>,
    broker_config: Option<PathBuf>,
    authority_db: Option<PathBuf>,
    budget_db: Option<PathBuf>,
    aggregate_invocation_admission: bool,
    admission_operation_db: Option<PathBuf>,
    approval_db: Option<PathBuf>,
    approver_directory: Option<PathBuf>,
    threshold_proposal_authority_public_key: Option<chio_core::PublicKey>,
    session_db: Option<PathBuf>,
    resume_hmac_keyring: Option<PathBuf>,
    control_url: Option<String>,
    control_token: Option<String>,
    control_authority_public_key: Option<chio_core::PublicKey>,
    control_authority_trusted_public_keys: Vec<chio_core::PublicKey>,
    partition_escrow_authority_descriptor: Option<PathBuf>,
    partition_escrow_authority_signer: Option<chio_core::PublicKey>,
) -> Result<(), CliError> {
    match command {
        McpCommands::Wrap(args) => {
            if keyring_config.is_some()
                || broker_config.is_some()
                || aggregate_invocation_admission
                || admission_operation_db.is_some()
                || approval_db.is_some()
                || approver_directory.is_some()
                || threshold_proposal_authority_public_key.is_some()
            {
                return Err(CliError::cli_other_error(
                    "keyring, broker, and ordinary admission flags require an MCP runtime command"
                        .to_string(),
                ));
            }
            cmd_mcp_wrap(&args)
        }
        McpCommands::GovernedSim(args) => {
            if keyring_config.is_some()
                || broker_config.is_some()
                || aggregate_invocation_admission
                || admission_operation_db.is_some()
                || approval_db.is_some()
                || approver_directory.is_some()
                || threshold_proposal_authority_public_key.is_some()
            {
                return Err(CliError::cli_other_error(
                    "keyring, broker, and ordinary admission flags are not supported by the governed simulation"
                        .to_string(),
                ));
            }
            cmd_mcp_governed_sim(&args)
        }
        McpCommands::Serve {
            policy,
            preset,
            server_id,
            server_name,
            server_version,
            signed_manifest,
            manifest_public_key,
            cage_policy,
            cage_policy_signer,
            page_size,
            tools_list_changed,
            command,
        } => cmd_mcp_serve(
            policy.as_deref(),
            preset.as_deref(),
            &server_id,
            server_name.as_deref(),
            server_version.as_deref(),
            signed_manifest.as_deref(),
            manifest_public_key.as_deref(),
            &cage_policy,
            &cage_policy_signer,
            page_size,
            tools_list_changed,
            &command,
            receipt_db.as_deref(),
            revocation_db.as_deref(),
            authority_seed_file.as_deref(),
            keyring_config.as_deref(),
            broker_config.as_deref(),
            authority_db.as_deref(),
            budget_db.as_deref(),
            aggregate_invocation_admission,
            admission_operation_db.as_deref(),
            approval_db.as_deref(),
            approver_directory.as_deref(),
            threshold_proposal_authority_public_key.as_ref(),
            session_db.as_deref(),
            control_url.as_deref(),
            control_token.as_deref(),
            control_authority_public_key.as_ref(),
            &control_authority_trusted_public_keys,
            partition_escrow_authority_descriptor.as_deref(),
            partition_escrow_authority_signer.as_ref(),
        ),
        McpCommands::ServeHttp {
            policy,
            server_id,
            server_name,
            server_version,
            signed_manifest,
            manifest_public_key,
            cage_policy,
            cage_policy_signer,
            page_size,
            tools_list_changed,
            shared_hosted_owner,
            listen,
            auth_token,
            auth_jwt_public_key,
            auth_jwt_discovery_url,
            auth_introspection_url,
            auth_introspection_client_id,
            auth_introspection_client_secret,
            auth_jwt_provider_profile,
            auth_server_seed_file,
            identity_federation_seed_file,
            enterprise_providers_file,
            auth_jwt_issuer,
            auth_jwt_audience,
            admin_token,
            remote_authority_workload_token,
            public_base_url,
            auth_servers,
            auth_authorization_endpoint,
            auth_token_endpoint,
            auth_registration_endpoint,
            auth_jwks_uri,
            auth_scopes,
            auth_subject,
            auth_code_ttl_secs,
            auth_access_token_ttl_secs,
            command,
        } => cmd_mcp_serve_http(
            &policy,
            &server_id,
            server_name.as_deref(),
            server_version.as_deref(),
            signed_manifest.as_deref(),
            manifest_public_key.as_deref(),
            &cage_policy,
            &cage_policy_signer,
            page_size,
            tools_list_changed,
            shared_hosted_owner,
            listen,
            auth_token.as_deref(),
            auth_jwt_public_key.as_deref(),
            auth_jwt_discovery_url.as_deref(),
            auth_introspection_url.as_deref(),
            auth_introspection_client_id.as_deref(),
            auth_introspection_client_secret.as_deref(),
            auth_jwt_provider_profile,
            auth_server_seed_file.as_deref(),
            identity_federation_seed_file.as_deref(),
            enterprise_providers_file.as_deref(),
            auth_jwt_issuer.as_deref(),
            auth_jwt_audience.as_deref(),
            admin_token.as_deref(),
            remote_authority_workload_token.as_deref(),
            public_base_url.as_deref(),
            &auth_servers,
            auth_authorization_endpoint.as_deref(),
            auth_token_endpoint.as_deref(),
            auth_registration_endpoint.as_deref(),
            auth_jwks_uri.as_deref(),
            &auth_scopes,
            &auth_subject,
            auth_code_ttl_secs,
            auth_access_token_ttl_secs,
            &command,
            receipt_db.as_deref(),
            revocation_db.as_deref(),
            authority_seed_file.as_deref(),
            keyring_config.as_deref(),
            broker_config.as_deref(),
            authority_db.as_deref(),
            budget_db.as_deref(),
            aggregate_invocation_admission,
            admission_operation_db.as_deref(),
            approval_db.as_deref(),
            approver_directory.as_deref(),
            threshold_proposal_authority_public_key.as_ref(),
            session_db.as_deref(),
            resume_hmac_keyring.as_deref(),
            control_url.as_deref(),
            control_token.as_deref(),
            control_authority_public_key.as_ref(),
            &control_authority_trusted_public_keys,
        ),
    }
}
