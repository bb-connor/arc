#[derive(Serialize)]
struct RemoteAuthContractFingerprint {
    mode: &'static str,
    issuer: Option<String>,
    audience: Option<String>,
    required_scopes: Vec<String>,
    provider_profile: String,
    static_token_fingerprint: Option<String>,
    verification_key_identity: Option<String>,
    discovery_url: Option<String>,
    introspection_url: Option<String>,
    enterprise_provider_registry_hash: Option<String>,
    authority_keyring_config_hash: Option<String>,
}

fn configured_file_hash(path: Option<&FsPath>) -> Result<Option<String>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = std::fs::read(path)?;
    Ok(Some(sha256_hex(&bytes)))
}

fn stable_upstream_file_hash(path: &FsPath, label: &str) -> Result<String, CliError> {
    let path_metadata = std::fs::symlink_metadata(path).map_err(|error| {
        CliError::cli_other_error(format!(
            "inspect {label} path `{}`: {error}",
            path.display()
        ))
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(CliError::cli_other_error(format!(
            "{label} `{}` is not a regular non-symlink file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if path_metadata.permissions().mode() & 0o022 != 0 {
            return Err(CliError::cli_other_error(format!(
                "{label} `{}` is group- or world-writable",
                path.display()
            )));
        }
    }
    let mut file = std::fs::File::open(path).map_err(|error| {
        CliError::cli_other_error(format!("open {label} `{}`: {error}", path.display()))
    })?;
    let descriptor_metadata = file.metadata().map_err(|error| {
        CliError::cli_other_error(format!(
            "inspect open {label} `{}`: {error}",
            path.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if descriptor_metadata.dev() != path_metadata.dev()
            || descriptor_metadata.ino() != path_metadata.ino()
        {
            return Err(CliError::cli_other_error(format!(
                "{label} `{}` changed before it was opened",
                path.display()
            )));
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        CliError::cli_other_error(format!("read {label} `{}`: {error}", path.display()))
    })?;
    let final_path_metadata = std::fs::symlink_metadata(path).map_err(|error| {
        CliError::cli_other_error(format!(
            "reinspect {label} path `{}`: {error}",
            path.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if descriptor_metadata.dev() != final_path_metadata.dev()
            || descriptor_metadata.ino() != final_path_metadata.ino()
        {
            return Err(CliError::cli_other_error(format!(
                "{label} `{}` changed while it was hashed",
                path.display()
            )));
        }
    }
    let bytes_len = u64::try_from(bytes.len()).map_err(|_| {
        CliError::cli_other_error(format!(
            "{label} `{}` length exceeds the resumable identity limit",
            path.display()
        ))
    })?;
    if descriptor_metadata.len() != bytes_len
        || final_path_metadata.len() != descriptor_metadata.len()
    {
        return Err(CliError::cli_other_error(format!(
            "{label} `{}` changed length while it was hashed",
            path.display()
        )));
    }
    Ok(sha256_hex(&bytes))
}

fn resolve_remote_upstream_executable(command: &str) -> Result<PathBuf, CliError> {
    if command.is_empty() {
        return Err(CliError::cli_other_error(
            "remote MCP upstream command is empty".to_string(),
        ));
    }
    let command_path = FsPath::new(command);
    let candidate = if command_path.is_absolute() || command_path.components().count() > 1 {
        command_path.to_path_buf()
    } else {
        let path = std::env::var_os("PATH").ok_or_else(|| {
            CliError::cli_other_error(
                "remote MCP upstream command cannot be resolved without PATH".to_string(),
            )
        })?;
        std::env::split_paths(&path)
            .map(|directory| directory.join(command_path))
            .find(|candidate| std::fs::metadata(candidate).is_ok_and(|metadata| metadata.is_file()))
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "remote MCP upstream command `{command}` is not a regular file on PATH"
                ))
            })?
    };
    let canonical = std::fs::canonicalize(&candidate).map_err(|error| {
        CliError::cli_other_error(format!(
            "canonicalize remote MCP upstream command `{}`: {error}",
            candidate.display()
        ))
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| {
        CliError::cli_other_error(format!(
            "inspect remote MCP upstream command `{}`: {error}",
            canonical.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(CliError::cli_other_error(format!(
            "remote MCP upstream command `{}` is not a regular file",
            canonical.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(CliError::cli_other_error(format!(
                "remote MCP upstream command `{}` is not executable",
                canonical.display()
            )));
        }
    }
    Ok(canonical)
}

fn canonicalize_remote_upstream_command(
    config: &mut RemoteServeHttpConfig,
) -> Result<(), CliError> {
    let executable = resolve_remote_upstream_executable(&config.wrapped_command)?;
    config.wrapped_command = executable
        .to_str()
        .ok_or_else(|| {
            CliError::cli_other_error(
                "remote MCP upstream executable path is not valid UTF-8".to_string(),
            )
        })?
        .to_string();
    Ok(())
}

fn upstream_argument_file_identities(
    config: &RemoteServeHttpConfig,
) -> Result<Vec<Value>, CliError> {
    let current_directory = std::env::current_dir().map_err(|error| {
        CliError::cli_other_error(format!(
            "inspect remote MCP upstream working directory: {error}"
        ))
    })?;
    let mut identities = Vec::new();
    for (index, argument) in config.wrapped_args.iter().enumerate() {
        if argument.starts_with('-') {
            continue;
        }
        let path = FsPath::new(argument);
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            current_directory.join(path)
        };
        let Ok(metadata) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let canonical = std::fs::canonicalize(&candidate).map_err(|error| {
            CliError::cli_other_error(format!(
                "canonicalize remote MCP upstream argument file `{}`: {error}",
                candidate.display()
            ))
        })?;
        let digest = stable_upstream_file_hash(&canonical, "remote MCP upstream argument file")?;
        identities.push(json!({
            "argument_index": index,
            "canonical_path": canonical,
            "sha256": digest,
        }));
    }
    Ok(identities)
}

fn fingerprint_remote_auth_contract(
    config: &RemoteServeHttpConfig,
    broker_contract_digest: Option<&str>,
    runtime_contract_digest: &str,
) -> Result<String, CliError> {
    let provider_profile = config
        .auth_jwt_provider_profile
        .unwrap_or(JwtProviderProfile::Generic);
    let enterprise_provider_registry_hash =
        configured_file_hash(config.enterprise_providers_file.as_deref())?;
    let authority_keyring_config_hash =
        configured_file_hash(config.keyring_config_path.as_deref())?;
    let fingerprint = if let Some(token) = config.auth_token.as_deref() {
        RemoteAuthContractFingerprint {
            mode: "static_bearer",
            issuer: None,
            audience: None,
            required_scopes: Vec::new(),
            provider_profile: format!("{provider_profile:?}"),
            static_token_fingerprint: Some(sha256_hex(token.as_bytes())),
            verification_key_identity: None,
            discovery_url: None,
            introspection_url: None,
            enterprise_provider_registry_hash,
            authority_keyring_config_hash,
        }
    } else if let Some(seed_path) = config.auth_server_seed_path.as_deref() {
        let verification_key_identity = authority_public_key_from_seed_file(seed_path)?
            .map(|public_key| public_key.to_hex())
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "auth server seed file `{}` did not yield a public key",
                    seed_path.display()
                ))
            })?;
        RemoteAuthContractFingerprint {
            mode: "jwt_bearer",
            issuer: config.auth_jwt_issuer.clone(),
            audience: config.auth_jwt_audience.clone(),
            required_scopes: config.auth_scopes.clone(),
            provider_profile: format!("{provider_profile:?}"),
            static_token_fingerprint: None,
            verification_key_identity: Some(verification_key_identity),
            discovery_url: None,
            introspection_url: None,
            enterprise_provider_registry_hash,
            authority_keyring_config_hash,
        }
    } else if let Some(introspection_url) = config.auth_introspection_url.as_deref() {
        RemoteAuthContractFingerprint {
            mode: "introspection_bearer",
            issuer: config.auth_jwt_issuer.clone(),
            audience: config.auth_jwt_audience.clone(),
            required_scopes: config.auth_scopes.clone(),
            provider_profile: format!("{provider_profile:?}"),
            static_token_fingerprint: None,
            verification_key_identity: None,
            discovery_url: config.auth_jwt_discovery_url.clone(),
            introspection_url: Some(introspection_url.to_string()),
            enterprise_provider_registry_hash,
            authority_keyring_config_hash,
        }
    } else {
        RemoteAuthContractFingerprint {
            mode: "jwt_bearer",
            issuer: config.auth_jwt_issuer.clone(),
            audience: config.auth_jwt_audience.clone(),
            required_scopes: config.auth_scopes.clone(),
            provider_profile: format!("{provider_profile:?}"),
            static_token_fingerprint: None,
            verification_key_identity: config.auth_jwt_public_key.clone(),
            discovery_url: config.auth_jwt_discovery_url.clone(),
            introspection_url: None,
            enterprise_provider_registry_hash,
            authority_keyring_config_hash,
        }
    };

    let encoded = canonical_json_bytes(&json!({
        "auth_contract": fingerprint,
        "broker_product_contract": broker_contract_digest,
        "runtime_contract": runtime_contract_digest,
    }))
    .map_err(|error| {
        CliError::cli_other_error(format!("serialize auth contract fingerprint: {error}"))
    })?;
    Ok(sha256_hex(&encoded))
}

fn fingerprint_remote_policy_contract(
    loaded_policy: &LoadedPolicy,
    config: &RemoteServeHttpConfig,
    broker_contract_digest: Option<&str>,
    runtime_contract_digest: &str,
) -> Result<String, CliError> {
    let fingerprint = json!({
        "format": loaded_policy.format_name(),
        "identity": {
            "source_hash": loaded_policy.identity.source_hash,
            "runtime_hash": loaded_policy.identity.runtime_hash,
        },
        "default_capabilities": loaded_policy.default_capabilities,
        "issuance_policy": loaded_policy.issuance_policy,
        "runtime_assurance_policy": loaded_policy.runtime_assurance_policy,
        "aggregate_invocation_admission": config.aggregate_invocation_admission,
        "broker_product_contract": broker_contract_digest,
        "runtime_contract": runtime_contract_digest,
    });
    let encoded = canonical_json_bytes(&fingerprint).map_err(|error| {
        CliError::cli_other_error(format!(
            "serialize resumable policy contract fingerprint: {error}"
        ))
    })?;
    Ok(sha256_hex(&encoded))
}

fn fingerprint_remote_runtime_contract(
    config: &RemoteServeHttpConfig,
    manifest_registry: &VerifiedManifestRegistry,
) -> Result<String, CliError> {
    let remote_authority_successors = config
        .control_authority_successors
        .iter()
        .map(|successor| {
            json!({
                "generation": successor.generation,
                "public_key": successor.public_key.to_hex(),
            })
        })
        .collect::<Vec<_>>();
    let remote_authority_trusted_keys = config
        .control_authority_trusted_public_keys
        .iter()
        .map(PublicKey::to_hex)
        .collect::<Vec<_>>();
    let remote_workload_signer_hash =
        configured_file_hash(config.remote_authority_workload_seed_path.as_deref())?;
    let remote_session_admission_signer_hash = configured_file_hash(
        config
            .remote_authority_session_admission_seed_path
            .as_deref(),
    )?;
    let remote_kernel_evidence_signer_hash =
        configured_file_hash(config.remote_kernel_evidence_seed_path.as_deref())?;
    let native_launch_authorization_digest = config
        .native_launch_factory
        .authorization_contract_digest()
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "bind remote MCP native launch authorization: {error}"
            ))
        })?;
    let upstream_executable = resolve_remote_upstream_executable(&config.wrapped_command)?;
    let upstream_executable_digest =
        stable_upstream_file_hash(&upstream_executable, "remote MCP upstream executable")?;
    let upstream_working_directory =
        std::fs::canonicalize(std::env::current_dir()?).map_err(|error| {
            CliError::cli_other_error(format!(
                "canonicalize remote MCP upstream working directory: {error}"
            ))
        })?;
    let argument_file_identities = upstream_argument_file_identities(config)?;
    let mut admitted_manifests = Vec::new();
    for signed in manifest_registry.verified_manifests() {
        let manifest_bytes = canonical_json_bytes(&signed.manifest).map_err(|error| {
            CliError::cli_other_error(format!(
                "serialize admitted manifest for resume binding: {error}"
            ))
        })?;
        let signed_bytes = canonical_json_bytes(signed).map_err(|error| {
            CliError::cli_other_error(format!(
                "serialize signed manifest for resume binding: {error}"
            ))
        })?;
        let mut tool_admissions = Vec::new();
        for tool in &signed.manifest.tools {
            let security = manifest_registry
                .tool_security(&signed.manifest.server_id, &tool.name)
                .ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "admitted registry lost security binding for {}/{}",
                        signed.manifest.server_id, tool.name
                    ))
                })?;
            let bridge = manifest_registry
                .bridge_security(&signed.manifest.server_id, &tool.name)
                .ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "admitted registry lost bridge binding for {}/{}",
                        signed.manifest.server_id, tool.name
                    ))
                })?;
            tool_admissions.push(json!({
                "tool_name": tool.name,
                "bridge_security": bridge,
                "effective_egress": security.effective_egress(),
                "policy_clearances": security.policy_clearances(),
                "manifest_clearance": security.manifest_clearance(),
                "effective_output_floor": security.effective_output_floor(),
                "declassification_purposes": security.declassification_purposes(),
            }));
        }
        let mut server_tool_admissions = Vec::new();
        for server_tool in &signed.manifest.server_tools {
            let tool_name = server_tool.as_str();
            let security = manifest_registry
                .tool_security_for_server_tool(&signed.manifest.server_id, tool_name)
                .ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "admitted registry lost server-tool binding for {}/{}",
                        signed.manifest.server_id, tool_name
                    ))
                })?;
            let bridge = manifest_registry
                .bridge_security_for_server_tool(&signed.manifest.server_id, tool_name)
                .ok_or_else(|| {
                    CliError::cli_other_error(format!(
                        "admitted registry lost server-tool bridge binding for {}/{}",
                        signed.manifest.server_id, tool_name
                    ))
                })?;
            server_tool_admissions.push(json!({
                "tool_name": tool_name,
                "bridge_security": bridge,
                "effective_egress": security.effective_egress(),
                "policy_clearances": security.policy_clearances(),
                "manifest_clearance": security.manifest_clearance(),
                "effective_output_floor": security.effective_output_floor(),
                "declassification_purposes": security.declassification_purposes(),
            }));
        }
        admitted_manifests.push(json!({
            "server_id": signed.manifest.server_id,
            "manifest_sha256": sha256_hex(&manifest_bytes),
            "signed_manifest_sha256": sha256_hex(&signed_bytes),
            "publisher_public_key": signed.manifest.public_key,
            "signer_key": signed.signer_key,
            "tools": tool_admissions,
            "server_tools": server_tool_admissions,
        }));
    }
    let contract = json!({
        "schema": "chio.remote-mcp.resume-runtime-contract.v1",
        "service": {
            "server_id": config.server_id,
            "server_name": config.server_name,
            "server_version": config.server_version,
        },
        "remote_authority": {
            "control_url": config.control_url,
            "current_public_key": config
                .control_authority_public_key
                .as_ref()
                .map(PublicKey::to_hex),
            "trusted_historical_public_keys": remote_authority_trusted_keys,
            "successors": remote_authority_successors,
            "tenant_id": config.remote_authority_tenant_id,
            "workload_id": config.remote_authority_workload_id,
            "workload_signer_seed_sha256": remote_workload_signer_hash,
            "session_admission_signer_seed_sha256": remote_session_admission_signer_hash,
            "kernel_evidence_signer_seed_sha256": remote_kernel_evidence_signer_hash,
        },
        "upstream": {
            "wrapped_command": upstream_executable,
            "wrapped_command_sha256": upstream_executable_digest,
            "working_directory": upstream_working_directory,
            "wrapped_args": config.wrapped_args,
            "argument_file_identities": argument_file_identities,
            "shared_hosted_owner": config.shared_hosted_owner,
            "native_launch_authorization_sha256": native_launch_authorization_digest,
        },
        "admitted_registry": admitted_manifests,
    });
    let encoded = canonical_json_bytes(&contract).map_err(|error| {
        CliError::cli_other_error(format!(
            "serialize resumable runtime contract fingerprint: {error}"
        ))
    })?;
    Ok(sha256_hex(&encoded))
}

fn derive_session_agent_keypair(
    config: &RemoteServeHttpConfig,
    auth_context: &SessionAuthContext,
) -> Result<Keypair, CliError> {
    let Some(seed_path) = config.identity_federation_seed_path.as_deref() else {
        return Ok(Keypair::generate());
    };
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal: Some(principal),
            ..
        } => derive_federated_agent_keypair(seed_path, principal),
        _ => Ok(Keypair::generate()),
    }
}

#[derive(Serialize)]
struct RemoteSessionResumeIntegrityEnvelope<'a> {
    schema: &'static str,
    session_id: &'a str,
    kernel_session_id: &'a SessionId,
    agent_id: &'a str,
    auth_context: &'a SessionAuthContext,
    auth_mode_fingerprint: Option<&'a str>,
    policy_fingerprint: Option<&'a str>,
    hosted_isolation: RemoteHostedIsolationMode,
    capability_issuance_binding: &'a RemoteCapabilityIssuanceBinding,
    lifecycle: &'a RemoteSessionLifecycleSnapshot,
    protocol_version: Option<&'a str>,
    peer_capabilities: &'a PeerCapabilities,
    initialize_params: &'a Value,
    issued_capabilities: &'a [CapabilityToken],
    resume_generation: u64,
    key_id: &'a str,
    key_version: u64,
}

#[derive(Serialize)]
struct RemoteSessionTombstoneIntegrityEnvelope<'a> {
    schema: &'static str,
    record: &'a RemoteSessionDiagnosticRecord,
    resume_generation: u64,
    terminal_epoch: u64,
    key_id: &'a str,
    key_version: u64,
}

#[derive(Serialize)]
struct RemoteSessionTerminalFenceIntegrityEnvelope<'a> {
    schema: &'static str,
    session_id: &'a str,
    terminal_at: u64,
    terminal_state: RemoteSessionState,
    resume_generation: u64,
    terminal_epoch: u64,
    key_id: &'a str,
    key_version: u64,
}

#[cfg(unix)]
fn resume_hmac_keyring_owner_is_trusted(owner_uid: u32, effective_uid: u32) -> bool {
    owner_uid == effective_uid || owner_uid == 0
}

#[cfg(unix)]
fn read_resume_hmac_keyring_file(path: &FsPath) -> Result<Zeroizing<Vec<u8>>, CliError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use rustix::fs::{Mode, OFlags};

    const MAX_KEYRING_BYTES: u64 = 64 * 1_024;

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "open remote MCP resume HMAC keyring {} without following links: {error}",
            path.display()
        ))
    })?;
    let mut file = std::fs::File::from(descriptor);
    let metadata = file.metadata().map_err(|error| {
        CliError::cli_other_error(format!(
            "inspect open remote MCP resume HMAC keyring {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(CliError::cli_other_error(format!(
            "remote MCP resume HMAC keyring {} must be a regular non-symlink file",
            path.display()
        )));
    }
    if metadata.len() > MAX_KEYRING_BYTES {
        return Err(CliError::cli_other_error(format!(
            "remote MCP resume HMAC keyring {} exceeds 64 KiB",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CliError::cli_other_error(format!(
            "remote MCP resume HMAC keyring {} must not be group- or world-accessible",
            path.display()
        )));
    }
    let effective_uid = rustix::process::geteuid().as_raw();
    if !resume_hmac_keyring_owner_is_trusted(metadata.uid(), effective_uid) {
        return Err(CliError::cli_other_error(format!(
            "remote MCP resume HMAC keyring {} must be owned by effective UID {} or root",
            path.display(),
            effective_uid
        )));
    }
    if metadata.nlink() != 1 {
        return Err(CliError::cli_other_error(format!(
            "remote MCP resume HMAC keyring {} must have exactly one hard link",
            path.display()
        )));
    }

    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        CliError::cli_other_error(format!(
            "remote MCP resume HMAC keyring {} length is not representable",
            path.display()
        ))
    })?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(capacity));
    std::io::Read::by_ref(&mut file)
        .take(MAX_KEYRING_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "read remote MCP resume HMAC keyring {}: {error}",
                path.display()
            ))
        })?;
    let encoded_len = u64::try_from(encoded.len()).map_err(|_| {
        CliError::cli_other_error(format!(
            "remote MCP resume HMAC keyring {} length is not representable",
            path.display()
        ))
    })?;
    if encoded_len > MAX_KEYRING_BYTES {
        return Err(CliError::cli_other_error(format!(
            "remote MCP resume HMAC keyring {} exceeds 64 KiB",
            path.display()
        )));
    }
    let final_metadata = file.metadata().map_err(|error| {
        CliError::cli_other_error(format!(
            "reinspect open remote MCP resume HMAC keyring {}: {error}",
            path.display()
        ))
    })?;
    if final_metadata.dev() != metadata.dev()
        || final_metadata.ino() != metadata.ino()
        || final_metadata.len() != metadata.len()
        || final_metadata.len() != encoded_len
        || final_metadata.mtime() != metadata.mtime()
        || final_metadata.mtime_nsec() != metadata.mtime_nsec()
        || final_metadata.ctime() != metadata.ctime()
        || final_metadata.ctime_nsec() != metadata.ctime_nsec()
        || final_metadata.permissions().mode() != metadata.permissions().mode()
        || final_metadata.uid() != metadata.uid()
        || final_metadata.nlink() != metadata.nlink()
    {
        return Err(CliError::cli_other_error(format!(
            "remote MCP resume HMAC keyring {} changed while it was read",
            path.display()
        )));
    }
    Ok(encoded)
}

#[cfg(not(unix))]
fn read_resume_hmac_keyring_file(path: &FsPath) -> Result<Zeroizing<Vec<u8>>, CliError> {
    Err(CliError::cli_other_error(format!(
        "remote MCP resume HMAC keyring {} cannot be loaded securely on this platform",
        path.display()
    )))
}

fn load_resume_hmac_keyring(
    config: &RemoteServeHttpConfig,
) -> Result<Option<Arc<RemoteSessionHmacKeyring>>, CliError> {
    load_resume_hmac_keyring_at(config, session_now_millis())
}

fn load_resume_hmac_keyring_at(
    config: &RemoteServeHttpConfig,
    now: u64,
) -> Result<Option<Arc<RemoteSessionHmacKeyring>>, CliError> {
    let Some(path) = config.resume_hmac_keyring_path.as_deref() else {
        if config.session_db_path.is_some() {
            return Err(CliError::cli_other_error(
                "durable MCP session resume requires --resume-hmac-keyring with a dedicated stable key"
                    .to_string(),
            ));
        }
        return Ok(None);
    };
    let encoded = read_resume_hmac_keyring_file(path)?;
    let mut deserializer = serde_json::Deserializer::from_slice(encoded.as_slice());
    let keyring_file = RemoteSessionHmacKeyringFile::deserialize(&mut deserializer).map_err(
        |error| {
            CliError::cli_other_error(format!(
                "parse strict remote MCP resume HMAC keyring {}: {error}",
                path.display()
            ))
        },
    )?;
    deserializer.end().map_err(|error| {
        CliError::cli_other_error(format!(
            "parse strict remote MCP resume HMAC keyring {}: {error}",
            path.display()
        ))
    })?;
    if keyring_file.schema != REMOTE_SESSION_HMAC_KEYRING_SCHEMA {
        return Err(CliError::cli_other_error(format!(
            "remote MCP resume HMAC keyring {} has unsupported schema {}",
            path.display(),
            keyring_file.schema
        )));
    }
    if keyring_file.previous.len() > MAX_REMOTE_SESSION_HMAC_PREVIOUS_KEYS {
        return Err(CliError::cli_other_error(format!(
            "remote MCP resume HMAC keyring {} exceeds the {}-key verification grace bound",
            path.display(),
            MAX_REMOTE_SESSION_HMAC_PREVIOUS_KEYS
        )));
    }
    let current = decode_resume_hmac_key(
        &keyring_file.current.key_id,
        keyring_file.current.version,
        &keyring_file.current.key_base64,
        None,
    )?;
    let mut previous = Vec::with_capacity(keyring_file.previous.len());
    let mut identities = BTreeMap::new();
    identities.insert((current.key_id.clone(), current.version), ());
    for old in &keyring_file.previous {
        if old.version >= current.version {
            return Err(CliError::cli_other_error(format!(
                "remote MCP resume HMAC grace key {} version {} is not older than current version {}",
                old.key_id, old.version, current.version
            )));
        }
        if old.verify_until_millis > now.saturating_add(MAX_REMOTE_SESSION_HMAC_GRACE_MILLIS) {
            return Err(CliError::cli_other_error(format!(
                "remote MCP resume HMAC grace key {} version {} exceeds the seven-day verification window",
                old.key_id, old.version
            )));
        }
        if identities
            .insert((old.key_id.clone(), old.version), ())
            .is_some()
        {
            return Err(CliError::cli_other_error(format!(
                "remote MCP resume HMAC key identity {} version {} is duplicated",
                old.key_id, old.version
            )));
        }
        previous.push(decode_resume_hmac_key(
            &old.key_id,
            old.version,
            &old.key_base64,
            Some(old.verify_until_millis),
        )?);
    }
    Ok(Some(Arc::new(RemoteSessionHmacKeyring {
        current,
        previous,
    })))
}

fn decode_resume_hmac_key(
    key_id: &str,
    version: u64,
    key_base64: &str,
    verify_until_millis: Option<u64>,
) -> Result<RemoteSessionHmacKey, CliError> {
    if key_id.is_empty()
        || key_id.len() > 64
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(CliError::cli_other_error(
            "remote MCP resume HMAC key ID must be 1-64 ASCII letters, digits, dots, underscores, or hyphens"
                .to_string(),
        ));
    }
    if version == 0 {
        return Err(CliError::cli_other_error(format!(
            "remote MCP resume HMAC key {key_id} has zero version"
        )));
    }
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(key_base64.as_bytes()).map_err(|_| {
        CliError::cli_other_error(format!(
            "remote MCP resume HMAC key {key_id} version {version} is not canonical unpadded base64url"
        ))
    })?);
    if decoded.len() != 32 {
        return Err(CliError::cli_other_error(format!(
            "remote MCP resume HMAC key {key_id} version {version} must decode to exactly 32 bytes"
        )));
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(decoded.as_slice());
    if URL_SAFE_NO_PAD.encode(key.as_slice()) != key_base64 {
        return Err(CliError::cli_other_error(format!(
            "remote MCP resume HMAC key {key_id} version {version} is not canonical unpadded base64url"
        )));
    }
    Ok(RemoteSessionHmacKey {
        key_id: key_id.to_string(),
        version,
        key,
        verify_until_millis,
    })
}

fn expected_resume_agent_id(
    config: &RemoteServeHttpConfig,
    auth_context: &SessionAuthContext,
) -> Result<Option<String>, CliError> {
    let Some(seed_path) = config.identity_federation_seed_path.as_deref() else {
        return Ok(None);
    };
    match &auth_context.method {
        SessionAuthMethod::OAuthBearer {
            principal: Some(principal),
            ..
        } => Ok(Some(
            derive_federated_agent_keypair(seed_path, principal)?
                .public_key()
                .to_hex(),
        )),
        _ => Ok(None),
    }
}

fn compute_resume_record_integrity_tag(
    key: &RemoteSessionHmacKey,
    record: &RemoteSessionResumeRecord,
) -> Result<String, CliError> {
    let envelope = RemoteSessionResumeIntegrityEnvelope {
        schema: "chio.remote-mcp.resume-record-integrity.v2",
        session_id: &record.session_id,
        kernel_session_id: &record.kernel_session_id,
        agent_id: &record.agent_id,
        auth_context: &record.auth_context,
        auth_mode_fingerprint: record.auth_mode_fingerprint.as_deref(),
        policy_fingerprint: record.policy_fingerprint.as_deref(),
        hosted_isolation: record.hosted_isolation,
        capability_issuance_binding: &record.capability_issuance_binding,
        lifecycle: &record.lifecycle,
        protocol_version: record.protocol_version.as_deref(),
        peer_capabilities: &record.peer_capabilities,
        initialize_params: &record.initialize_params,
        issued_capabilities: &record.issued_capabilities,
        resume_generation: record.resume_generation,
        key_id: &record.resume_integrity.key_id,
        key_version: record.resume_integrity.key_version,
    };
    compute_remote_session_hmac(
        REMOTE_SESSION_RESUME_RECORD_HMAC_LABEL,
        key.key.as_slice(),
        &envelope,
        "resumable session envelope",
    )
}

#[cfg(test)]
fn validate_resume_record_integrity(
    config: &RemoteServeHttpConfig,
    record: &RemoteSessionResumeRecord,
) -> Result<(), CliError> {
    let keyring = load_resume_hmac_keyring(config)?.ok_or_else(|| {
        CliError::cli_other_error(format!(
            "stored MCP session {} cannot be restored without a dedicated resume HMAC keyring",
            record.session_id
        ))
    })?;
    validate_resume_record_integrity_with_keyring(&keyring, record, session_now_millis())
}

fn validate_resume_record_integrity_with_keyring(
    keyring: &RemoteSessionHmacKeyring,
    record: &RemoteSessionResumeRecord,
    now: u64,
) -> Result<(), CliError> {
    if record.resume_generation == 0 {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} has an invalid zero resume generation",
            record.session_id
        )));
    }
    let key = keyring.verification_key(&record.resume_integrity, now).ok_or_else(|| {
        CliError::cli_other_error(format!(
            "stored MCP session {} uses an unknown or expired resume HMAC key {} version {}",
            record.session_id,
            record.resume_integrity.key_id,
            record.resume_integrity.key_version
        ))
    })?;
    let expected_tag = compute_resume_record_integrity_tag(key, record)?;
    verify_remote_session_hmac(
        &expected_tag,
        &record.resume_integrity.tag,
        &record.session_id,
        "resumable integrity",
    )
}

impl RemoteSessionHmacKeyring {
    fn verification_key(
        &self,
        integrity: &RemoteSessionIntegrityTag,
        now: u64,
    ) -> Option<&RemoteSessionHmacKey> {
        if self.current.key_id == integrity.key_id
            && self.current.version == integrity.key_version
        {
            return Some(&self.current);
        }
        self.previous.iter().find(|key| {
            key.key_id == integrity.key_id
                && key.version == integrity.key_version
                && key.verify_until_millis.is_some_and(|until| now <= until)
        })
    }

    fn empty_tag_for_current(&self) -> RemoteSessionIntegrityTag {
        RemoteSessionIntegrityTag {
            key_id: self.current.key_id.clone(),
            key_version: self.current.version,
            tag: String::new(),
        }
    }
}

fn compute_remote_session_hmac<T: Serialize>(
    label: &[u8],
    key: &[u8],
    envelope: &T,
    description: &str,
) -> Result<String, CliError> {
    let canonical = canonical_json_bytes(envelope).map_err(|error| {
        CliError::cli_other_error(format!("serialize {description}: {error}"))
    })?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| {
        CliError::cli_other_error("initialize remote session HMAC".to_string())
    })?;
    mac.update(label);
    mac.update(&[0]);
    mac.update(&canonical);
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn verify_remote_session_hmac(
    expected: &str,
    stored: &str,
    session_id: &str,
    description: &str,
) -> Result<(), CliError> {
    let decode_tag = |encoded: &str| -> Option<Zeroizing<[u8; 32]>> {
        let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded.as_bytes()).ok()?);
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != encoded {
            return None;
        }
        let mut tag = Zeroizing::new([0_u8; 32]);
        tag.copy_from_slice(decoded.as_slice());
        Some(tag)
    };
    let expected = decode_tag(expected).ok_or_else(|| {
        CliError::cli_other_error("internal remote session HMAC encoding failed".to_string())
    })?;
    let stored = decode_tag(stored).ok_or_else(|| {
        CliError::cli_other_error(format!(
            "stored MCP session {session_id} failed {description} validation"
        ))
    })?;
    if !bool::from(expected.as_slice().ct_eq(stored.as_slice())) {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {session_id} failed {description} validation"
        )));
    }
    Ok(())
}

fn sign_terminal_session_records(
    keyring: &RemoteSessionHmacKeyring,
    record: RemoteSessionDiagnosticRecord,
    resume_generation: u64,
    terminal_epoch: u64,
) -> Result<(RemoteSessionTombstoneRecord, RemoteSessionTerminalFence), CliError> {
    if resume_generation == 0 || terminal_epoch == 0 || terminal_epoch != resume_generation {
        return Err(CliError::cli_other_error(
            "remote MCP terminal persistence requires a nonzero matching generation and epoch"
                .to_string(),
        ));
    }
    let mut tombstone = RemoteSessionTombstoneRecord {
        record,
        resume_generation,
        terminal_epoch,
        resume_integrity: keyring.empty_tag_for_current(),
    };
    tombstone.resume_integrity.tag = compute_terminal_tombstone_integrity_tag(
        &keyring.current,
        &tombstone,
    )?;
    let mut fence = RemoteSessionTerminalFence {
        session_id: tombstone.record.session_id.clone(),
        terminal_at: tombstone.record.terminal_at,
        terminal_state: tombstone.record.lifecycle.state,
        resume_generation,
        terminal_epoch,
        resume_integrity: keyring.empty_tag_for_current(),
    };
    fence.resume_integrity.tag =
        compute_terminal_fence_integrity_tag(&keyring.current, &fence)?;
    Ok((tombstone, fence))
}

fn compute_terminal_tombstone_integrity_tag(
    key: &RemoteSessionHmacKey,
    tombstone: &RemoteSessionTombstoneRecord,
) -> Result<String, CliError> {
    let envelope = RemoteSessionTombstoneIntegrityEnvelope {
        schema: "chio.remote-mcp.terminal-tombstone-integrity.v2",
        record: &tombstone.record,
        resume_generation: tombstone.resume_generation,
        terminal_epoch: tombstone.terminal_epoch,
        key_id: &tombstone.resume_integrity.key_id,
        key_version: tombstone.resume_integrity.key_version,
    };
    compute_remote_session_hmac(
        REMOTE_SESSION_TOMBSTONE_HMAC_LABEL,
        key.key.as_slice(),
        &envelope,
        "terminal MCP session tombstone",
    )
}

fn compute_terminal_fence_integrity_tag(
    key: &RemoteSessionHmacKey,
    fence: &RemoteSessionTerminalFence,
) -> Result<String, CliError> {
    let envelope = RemoteSessionTerminalFenceIntegrityEnvelope {
        schema: "chio.remote-mcp.terminal-fence-integrity.v2",
        session_id: &fence.session_id,
        terminal_at: fence.terminal_at,
        terminal_state: fence.terminal_state,
        resume_generation: fence.resume_generation,
        terminal_epoch: fence.terminal_epoch,
        key_id: &fence.resume_integrity.key_id,
        key_version: fence.resume_integrity.key_version,
    };
    compute_remote_session_hmac(
        REMOTE_SESSION_TERMINAL_FENCE_HMAC_LABEL,
        key.key.as_slice(),
        &envelope,
        "terminal MCP session generation fence",
    )
}

fn validate_terminal_tombstone_integrity(
    keyring: &RemoteSessionHmacKeyring,
    tombstone: &RemoteSessionTombstoneRecord,
    now: u64,
) -> Result<(), CliError> {
    if tombstone.resume_generation == 0
        || tombstone.terminal_epoch == 0
        || tombstone.resume_generation != tombstone.terminal_epoch
        || !matches!(
            tombstone.record.lifecycle.state,
            RemoteSessionState::Deleted | RemoteSessionState::Expired | RemoteSessionState::Closed
        )
    {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} has an invalid terminal generation or state",
            tombstone.record.session_id
        )));
    }
    let key = keyring
        .verification_key(&tombstone.resume_integrity, now)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "stored MCP session {} uses an unknown or expired tombstone HMAC key",
                tombstone.record.session_id
            ))
        })?;
    let expected = compute_terminal_tombstone_integrity_tag(key, tombstone)?;
    verify_remote_session_hmac(
        &expected,
        &tombstone.resume_integrity.tag,
        &tombstone.record.session_id,
        "terminal tombstone integrity",
    )
}

fn validate_terminal_fence_integrity(
    keyring: &RemoteSessionHmacKeyring,
    fence: &RemoteSessionTerminalFence,
    now: u64,
) -> Result<(), CliError> {
    if fence.resume_generation == 0
        || fence.terminal_epoch == 0
        || fence.resume_generation != fence.terminal_epoch
        || !matches!(
            fence.terminal_state,
            RemoteSessionState::Deleted | RemoteSessionState::Expired | RemoteSessionState::Closed
        )
    {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} has an invalid terminal fence generation",
            fence.session_id
        )));
    }
    let key = keyring
        .verification_key(&fence.resume_integrity, now)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "stored MCP session {} uses an unknown or expired terminal fence HMAC key",
                fence.session_id
            ))
        })?;
    let expected = compute_terminal_fence_integrity_tag(key, fence)?;
    verify_remote_session_hmac(
        &expected,
        &fence.resume_integrity.tag,
        &fence.session_id,
        "terminal fence integrity",
    )
}

fn validate_restored_peer_capabilities(
    record: &RemoteSessionResumeRecord,
) -> Result<PeerCapabilities, CliError> {
    let derived = parse_remote_session_peer_capabilities(&record.initialize_params);
    if derived != record.peer_capabilities {
        return Err(CliError::cli_other_error(format!(
            "stored MCP session {} failed peer capability re-validation against initialize params",
            record.session_id
        )));
    }
    Ok(derived)
}
