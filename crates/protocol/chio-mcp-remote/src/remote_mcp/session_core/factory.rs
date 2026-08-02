use super::*;

struct RemoteBoundCapabilityRecord {
    canonical_capability: Vec<u8>,
}

/// Session-local resolver for centrally issued capabilities when the optional
/// production broker is not installed. Every identity field comes from the
/// signed capability caveat, while the operation context supplies only the
/// actual kernel session that must match it.
pub(super) struct RemoteBoundSecurityInvocationContextAuthority {
    agent_id: String,
    agent_public_key: PublicKey,
    security_context: chio_kernel::SecurityInvocationContext,
    capabilities: BTreeMap<String, RemoteBoundCapabilityRecord>,
}

impl RemoteBoundSecurityInvocationContextAuthority {
    pub(super) fn new(
        agent_id: &str,
        kernel_session_id: &SessionId,
        issuance_binding: &RemoteCapabilityIssuanceBinding,
        server_id: &str,
        issued_capabilities: &[CapabilityToken],
    ) -> Result<Self, CliError> {
        if issued_capabilities.is_empty() {
            return Err(CliError::cli_other_error(
                "remote capability security context requires issued capabilities".to_string(),
            ));
        }
        if issuance_binding.security_session_id != kernel_session_id.as_str() {
            return Err(CliError::cli_other_error(
                "remote capability issuance binding does not match the kernel session"
                    .to_string(),
            ));
        }
        let agent_public_key = PublicKey::from_hex(agent_id).map_err(|error| {
            CliError::cli_other_error(format!(
                "remote capability agent identity is invalid: {error}"
            ))
        })?;
        let mut exact_binding = None::<CapabilitySecurityBinding>;
        let mut capabilities = BTreeMap::new();
        for capability in issued_capabilities {
            if capability.subject != agent_public_key {
                return Err(CliError::cli_other_error(
                    "remote capability subject does not match the session agent".to_string(),
                ));
            }
            let binding = capability
                .security_binding()
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "remote capability security binding is invalid: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    CliError::cli_other_error(
                        "remote capability has no signed security binding".to_string(),
                    )
                })?;
            if binding.tenant_id != issuance_binding.tenant_id
                || binding.lineage_id != issuance_binding.lineage_id
                || binding.session_id != issuance_binding.security_session_id
                || binding.principal_id != issuance_binding.principal_id
                || binding.isolation_epoch_id != issuance_binding.isolation_epoch_id
                || binding.context_generation != issuance_binding.context_generation
                || binding.server_id != server_id
            {
                return Err(CliError::cli_other_error(
                    "remote capability does not match the session issuance binding".to_string(),
                ));
            }
            match exact_binding.as_ref() {
                Some(expected) if expected != &binding => {
                    return Err(CliError::cli_other_error(
                        "remote capability set has inconsistent signed security bindings"
                            .to_string(),
                    ));
                }
                Some(_) => {}
                None => exact_binding = Some(binding),
            }
            let canonical_capability = canonical_json_bytes(capability).map_err(|error| {
                CliError::cli_other_error(format!(
                    "remote capability could not be canonicalized: {error}"
                ))
            })?;
            if capabilities
                .insert(
                    capability.id.clone(),
                    RemoteBoundCapabilityRecord {
                        canonical_capability,
                    },
                )
                .is_some()
            {
                return Err(CliError::cli_other_error(
                    "remote capability set contains duplicate capability ids".to_string(),
                ));
            }
        }
        Ok(Self {
            agent_id: agent_id.to_string(),
            agent_public_key,
            security_context: security_context_from_issuance_binding(issuance_binding)?,
            capabilities,
        })
    }
}

impl chio_kernel::SecurityInvocationContextAuthority
    for RemoteBoundSecurityInvocationContextAuthority
{
    fn resolve_security_invocation_context(
        &self,
        context: &chio_core::session::OperationContext,
        operation: &chio_core::session::ToolCallOperation,
    ) -> Result<chio_kernel::SecurityInvocationContext, KernelError> {
        let expected_context = self.security_context.as_v1();
        if context.agent_id != self.agent_id
            || context.session_id.as_str() != expected_context.session_id().as_str()
            || operation.capability.subject != self.agent_public_key
        {
            return Err(KernelError::GuardDenied(
                "remote capability crossed its signed agent or kernel session binding"
                    .to_string(),
            ));
        }
        let installed = self
            .capabilities
            .get(&operation.capability.id)
            .ok_or_else(|| {
                KernelError::GuardDenied(
                    "remote capability is not installed for this session incarnation".to_string(),
                )
            })?;
        let observed = canonical_json_bytes(&operation.capability).map_err(|error| {
            KernelError::GuardDenied(format!(
                "remote capability could not be canonicalized: {error}"
            ))
        })?;
        if observed != installed.canonical_capability {
            return Err(KernelError::GuardDenied(
                "remote capability does not match the installed signed token".to_string(),
            ));
        }
        Ok(self.security_context.clone())
    }
}

pub(super) fn derive_capability_issuance_binding(
    config: &RemoteServeHttpConfig,
    auth_context: &SessionAuthContext,
    kernel_session_id: &SessionId,
    agent_public_key: &PublicKey,
) -> Result<RemoteCapabilityIssuanceBinding, CliError> {
    let tenant_source = auth_context
        .authenticated_tenant_id()
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!(
                "mcp-host:{}",
                sha256_hex(config.server_id.as_bytes())
            )
        });
    let tenant_id = TenantId::new(tenant_source)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let principal_source = auth_context
        .principal()
        .map(str::to_string)
        .unwrap_or_else(|| agent_public_key.to_hex());
    let principal_id = PrincipalId::new(principal_source)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let binding_material = canonical_json_bytes(&json!({
        "tenantId": tenant_id.as_str(),
        "kernelSessionId": kernel_session_id.as_str(),
        "agentPublicKey": agent_public_key.to_hex(),
        "serverId": config.server_id,
    }))
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let digest = sha256_hex(&binding_material);
    let lineage_id = LineageId::new(format!("mcp-lineage:{digest}"))
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let security_session_id = SecuritySessionId::new(kernel_session_id.as_str().to_string())
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let isolation_epoch_id = IsolationEpochId::new(format!("mcp-isolation:{digest}"))
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(RemoteCapabilityIssuanceBinding {
        tenant_id: tenant_id.to_string(),
        lineage_id: lineage_id.to_string(),
        security_session_id: security_session_id.to_string(),
        principal_id: principal_id.to_string(),
        isolation_epoch_id: isolation_epoch_id.to_string(),
        context_generation: 1,
    })
}

pub(super) fn security_context_from_issuance_binding(
    binding: &RemoteCapabilityIssuanceBinding,
) -> Result<chio_kernel::SecurityInvocationContext, CliError> {
    let context = chio_kernel::SecurityInvocationContextV1::new(
        TenantId::new(binding.tenant_id.clone())
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        SecuritySessionId::new(binding.security_session_id.clone())
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        PrincipalId::new(binding.principal_id.clone())
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        IsolationEpochId::new(binding.isolation_epoch_id.clone())
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        LineageId::new(binding.lineage_id.clone())
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        binding.context_generation,
    );
    Ok(chio_kernel::SecurityInvocationContext::v1(
        context.with_flow_state_generation(binding.context_generation),
    ))
}

fn validate_stored_capability_issuance_binding(
    config: &RemoteServeHttpConfig,
    auth_context: &SessionAuthContext,
    kernel_session_id: &SessionId,
    agent_public_key: &PublicKey,
    binding: &RemoteCapabilityIssuanceBinding,
) -> Result<(), CliError> {
    let expected = derive_capability_issuance_binding(
        config,
        auth_context,
        kernel_session_id,
        agent_public_key,
    )?;
    let isolation_epoch_is_valid =
        IsolationEpochId::new(binding.isolation_epoch_id.clone()).is_ok();
    if binding.tenant_id != expected.tenant_id
        || binding.lineage_id != expected.lineage_id
        || binding.security_session_id != expected.security_session_id
        || binding.principal_id != expected.principal_id
        || binding.context_generation == 0
        || !isolation_epoch_is_valid
    {
        return Err(CliError::cli_other_error(
            "stored MCP session has a capability issuance context mismatch".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn persist_next_restore_incarnation(
    config: &RemoteServeHttpConfig,
    keyring: &RemoteSessionHmacKeyring,
    record: &RemoteSessionResumeRecord,
    agent_public_key: &PublicKey,
) -> Result<RemoteSessionResumeRecord, CliError> {
    validate_stored_capability_issuance_binding(
        config,
        &record.auth_context,
        &record.kernel_session_id,
        agent_public_key,
        &record.capability_issuance_binding,
    )?;
    let context_generation = record
        .capability_issuance_binding
        .context_generation
        .checked_add(1)
        .ok_or_else(|| {
            CliError::cli_other_error(format!(
                "stored MCP session {} exhausted its isolation context generation",
                record.session_id
            ))
        })?;
    let resume_generation = record.resume_generation.checked_add(1).ok_or_else(|| {
        CliError::cli_other_error(format!(
            "stored MCP session {} exhausted its resume generation",
            record.session_id
        ))
    })?;
    let incarnation_nonce = Keypair::generate().public_key().to_hex();
    let incarnation_material = canonical_json_bytes(&json!({
        "schema": "chio.remote-mcp.restore-incarnation.v1",
        "sessionId": record.session_id,
        "kernelSessionId": record.kernel_session_id.as_str(),
        "previousIsolationEpochId": record.capability_issuance_binding.isolation_epoch_id,
        "contextGeneration": context_generation,
        "resumeGeneration": resume_generation,
        "incarnationNonce": incarnation_nonce,
    }))
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "serialize MCP restore incarnation for {}: {error}",
            record.session_id
        ))
    })?;
    let isolation_epoch_id =
        IsolationEpochId::new(format!("mcp-isolation:{}", sha256_hex(&incarnation_material)))
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let mut next = record.clone();
    next.capability_issuance_binding.context_generation = context_generation;
    next.capability_issuance_binding.isolation_epoch_id = isolation_epoch_id.to_string();
    next.issued_capabilities.clear();
    next.resume_generation = resume_generation;
    next.resume_integrity = keyring.empty_tag_for_current();
    next.resume_integrity.tag =
        compute_resume_record_integrity_tag(&keyring.current, &next)?;
    let path = config.session_db_path.as_deref().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "stored MCP session {} cannot persist a pre-launch restore incarnation without a session database",
            record.session_id
        ))
    })?;
    persist_active_session_record(path, &next, keyring)?;
    Ok(next)
}

#[cfg(unix)]
fn production_broker_runtime_lock_error() -> CliError {
    CliError::cli_other_error("production broker runtime ownership lock is poisoned".to_string())
}

#[cfg(unix)]
fn governed_response_kernel_lock_error() -> CliError {
    CliError::cli_other_error("governed response kernel ownership lock is poisoned".to_string())
}

pub(super) fn merge_remote_active_defense_results(
    operation: Result<(), CliError>,
    shutdown: Result<(), CliError>,
) -> Result<(), CliError> {
    match (operation, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(operation_error), Err(shutdown_error)) => Err(CliError::cli_other_error(format!(
            "remote MCP operation failed: {operation_error}; explicit active-defense shutdown also failed: {shutdown_error}"
        ))),
    }
}

pub(super) async fn finish_remote_active_defense_with_shutdown<F, Fut>(
    operation: Result<(), CliError>,
    shutdown: F,
) -> Result<(), CliError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), CliError>>,
{
    merge_remote_active_defense_results(operation, shutdown().await)
}

impl PinnedRemotePolicyContract {
    fn capture(policy: &LoadedPolicy) -> Result<Self, CliError> {
        let active_defense_rule_canonical = policy
            .active_defense_rules
            .iter()
            .map(|rule| {
                rule.canonical_bytes().map_err(|error| {
                    CliError::cli_other_error(format!(
                        "failed to pin active-defense rule material: {error}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            identity: policy.identity.clone(),
            active_defense: policy.active_defense.clone(),
            active_defense_rule_canonical,
        })
    }

    fn require_exact(&self, policy: &LoadedPolicy) -> Result<(), CliError> {
        let observed = Self::capture(policy)?;
        if &observed != self {
            return Err(CliError::cli_other_error(
                "remote MCP policy or active-defense rule material changed after startup"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

impl RemoteSessionFactory {
    pub(super) fn uses_remote_authority(&self) -> bool {
        session_core_authority_mode::uses_remote_authority(&self.config)
    }

    fn issue_hosted_default_capabilities(
        &self,
        kernel: &ChioKernel,
        agent_public_key: &PublicKey,
        default_capabilities: &[chio_control_plane::policy::DefaultCapability],
        binding: &RemoteCapabilityIssuanceBinding,
    ) -> Result<Vec<CapabilityToken>, CliError> {
        if !self.uses_remote_authority() && self.broker_contract_digest.is_none() {
            return issue_default_capabilities(kernel, agent_public_key, default_capabilities);
        }
        let security_context = security_context_from_issuance_binding(binding)?;
        issue_default_capabilities_with_security_context(
            kernel,
            agent_public_key,
            default_capabilities,
            &security_context,
        )
    }

    fn remote_bound_security_context_authority(
        &self,
        agent_id: &str,
        kernel_session_id: &SessionId,
        binding: &RemoteCapabilityIssuanceBinding,
        capabilities: &[CapabilityToken],
    ) -> Result<Arc<dyn chio_kernel::SecurityInvocationContextAuthority>, CliError> {
        Ok(Arc::new(
            RemoteBoundSecurityInvocationContextAuthority::new(
                agent_id,
                kernel_session_id,
                binding,
                &self.config.server_id,
                capabilities,
            )?,
        ))
    }

    #[cfg(test)]
    pub(super) fn new(config: RemoteServeHttpConfig) -> Result<Self, CliError> {
        Self::new_with_topology(config, RuntimeToolTopology::local())
    }

    pub(super) async fn new_ready(config: RemoteServeHttpConfig) -> Result<Self, CliError> {
        // This topology describes the downstream tool execution boundary. The
        // HTTP listener is an agent ingress boundary, while the wrapped MCP
        // command remains a local native process admitted by the cage policy.
        let mut factory = Self::new_with_topology(config, RuntimeToolTopology::local())?;
        factory.pin_configured_policy()?;
        #[cfg(unix)]
        factory.start_production_active_defense().await?;
        Ok(factory)
    }

    #[cfg(test)]
    pub(super) async fn new_ready_for_local_manifest_test(
        config: RemoteServeHttpConfig,
    ) -> Result<Self, CliError> {
        let mut factory = Self::new_with_topology(config, RuntimeToolTopology::local())?;
        factory.pin_configured_policy()?;
        Ok(factory)
    }

    #[cfg(test)]
    pub(super) fn new_for_local_manifest_test(
        config: RemoteServeHttpConfig,
    ) -> Result<Self, CliError> {
        Self::new_with_topology(config, RuntimeToolTopology::local())
    }

    fn new_with_topology(
        mut config: RemoteServeHttpConfig,
        topology: RuntimeToolTopology,
    ) -> Result<Self, CliError> {
        session_core_authority_mode::validate_remote_authority_factory_config(&config)?;
        let uses_remote_authority =
            session_core_authority_mode::uses_remote_authority(&config);
        if let Some(path) = config.session_db_path.as_deref() {
            config.session_db_path = Some(canonical_session_database_path(path)?);
        }
        let session_store_lease = config
            .session_db_path
            .as_deref()
            .map(RemoteSessionStoreLifecycleLease::acquire)
            .transpose()?
            .map(Arc::new);
        let remote_control_authority_trust = match (uses_remote_authority, config.control_url.as_deref()) {
            (true, Some(control_url)) => {
                let pinned = trust_control::service_runtime::PinnedControlAuthority::with_successors(
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
                Some(
                    trust_control::service_runtime::remote_authority::RemoteControlAuthorityTrust::open(
                        control_url,
                        config.control_token.as_deref().ok_or_else(|| {
                            CliError::cli_other_error(
                                "remote authority service token is unavailable".to_string(),
                            )
                        })?,
                        pinned,
                        config
                            .control_authority_key_log_policy_path
                            .as_deref()
                            .ok_or_else(|| {
                                CliError::cli_other_error(
                                    "remote authority key-log policy path is unavailable"
                                        .to_string(),
                                )
                            })?,
                        config
                            .control_authority_key_log_verifier_db_path
                            .as_deref()
                            .ok_or_else(|| {
                                CliError::cli_other_error(
                                    "remote authority verifier database path is unavailable"
                                        .to_string(),
                                )
                            })?,
                    )?,
                )
            }
            _ => None,
        };
        let (
            remote_authority_workload_signer,
            remote_authority_session_admission_signer,
            remote_kernel_evidence_signer,
        ) = match uses_remote_authority {
            true => {
                let workload_signer = load_existing_authority_keypair(
                    config
                        .remote_authority_workload_seed_path
                        .as_deref()
                        .ok_or_else(|| {
                            CliError::cli_other_error(
                                "remote authority workload signer seed is unavailable".to_string(),
                            )
                        })?,
                )?;
                let session_admission_signer = load_existing_authority_keypair(
                    config
                        .remote_authority_session_admission_seed_path
                        .as_deref()
                        .ok_or_else(|| {
                            CliError::cli_other_error(
                                "remote authority session-admission signer seed is unavailable"
                                    .to_string(),
                            )
                        })?,
                )?;
                let kernel_evidence_signer = load_existing_authority_keypair(
                    config
                        .remote_kernel_evidence_seed_path
                        .as_deref()
                        .ok_or_else(|| {
                            CliError::cli_other_error(
                                "remote kernel evidence signer seed is unavailable".to_string(),
                            )
                        })?,
                )?;
                let workload_key = workload_signer.public_key();
                let session_admission_key = session_admission_signer.public_key();
                let kernel_evidence_key = kernel_evidence_signer.public_key();
                session_core_authority_mode::validate_remote_authority_role_keys(
                    &config,
                    &workload_key,
                    &session_admission_key,
                    &kernel_evidence_key,
                )?;
                (
                    Some(workload_signer),
                    Some(session_admission_signer),
                    Some(kernel_evidence_signer),
                )
            }
            false => (None, None, None),
        };
        let signed_manifest_path = config.signed_manifest_path.as_deref().ok_or_else(|| {
            CliError::cli_other_error(
                "remote MCP requires an existing publisher-signed manifest file".to_string(),
            )
        })?;
        let manifest_public_key = config.manifest_public_key.as_deref().ok_or_else(|| {
            CliError::cli_other_error(
                "remote MCP requires an independently registered manifest public key".to_string(),
            )
        })?;
        let manifest_registry = load_existing_verified_manifest_registry(
            signed_manifest_path,
            manifest_public_key,
            &config.server_id,
            topology,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("failed to load admitted MCP manifest: {error}"))
        })?;
        let (kernel_keypair, keyring_runtime) = match (
            config.keyring_config_path.as_deref(),
            config.authority_seed_path.as_deref(),
            remote_kernel_evidence_signer,
        ) {
            (None, None, Some(keypair)) => (keypair, None),
            (Some(config_path), Some(seed_path), None) => {
                let (keypair, runtime) =
                    load_keyring_runtime_from_authority_seed(config_path, seed_path)?;
                (keypair, Some(runtime))
            }
            (Some(_), None, None) => {
                return Err(CliError::cli_other_error(
                    "keyring configuration requires a persistent authority seed".to_string(),
                ));
            }
            (None, Some(seed_path), None) => {
                (load_existing_authority_keypair(seed_path)?, None)
            }
            (None, None, None) => match config.authority_db_path.as_deref() {
                Some(authority_db_path) => (
                    SqliteCapabilityAuthority::open_existing(authority_db_path)?.local_keypair()?,
                    None,
                ),
                None => (Keypair::generate(), None),
            },
            _ => {
                return Err(CliError::cli_other_error(
                    "remote kernel evidence custody cannot be combined with local authority custody"
                        .to_string(),
                ));
            }
        };
        #[cfg(unix)]
        let broker_runtime = match config.broker_config_path.as_deref() {
            Some(path) => Some(
                ProductionBrokerProductRuntime::open(
                    path,
                    keyring_runtime.as_ref().ok_or_else(|| {
                        CliError::cli_other_error(
                            "production broker composition requires enterprise keyring custody"
                                .to_string(),
                        )
                    })?,
                )
                .map_err(|error| {
                    CliError::cli_other_error(format!("production broker startup failed: {error}"))
                })?,
            ),
            None => None,
        };
        #[cfg(not(unix))]
        if config.broker_config_path.is_some() {
            return Err(CliError::cli_other_error(
                "production broker composition requires Unix process isolation".to_string(),
            ));
        }
        #[cfg(unix)]
        if let Some(runtime) = broker_runtime.as_ref() {
            let startup_policy = load_policy_for_runtime(
                &config.policy_path,
                config.approver_directory_path.as_deref(),
                config.threshold_proposal_authority_public_key.as_ref(),
            )?;
            runtime
                .require_default_route_capability(&startup_policy.default_capabilities)
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "production broker policy composition failed: {error}"
                    ))
                })?;
            let paths = runtime
                .resolve_host_database_paths(
                    config.receipt_db_path.as_deref(),
                    config.revocation_db_path.as_deref(),
                    config.budget_db_path.as_deref(),
                    config.admission_operation_db_path.as_deref(),
                    config.authority_db_path.as_deref(),
                    config.approval_db_path.as_deref(),
                    config.session_db_path.as_deref(),
                )
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "production broker database composition failed: {error}"
                    ))
                })?;
            config.receipt_db_path = Some(paths.receipt_database_path);
            config.revocation_db_path = Some(paths.revocation_database_path);
            config.budget_db_path = Some(paths.budget_database_path);
            config.admission_operation_db_path = Some(paths.admission_operation_database_path);
            config.approval_db_path = Some(paths.approval_database_path);
            config.aggregate_invocation_admission = true;
        }
        #[cfg(unix)]
        let broker_contract_digest = broker_runtime
            .as_ref()
            .map(|runtime| runtime.contract_digest().to_string());
        #[cfg(not(unix))]
        let broker_contract_digest = None;
        #[cfg(unix)]
        let (manifest_registry, broker_manifest_registry) =
            if let Some(runtime) = broker_runtime.as_ref() {
                let composed = runtime
                    .compose_manifest_registry(manifest_registry)
                    .map_err(|error| {
                        CliError::cli_other_error(format!(
                            "production broker manifest composition failed: {error}"
                        ))
                    })?;
                (Arc::clone(composed.registry()), Some(composed))
            } else {
                chio_control_plane::security::reject_unprotected_flow_manifest(&manifest_registry)
                    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
                (Arc::new(manifest_registry), None)
            };
        #[cfg(not(unix))]
        let manifest_registry = {
            chio_control_plane::security::reject_unprotected_flow_manifest(&manifest_registry)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?;
            Arc::new(manifest_registry)
        };
        canonicalize_remote_upstream_command(&mut config)?;
        let resume_runtime_contract_digest =
            fingerprint_remote_runtime_contract(&config, &manifest_registry)?;
        Ok(Self {
            config,
            manifest_registry,
            resume_runtime_contract_digest,
            pinned_policy_contract: None,
            #[cfg(unix)]
            broker_runtime: StdMutex::new(broker_runtime),
            #[cfg(unix)]
            broker_manifest_registry,
            #[cfg(unix)]
            governed_response_kernel: StdMutex::new(None),
            broker_contract_digest,
            keyring_runtime,
            kernel_keypair,
            remote_authority_workload_signer,
            remote_authority_session_admission_signer,
            remote_control_authority_trust,
            session_store_lease,
            shared_upstream_owner: Arc::new(StdMutex::new(None)),
            lifecycle_policy: read_session_lifecycle_policy(),
        })
    }

    pub(super) fn ensure_session_store_owned(&self) -> Result<(), CliError> {
        match self.session_store_lease.as_deref() {
            Some(lease) => lease.ensure_owned(),
            None if self.config.session_db_path.is_some() => Err(CliError::cli_other_error(
                "remote MCP session database has no retained lifecycle lease".to_string(),
            )),
            None => Ok(()),
        }
    }

    #[cfg(unix)]
    async fn start_production_active_defense(&mut self) -> Result<(), CliError> {
        let loaded_policy = self.load_configured_policy()?;
        let mut broker_runtime = self
            .broker_runtime
            .get_mut()
            .map_err(|_| production_broker_runtime_lock_error())?
            .take();
        let Some(runtime) = broker_runtime.as_mut() else {
            return Ok(());
        };
        let startup_result = runtime
            .start_configured_active_defense(&loaded_policy)
            .await
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "production active-defense startup failed: {error}"
                ))
            });
        *self
            .broker_runtime
            .get_mut()
            .map_err(|_| production_broker_runtime_lock_error())? = broker_runtime;
        if let Err(startup_error) = startup_result {
            return finish_remote_active_defense_with_shutdown(Err(startup_error), || {
                self.shutdown_production_active_defense()
            })
            .await;
        }

        let bind_result = (|| {
            let response_kernel = Arc::new(self.compose_product_kernel(loaded_policy)?);
            self.with_production_broker_runtime(|runtime| {
                runtime
                    .bind_active_response_kernel(Arc::clone(&response_kernel))
                    .map_err(|error| {
                        CliError::cli_other_error(format!(
                            "production active-response kernel binding failed: {error}"
                        ))
                    })
            })?;
            *self
                .governed_response_kernel
                .get_mut()
                .map_err(|_| governed_response_kernel_lock_error())? = Some(response_kernel);
            Ok(())
        })();
        if bind_result.is_ok() {
            return Ok(());
        }
        finish_remote_active_defense_with_shutdown(bind_result, || {
            self.shutdown_production_active_defense()
        })
        .await
    }

    #[cfg(unix)]
    fn with_production_broker_runtime<T>(
        &self,
        operation: impl FnOnce(&ProductionBrokerProductRuntime) -> Result<T, CliError>,
    ) -> Result<T, CliError> {
        let runtime = self
            .broker_runtime
            .lock()
            .map_err(|_| production_broker_runtime_lock_error())?;
        let runtime = runtime.as_ref().ok_or_else(|| {
            CliError::cli_other_error(
                "production broker runtime is unavailable during product operation".to_string(),
            )
        })?;
        operation(runtime)
    }

    #[cfg(unix)]
    pub(super) async fn shutdown_production_active_defense(&self) -> Result<(), CliError> {
        let governed_response_kernel = {
            let mut governed_response_kernel = self
                .governed_response_kernel
                .lock()
                .map_err(|_| governed_response_kernel_lock_error())?;
            governed_response_kernel.take()
        };
        drop(governed_response_kernel);
        let mut runtime = {
            let mut broker_runtime = self
                .broker_runtime
                .lock()
                .map_err(|_| production_broker_runtime_lock_error())?;
            broker_runtime.take()
        };
        let Some(runtime) = runtime.as_mut() else {
            return Ok(());
        };
        runtime.shutdown_active_defense().await.map_err(|error| {
            CliError::cli_other_error(format!(
                "production active-defense shutdown failed: {error}"
            ))
        })
    }

    pub(super) async fn shutdown_services(&self) -> Result<(), CliError> {
        let upstream_result = self.shutdown_shared_upstream_owner();
        #[cfg(unix)]
        let active_defense_result = self.shutdown_production_active_defense().await;
        #[cfg(not(unix))]
        let active_defense_result = Ok(());
        merge_remote_active_defense_results(upstream_result, active_defense_result)
    }

    #[cfg(test)]
    pub(super) fn authority_public_key(&self) -> PublicKey {
        if self.uses_remote_authority() {
            return match self.config.control_authority_public_key.clone() {
                Some(public_key) => public_key,
                None => panic!("seedless remote factory lost its current authority pin"),
            };
        }
        self.keyring_runtime
            .as_ref()
            .and_then(|runtime| runtime.authority_status().ok())
            .map(|status| status.public_key)
            .unwrap_or_else(|| self.kernel_keypair.public_key())
    }

    pub(super) fn load_configured_policy(&self) -> Result<LoadedPolicy, CliError> {
        let loaded = load_policy_for_runtime(
            &self.config.policy_path,
            self.config.approver_directory_path.as_deref(),
            self.config.threshold_proposal_authority_public_key.as_ref(),
        )
        .map_err(CliError::from)?;
        if let Some(contract) = self.pinned_policy_contract.as_ref() {
            contract.require_exact(&loaded)?;
        }
        Ok(loaded)
    }

    fn keypair_for_new_kernel(&self) -> Result<Keypair, CliError> {
        let keypair = match (
            self.keyring_runtime.as_ref(),
            self.config.authority_seed_path.as_deref(),
            self.config.authority_db_path.as_deref(),
        ) {
            (None, Some(seed_path), _) => load_existing_authority_keypair(seed_path),
            (None, None, Some(authority_db_path)) => {
                Ok(SqliteCapabilityAuthority::open_existing(authority_db_path)?.local_keypair()?)
            }
            _ => Ok(self.kernel_keypair.clone()),
        }?;
        if !self.uses_remote_authority()
            && self.config.control_url.is_some()
            && self
                .config
                .control_authority_public_key
                .as_ref()
                .is_some_and(|pinned| pinned != &keypair.public_key())
        {
            return Err(CliError::cli_other_error(
                "local authority/control-pin epoch mismatch during future kernel selection"
                    .to_string(),
            ));
        }
        Ok(keypair)
    }

    fn pin_configured_policy(&mut self) -> Result<(), CliError> {
        if self.pinned_policy_contract.is_some() {
            return Err(CliError::cli_other_error(
                "remote MCP policy contract is already pinned".to_string(),
            ));
        }
        let loaded = load_policy_for_runtime(
            &self.config.policy_path,
            self.config.approver_directory_path.as_deref(),
            self.config.threshold_proposal_authority_public_key.as_ref(),
        )?;
        #[cfg(unix)]
        {
            let broker_runtime = self
                .broker_runtime
                .lock()
                .map_err(|_| production_broker_runtime_lock_error())?;
            if let Some(runtime) = broker_runtime.as_ref() {
                runtime
                    .require_default_route_capability(&loaded.default_capabilities)
                    .map_err(|error| {
                        CliError::cli_other_error(format!(
                            "production broker pinned policy composition failed: {error}"
                        ))
                    })?;
            }
        }
        self.pinned_policy_contract = Some(PinnedRemotePolicyContract::capture(&loaded)?);
        Ok(())
    }

    /// Build the kernel used by both new and restored product sessions.
    ///
    /// Broker authorities are installed atomically before Enforce publication.
    /// The ordinary path consumes the partially built kernel during final
    /// admission composition, so partial durable state cannot escape.
    pub(super) fn compose_product_kernel(
        &self,
        loaded_policy: LoadedPolicy,
    ) -> Result<ChioKernel, CliError> {
        if let Some(contract) = self.pinned_policy_contract.as_ref() {
            contract.require_exact(&loaded_policy)?;
        }
        let kernel_kp = self.keypair_for_new_kernel()?;
        #[cfg(unix)]
        let broker_runtime = self
            .broker_runtime
            .lock()
            .map_err(|_| production_broker_runtime_lock_error())?;
        #[cfg(unix)]
        match (
            broker_runtime.as_ref(),
            self.broker_manifest_registry.as_ref(),
        ) {
            (Some(runtime), Some(manifests)) => {
                if !matches!(
                    loaded_policy.active_defense.mode,
                    ActiveDefenseMode::Enforce
                ) {
                    return Err(CliError::cli_other_error(
                        "production broker composition requires active_defense.mode=enforce"
                            .to_string(),
                    ));
                }
                let keyring = self.keyring_runtime.as_ref().ok_or_else(|| {
                    CliError::cli_other_error(
                        "production broker composition requires enterprise keyring custody"
                            .to_string(),
                    )
                })?;
                let security_runtime = runtime
                    .build_security_runtime(manifests, &loaded_policy.identity.runtime_hash)
                    .map_err(|error| {
                        CliError::cli_other_error(format!(
                            "production broker security runtime composition failed: {error}"
                        ))
                    })?;
                let host = ProductionBrokerKernelHostConfig {
                    receipt_database_path: self.config.receipt_db_path.as_deref().ok_or_else(
                        || {
                            CliError::cli_other_error(
                                "production broker composition has no receipt database".to_string(),
                            )
                        },
                    )?,
                    revocation_database_path: self
                        .config
                        .revocation_db_path
                        .as_deref()
                        .ok_or_else(|| {
                            CliError::cli_other_error(
                                "production broker composition has no revocation database"
                                    .to_string(),
                            )
                        })?,
                    budget_database_path: self.config.budget_db_path.as_deref().ok_or_else(
                        || {
                            CliError::cli_other_error(
                                "production broker composition has no budget database".to_string(),
                            )
                        },
                    )?,
                    authority_seed_path: self.config.authority_seed_path.as_deref(),
                    authority_database_path: self.config.authority_db_path.as_deref(),
                };
                return
                    build_kernel_with_keyring_composition_and_production_broker_security_runtime(
                        loaded_policy,
                        &kernel_kp,
                        keyring,
                        runtime,
                        security_runtime,
                        host,
                    );
            }
            (None, None) => {}
            _ => {
                return Err(CliError::cli_other_error(
                    "production broker runtime and manifest registry are inconsistent".to_string(),
                ));
            }
        }
        let issuance_policy = loaded_policy.issuance_policy.clone();
        let runtime_assurance_policy = loaded_policy.runtime_assurance_policy.clone();
        let mut kernel = match self.keyring_runtime.as_ref() {
            Some(runtime) => build_kernel_with_keyring_composition_and_security_runtime(
                loaded_policy,
                &kernel_kp,
                runtime,
                None,
            )?,
            None => build_kernel_with_security_runtime(loaded_policy, &kernel_kp, None)?,
        };
        if self.uses_remote_authority() {
            configure_capability_authority(
                &mut kernel,
                None,
                None,
                None,
                None,
                self.config.control_url.as_deref(),
                self.config.remote_authority_workload_token.as_deref(),
                self.config.control_authority_public_key.as_ref(),
                &self.config.control_authority_trusted_public_keys,
                Some(RemoteCapabilityAuthorityWorkloadConfig {
                    tenant_id: self
                        .config
                        .remote_authority_tenant_id
                        .clone()
                        .ok_or_else(|| {
                            CliError::cli_other_error(
                                "remote authority workload tenant id is unavailable".to_string(),
                            )
                        })?,
                    workload_id: self
                        .config
                        .remote_authority_workload_id
                        .clone()
                        .ok_or_else(|| {
                            CliError::cli_other_error(
                                "remote authority workload id is unavailable".to_string(),
                            )
                        })?,
                    server_id: self.config.server_id.clone(),
                    authority_successors: self.config.control_authority_successors.clone(),
                    authority_trust: Arc::clone(
                        self.remote_control_authority_trust.as_ref().ok_or_else(|| {
                            CliError::cli_other_error(
                                "remote authority verified trust state is unavailable".to_string(),
                            )
                        })?,
                    ),
                    workload_signer: self
                        .remote_authority_workload_signer
                        .clone()
                        .ok_or_else(|| {
                            CliError::cli_other_error(
                                "remote authority workload signer is unavailable".to_string(),
                            )
                        })?,
                    session_admission_signer: self
                        .remote_authority_session_admission_signer
                        .clone()
                        .ok_or_else(|| {
                            CliError::cli_other_error(
                                "remote authority session-admission signer is unavailable"
                                    .to_string(),
                            )
                        })?,
                }),
                issuance_policy.clone(),
                runtime_assurance_policy.clone(),
            )?;
        }
        let receipt_store = match self.remote_control_authority_trust.as_ref() {
            Some(authority_trust) => configure_receipt_store_with_remote_authority_trust(
                &mut kernel,
                self.config.receipt_db_path.as_deref(),
                self.config.control_url.as_deref(),
                self.config.control_token.as_deref(),
                self.config.control_authority_public_key.as_ref(),
                &self.config.control_authority_trusted_public_keys,
                Arc::clone(authority_trust),
            )?,
            None => configure_receipt_store(
                &mut kernel,
                self.config.receipt_db_path.as_deref(),
                self.config.control_url.as_deref(),
                self.config.control_token.as_deref(),
                self.config.control_authority_public_key.as_ref(),
                &self.config.control_authority_trusted_public_keys,
            )?,
        };
        if let Some(runtime) = self.keyring_runtime.as_ref() {
            let receipt_store = receipt_store.ok_or_else(|| {
                CliError::cli_other_error(
                    "keyring runtime requires a durable normal receipt store".to_string(),
                )
            })?;
            runtime.attach_receipt_store(receipt_store)?;
        }
        configure_revocation_store(
            &mut kernel,
            self.config.revocation_db_path.as_deref(),
            self.config.control_url.as_deref(),
            self.config.control_token.as_deref(),
        )?;
        if !self.uses_remote_authority() {
            configure_capability_authority(
                &mut kernel,
                self.config.authority_seed_path.as_deref(),
                self.config.authority_db_path.as_deref(),
                self.config.receipt_db_path.as_deref(),
                self.config.budget_db_path.as_deref(),
                None,
                None,
                None,
                &[],
                None,
                issuance_policy,
                runtime_assurance_policy,
            )?;
        }
        let kernel = compose_ordinary_admission_runtime(
            kernel,
            OrdinaryAdmissionRuntimeConfig {
                enable_aggregate_invocation_admission: self.config.aggregate_invocation_admission,
                admission_operation_db_path: self.config.admission_operation_db_path.as_deref(),
                approval_db_path: self.config.approval_db_path.as_deref(),
                budget_db_path: self.config.budget_db_path.as_deref(),
                control_url: self.config.control_url.as_deref(),
                control_token: self.config.control_token.as_deref(),
            },
        )?;
        Ok(kernel)
    }

    pub(super) fn build_session_upstream_server(&self) -> Result<Arc<AdaptedMcpServer>, CliError> {
        let wrapped_arg_refs = self
            .config
            .wrapped_args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let admitted_manifest = self.admitted_manifest()?;
        let native_launch = self.config.native_launch_factory.prepare_launch(
            &self.config.wrapped_command,
            &wrapped_arg_refs,
            &self.config.server_id,
            Arc::clone(&self.manifest_registry),
        )?;
        let adapted_server = AdaptedMcpServer::from_command(
            &self.config.wrapped_command,
            &wrapped_arg_refs,
            McpAdapterConfig {
                server_id: self.config.server_id.clone(),
                server_name: self.config.server_name.clone(),
                server_version: self.config.server_version.clone(),
                public_key: admitted_manifest.public_key.clone(),
            },
            native_launch,
        )?;
        if let Err(error) = chio_mcp_adapter::verify_discovered_manifest_surface(
            adapted_server.manifest(),
            admitted_manifest,
        ) {
            return Err(upstream_admission_failure(&adapted_server, error));
        }

        Ok(Arc::new(adapted_server))
    }

    fn admitted_manifest(&self) -> Result<&ToolManifest, CliError> {
        self.manifest_registry
            .verified_manifest(&self.config.server_id)
            .map(|signed| &signed.manifest)
            .ok_or_else(|| {
                CliError::cli_other_error("admitted MCP manifest is unavailable".to_string())
            })
    }

    pub(crate) fn require_current_resume_runtime_contract(&self) -> Result<(), CliError> {
        let observed =
            fingerprint_remote_runtime_contract(&self.config, self.manifest_registry.as_ref())?;
        if observed != self.resume_runtime_contract_digest {
            return Err(CliError::cli_other_error(
                "remote MCP admitted registry or upstream service identity changed after startup"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn shared_upstream_owner(&self) -> Result<Arc<SharedUpstreamOwner>, CliError> {
        let mut guard = self.shared_upstream_owner.lock().map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to lock shared remote MCP upstream owner cache: {error}"
            ))
        })?;
        if let Some(owner) = guard.as_ref() {
            return Ok(owner.clone());
        }

        let owner = Arc::new(SharedUpstreamOwner::new(
            &self.config,
            self.admitted_manifest()?,
            Arc::clone(&self.manifest_registry),
        )?);
        info!(
            server_id = %self.config.server_id,
            "created shared remote MCP hosted owner"
        );
        *guard = Some(owner.clone());
        Ok(owner)
    }

    fn shutdown_shared_upstream_owner(&self) -> Result<(), CliError> {
        let owner = self
            .shared_upstream_owner
            .lock()
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "failed to lock shared remote MCP upstream owner cache: {error}"
                ))
            })?
            .take();
        owner.map_or(Ok(()), |owner| owner.shutdown())
    }

    pub(super) fn configured_hosted_isolation(&self) -> RemoteHostedIsolationMode {
        if self.config.shared_hosted_owner {
            RemoteHostedIsolationMode::SharedHostedOwnerCompatibility
        } else {
            RemoteHostedIsolationMode::DedicatedPerSession
        }
    }

    pub(super) fn spawn_session(
        &self,
        auth_context: SessionAuthContext,
    ) -> Result<Arc<RemoteSession>, CliError> {
        self.ensure_session_store_owned()?;
        self.require_current_resume_runtime_contract()?;
        let loaded_policy = self.load_configured_policy()?;
        let auth_mode_fingerprint = fingerprint_remote_auth_contract(
            &self.config,
            self.broker_contract_digest.as_deref(),
            &self.resume_runtime_contract_digest,
        )?;
        let policy_fingerprint = fingerprint_remote_policy_contract(
            &loaded_policy,
            &self.config,
            self.broker_contract_digest.as_deref(),
            &self.resume_runtime_contract_digest,
        )?;
        let default_capabilities = loaded_policy.default_capabilities.clone();
        #[cfg(unix)]
        {
            let broker_runtime = self
                .broker_runtime
                .lock()
                .map_err(|_| production_broker_runtime_lock_error())?;
            if let Some(runtime) = broker_runtime.as_ref() {
                runtime
                    .require_default_route_capability(&default_capabilities)
                    .map_err(|error| {
                        CliError::cli_other_error(format!(
                            "production broker policy composition failed: {error}"
                        ))
                    })?;
            }
        }
        let resume_hmac_keyring = load_resume_hmac_keyring(&self.config)?;
        let owns_upstream = !self.config.shared_hosted_owner;
        let (upstream_server, upstream_notification_source) = if self.config.shared_hosted_owner {
            let owner = self.shared_upstream_owner()?;
            (owner.upstream_server(), owner.notification_tap())
        } else {
            let upstream_server = self.build_session_upstream_server()?;
            let notification_source = upstream_server.notification_source();
            (upstream_server, notification_source)
        };
        let session_result = (|| -> Result<Arc<RemoteSession>, CliError> {
            let upstream_capabilities = upstream_server.upstream_capabilities();

            let mut kernel = self.compose_product_kernel(loaded_policy)?;
            if let Some(resource_provider) = upstream_server.resource_provider() {
                kernel.register_resource_provider(Box::new(resource_provider));
            }
            if let Some(prompt_provider) = upstream_server.prompt_provider() {
                kernel.register_prompt_provider(Box::new(prompt_provider));
            }
            kernel.register_tool_server(Box::new(SharedUpstreamToolServer::new(
                upstream_server.clone(),
            )));

            let hosted_isolation = self.configured_hosted_isolation();
            let session_auth_context = hosted_isolation.snapshot_auth_context(auth_context);

            let agent_kp = derive_session_agent_keypair(&self.config, &session_auth_context)?;
            let agent_pk = agent_kp.public_key();
            let agent_id = agent_pk.to_hex();
            let kernel_session_id = SessionId::new(format!(
                "sess-{}",
                Keypair::generate().public_key().to_hex()
            ));
            let capability_issuance_binding = derive_capability_issuance_binding(
                &self.config,
                &session_auth_context,
                &kernel_session_id,
                &agent_pk,
            )?;
            let capabilities: Vec<CapabilityToken> = self.issue_hosted_default_capabilities(
                &kernel,
                &agent_pk,
                &default_capabilities,
                &capability_issuance_binding,
            )?;
            let session_capabilities = capabilities
                .iter()
                .map(|capability| RemoteSessionCapability {
                    id: capability.id.clone(),
                    issuer_public_key: capability.issuer.to_hex(),
                    subject_public_key: capability.subject.to_hex(),
                })
                .collect();

            let edge_config = McpEdgeConfig {
                server_name: "Chio MCP Edge".to_string(),
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                page_size: self.config.page_size,
                tools_list_changed: self.config.tools_list_changed
                    || upstream_capabilities.tools_list_changed,
                completion_enabled: Some(upstream_capabilities.completions_supported),
                resources_subscribe: upstream_capabilities.resources_subscribe,
                resources_list_changed: upstream_capabilities.resources_list_changed,
                prompts_list_changed: upstream_capabilities.prompts_list_changed,
                logging_enabled: true,
            };
            #[cfg(unix)]
            let broker_security_context_authority = {
                let broker_runtime = self
                    .broker_runtime
                    .lock()
                    .map_err(|_| production_broker_runtime_lock_error())?;
                broker_runtime
                    .as_ref()
                    .map(|runtime| {
                        runtime.security_invocation_context_authority(
                            session_auth_context.authenticated_tenant_id(),
                            &agent_id,
                            &capabilities,
                        )
                    })
                    .transpose()
                    .map_err(|error| {
                        CliError::cli_other_error(format!(
                            "production security invocation authority composition failed: {error}"
                        ))
                    })?
            };
            #[cfg(unix)]
            let security_context_authority = match broker_security_context_authority {
                Some(authority) => Some(authority),
                None if self.uses_remote_authority() => Some(
                    self.remote_bound_security_context_authority(
                        &agent_id,
                        &kernel_session_id,
                        &capability_issuance_binding,
                        &capabilities,
                    )?,
                ),
                None => None,
            };
            #[cfg(not(unix))]
            let security_context_authority = if self.uses_remote_authority() {
                Some(self.remote_bound_security_context_authority(
                    &agent_id,
                    &kernel_session_id,
                    &capability_issuance_binding,
                    &capabilities,
                )?)
            } else {
                None
            };
            let kernel = Arc::new(kernel);
            let mut edge = match security_context_authority {
            Some(authority) => {
                ChioMcpEdge::new_with_shared_kernel_manifest_registry_arc_and_security_context_authority(
                    edge_config,
                    Arc::clone(&kernel),
                    agent_id.clone(),
                    capabilities.clone(),
                    Arc::clone(&self.manifest_registry),
                    authority,
                )
            }
            None => ChioMcpEdge::new_with_shared_kernel_and_manifest_registry_arc(
                edge_config,
                kernel,
                agent_id.clone(),
                capabilities.clone(),
                Arc::clone(&self.manifest_registry),
            ),
        }?;
            edge.set_initial_session_id(kernel_session_id.clone())?;
            edge.set_session_auth_context(session_auth_context.clone());
            edge.attach_upstream_transport(Arc::clone(&upstream_notification_source));

            let (input_tx, input_rx) = mpsc::channel::<Value>();
            let (event_tx, _) = broadcast::channel::<RemoteSessionEvent>(256);
            let session_id = Keypair::generate().public_key().to_hex();
            let retained_notification_events =
                Arc::new(StdMutex::new(VecDeque::<RetainedRemoteSessionEvent>::new()));
            let next_event_id = Arc::new(AtomicU64::new(0));
            let writer = BroadcastJsonRpcWriter::new(
                event_tx.clone(),
                retained_notification_events.clone(),
                next_event_id.clone(),
                session_id.clone(),
            );

            std::thread::spawn(move || {
                if let Err(error) = edge.serve_message_channels(input_rx, writer) {
                    error!(error = %error, "remote MCP edge session worker exited with error");
                }
            });

            Ok(Arc::new(RemoteSession::new(RemoteSessionInit {
                session_id,
                kernel_session_id,
                agent_id,
                capabilities: session_capabilities,
                issued_capabilities: capabilities,
                auth_context: session_auth_context,
                auth_mode_fingerprint,
                policy_fingerprint,
                hosted_isolation,
                capability_issuance_binding,
                lifecycle_policy: self.lifecycle_policy.clone(),
                protocol_version: None,
                peer_capabilities: None,
                initialize_params: None,
                lifecycle_snapshot: None,
                input_tx,
                event_tx,
                retained_notification_events,
                next_event_id,
                session_db_path: self.config.session_db_path.clone(),
                session_store_lease: self.session_store_lease.clone(),
                resume_hmac_keyring,
                resume_generation: 0,
                upstream_transport: Arc::clone(&upstream_notification_source),
            })))
        })();
        finish_with_owned_upstream_shutdown(session_result, &upstream_server, owns_upstream)
    }

    pub(super) fn restore_session(
        &self,
        record: &RemoteSessionResumeRecord,
    ) -> Result<Arc<RemoteSession>, CliError> {
        self.ensure_session_store_owned()?;
        self.require_current_resume_runtime_contract()?;
        let resume_hmac_keyring = load_resume_hmac_keyring(&self.config)?.ok_or_else(|| {
            CliError::cli_other_error(format!(
                "stored MCP session {} cannot be restored without a dedicated resume HMAC keyring",
                record.session_id
            ))
        })?;
        validate_resume_record_integrity_with_keyring(
            &resume_hmac_keyring,
            record,
            session_now_millis(),
        )?;
        let configured_hosted_isolation = self.configured_hosted_isolation();
        if configured_hosted_isolation != record.hosted_isolation {
            return Err(CliError::cli_other_error(format!(
                "stored MCP session {} expects hosted isolation {:?} but the server is configured for {:?}",
                record.session_id, record.hosted_isolation, configured_hosted_isolation
            )));
        }
        if let Some(expected_agent_id) =
            expected_resume_agent_id(&self.config, &record.auth_context)?
        {
            if expected_agent_id != record.agent_id {
                return Err(CliError::cli_other_error(format!(
                    "stored MCP session {} failed authenticated principal re-validation during restore",
                    record.session_id
                )));
            }
        }

        let loaded_policy = self.load_configured_policy()?;
        let auth_mode_fingerprint = fingerprint_remote_auth_contract(
            &self.config,
            self.broker_contract_digest.as_deref(),
            &self.resume_runtime_contract_digest,
        )?;
        let policy_fingerprint = fingerprint_remote_policy_contract(
            &loaded_policy,
            &self.config,
            self.broker_contract_digest.as_deref(),
            &self.resume_runtime_contract_digest,
        )?;
        let default_capabilities = loaded_policy.default_capabilities.clone();
        #[cfg(unix)]
        {
            let broker_runtime = self
                .broker_runtime
                .lock()
                .map_err(|_| production_broker_runtime_lock_error())?;
            if let Some(runtime) = broker_runtime.as_ref() {
                runtime
                    .require_default_route_capability(&default_capabilities)
                    .map_err(|error| {
                        CliError::cli_other_error(format!(
                            "production broker policy composition failed: {error}"
                        ))
                    })?;
            }
        }
        match record.auth_mode_fingerprint.as_deref() {
            Some(stored) if stored == auth_mode_fingerprint => {}
            Some(_) => {
                return Err(CliError::cli_other_error(format!(
                    "stored MCP session {} was created under different serve-http auth or broker product settings",
                    record.session_id
                )));
            }
            None => {
                return Err(CliError::cli_other_error(format!(
                    "stored MCP session {} predates auth contract fingerprinting and must be re-initialized",
                    record.session_id
                )));
            }
        }
        let agent_public_key = PublicKey::from_hex(&record.agent_id)?;
        let incarnation_record = persist_next_restore_incarnation(
            &self.config,
            &resume_hmac_keyring,
            record,
            &agent_public_key,
        )?;
        let owns_upstream = !self.config.shared_hosted_owner;
        let (upstream_server, upstream_notification_source) = if self.config.shared_hosted_owner {
            let owner = self.shared_upstream_owner()?;
            (owner.upstream_server(), owner.notification_tap())
        } else {
            let upstream_server = self.build_session_upstream_server()?;
            let notification_source = upstream_server.notification_source();
            (upstream_server, notification_source)
        };
        let session_result = (|| -> Result<Arc<RemoteSession>, CliError> {
            let upstream_capabilities = upstream_server.upstream_capabilities();

            let mut kernel = self.compose_product_kernel(loaded_policy)?;
            if let Some(resource_provider) = upstream_server.resource_provider() {
                kernel.register_resource_provider(Box::new(resource_provider));
            }
            if let Some(prompt_provider) = upstream_server.prompt_provider() {
                kernel.register_prompt_provider(Box::new(prompt_provider));
            }
            kernel.register_tool_server(Box::new(SharedUpstreamToolServer::new(
                upstream_server.clone(),
            )));

            let restored_peer_capabilities =
                validate_restored_peer_capabilities(&incarnation_record)?;
            let issued_capabilities = self.issue_hosted_default_capabilities(
                &kernel,
                &agent_public_key,
                &default_capabilities,
                &incarnation_record.capability_issuance_binding,
            )?;
            let session_capabilities = issued_capabilities
                .iter()
                .map(|capability| RemoteSessionCapability {
                    id: capability.id.clone(),
                    issuer_public_key: capability.issuer.to_hex(),
                    subject_public_key: capability.subject.to_hex(),
                })
                .collect::<Vec<_>>();

            let edge_config = McpEdgeConfig {
                server_name: "Chio MCP Edge".to_string(),
                server_version: env!("CARGO_PKG_VERSION").to_string(),
                page_size: self.config.page_size,
                tools_list_changed: self.config.tools_list_changed
                    || upstream_capabilities.tools_list_changed,
                completion_enabled: Some(upstream_capabilities.completions_supported),
                resources_subscribe: upstream_capabilities.resources_subscribe,
                resources_list_changed: upstream_capabilities.resources_list_changed,
                prompts_list_changed: upstream_capabilities.prompts_list_changed,
                logging_enabled: true,
            };
            #[cfg(unix)]
            let broker_security_context_authority = {
                let broker_runtime = self
                    .broker_runtime
                    .lock()
                    .map_err(|_| production_broker_runtime_lock_error())?;
                broker_runtime
                .as_ref()
                .map(|runtime| {
                    runtime.security_invocation_context_authority(
                        incarnation_record.auth_context.authenticated_tenant_id(),
                        &incarnation_record.agent_id,
                        &issued_capabilities,
                    )
                })
                .transpose()
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "restored production security invocation authority composition failed: {error}"
                    ))
                })?
            };
            #[cfg(unix)]
            let security_context_authority = match broker_security_context_authority {
                Some(authority) => Some(authority),
                None if self.uses_remote_authority() => Some(
                    self.remote_bound_security_context_authority(
                        &incarnation_record.agent_id,
                        &incarnation_record.kernel_session_id,
                        &incarnation_record.capability_issuance_binding,
                        &issued_capabilities,
                    )?,
                ),
                None => None,
            };
            #[cfg(not(unix))]
            let security_context_authority = if self.uses_remote_authority() {
                Some(self.remote_bound_security_context_authority(
                    &incarnation_record.agent_id,
                    &incarnation_record.kernel_session_id,
                    &incarnation_record.capability_issuance_binding,
                    &issued_capabilities,
                )?)
            } else {
                None
            };
            let kernel = Arc::new(kernel);
            let mut edge = match security_context_authority {
            Some(authority) => {
                ChioMcpEdge::new_with_shared_kernel_manifest_registry_arc_and_security_context_authority(
                    edge_config,
                    Arc::clone(&kernel),
                    incarnation_record.agent_id.clone(),
                    issued_capabilities.clone(),
                    Arc::clone(&self.manifest_registry),
                    authority,
                )
            }
            None => ChioMcpEdge::new_with_shared_kernel_and_manifest_registry_arc(
                edge_config,
                kernel,
                incarnation_record.agent_id.clone(),
                issued_capabilities.clone(),
                Arc::clone(&self.manifest_registry),
            ),
        }?;
            edge.set_session_auth_context(incarnation_record.auth_context.clone());
            edge.attach_upstream_transport(Arc::clone(&upstream_notification_source));
            edge.restore_ready_session(
                incarnation_record.kernel_session_id.clone(),
                restored_peer_capabilities.clone(),
            )?;

            let (input_tx, input_rx) = mpsc::channel::<Value>();
            let (event_tx, _) = broadcast::channel::<RemoteSessionEvent>(256);
            let retained_notification_events =
                Arc::new(StdMutex::new(VecDeque::<RetainedRemoteSessionEvent>::new()));
            let next_event_id = Arc::new(AtomicU64::new(0));
            let writer = BroadcastJsonRpcWriter::new(
                event_tx.clone(),
                retained_notification_events.clone(),
                next_event_id.clone(),
                incarnation_record.session_id.clone(),
            );

            std::thread::spawn(move || {
                if let Err(error) = edge.serve_message_channels(input_rx, writer) {
                    error!(error = %error, "remote MCP edge session worker exited with error");
                }
            });

            Ok(Arc::new(RemoteSession::new(RemoteSessionInit {
                session_id: incarnation_record.session_id.clone(),
                kernel_session_id: incarnation_record.kernel_session_id.clone(),
                agent_id: incarnation_record.agent_id.clone(),
                capabilities: session_capabilities,
                issued_capabilities,
                auth_context: incarnation_record.auth_context.clone(),
                auth_mode_fingerprint,
                policy_fingerprint,
                hosted_isolation: incarnation_record.hosted_isolation,
                capability_issuance_binding: incarnation_record
                    .capability_issuance_binding
                    .clone(),
                lifecycle_policy: self.lifecycle_policy.clone(),
                protocol_version: incarnation_record.protocol_version.clone(),
                peer_capabilities: Some(restored_peer_capabilities),
                initialize_params: Some(incarnation_record.initialize_params.clone()),
                lifecycle_snapshot: Some(incarnation_record.lifecycle.clone()),
                input_tx,
                event_tx,
                retained_notification_events,
                next_event_id,
                session_db_path: self.config.session_db_path.clone(),
                session_store_lease: self.session_store_lease.clone(),
                resume_hmac_keyring: Some(resume_hmac_keyring),
                resume_generation: incarnation_record.resume_generation,
                upstream_transport: Arc::clone(&upstream_notification_source),
            })))
        })();
        finish_with_owned_upstream_shutdown(session_result, &upstream_server, owns_upstream)
    }
}
