impl ProductionBrokerProductRuntime {
    pub fn open(
        path: impl AsRef<Path>,
        keyring: &crate::KeyringRuntimeComposition,
    ) -> Result<Self, BrokerIntegrationError> {
        keyring.ensure_bound_signing_topology().map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "production broker keyring enforcement failed: {error}"
            ))
        })?;
        let file_config = ProductionBrokerProductConfig::load(path)?;
        let authority_signer = keyring.authority_signing_backend();
        if authority_signer.public_key() != file_config.authority_public_key {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "production broker authority trust root does not match the active keyring signer"
                    .to_string(),
            ));
        }
        let canonical_contract = canonical_json_bytes(&file_config).map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "broker product contract encoding failed: {error}"
            ))
        })?;
        let contract_digest = sha256_hex(&canonical_contract);
        let composition_config = file_config.composition_config();

        let broker_registry = load_existing_verified_manifest_registry(
            &file_config.broker_manifest_path,
            &file_config.broker_manifest_public_key.to_hex(),
            &file_config.broker_server_id,
            RuntimeToolTopology::remote(),
        )
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "broker manifest admission failed: {error}"
            ))
        })?;
        let broker_manifest = broker_registry
            .verified_manifests()
            .next()
            .cloned()
            .ok_or_else(|| {
                BrokerIntegrationError::InvalidConfiguration(
                    "broker manifest registry is empty".to_string(),
                )
            })?;
        validate_broker_only_manifest(
            &broker_manifest,
            &file_config.broker_server_id,
            &file_config.broker_tool_name,
        )?;
        let (keys, active_defense_executor_signer, decoy_registry_master_key) =
            file_config.load_keys(authority_signer)?;
        composition_config.validate(&keys)?;

        for (path, label) in [
            (
                &file_config.execution_authority_database_path,
                "execution authority database",
            ),
            (
                &file_config.kernel_admission_operation_database_path,
                "kernel admission operation database",
            ),
            (
                &file_config.governed_admin_database_path,
                "governed admin database",
            ),
            (
                &file_config.broker_receipt_database_path,
                "broker receipt database",
            ),
            (&file_config.issuance_database_path, "issuance database"),
            (
                &file_config.security_runtime.security_state_database_path,
                "security state database",
            ),
            (
                &file_config.security_runtime.decoy_registry_database_path,
                "decoy registry database",
            ),
            (
                &file_config.security_runtime.approval_database_path,
                "security approval database",
            ),
            (
                &file_config.security_runtime.alert_outbox_database_path,
                "security alert outbox database",
            ),
            (
                &file_config.security_runtime.alert_archive_path,
                "security alert archive",
            ),
            (
                &file_config.enterprise_migration.state_database_path,
                "enterprise migration state database",
            ),
        ] {
            prepare_private_database(path, label)?;
        }

        validate_distinct_database_files(&[
            (
                &file_config.execution_authority_database_path,
                "execution authority database",
            ),
            (
                &file_config.kernel_admission_operation_database_path,
                "kernel admission operation database",
            ),
            (
                &file_config.governed_admin_database_path,
                "governed admin database",
            ),
            (
                &file_config.broker_receipt_database_path,
                "broker receipt database",
            ),
            (&file_config.issuance_database_path, "issuance database"),
            (
                &file_config.native_receipt_database_path,
                "native receipt database",
            ),
            (
                &file_config.security_runtime.security_state_database_path,
                "security state database",
            ),
            (
                &file_config.security_runtime.decoy_registry_database_path,
                "decoy registry database",
            ),
            (
                &file_config.security_runtime.approval_database_path,
                "security approval database",
            ),
            (
                &file_config.security_runtime.alert_outbox_database_path,
                "security alert outbox database",
            ),
            (
                &file_config.security_runtime.alert_archive_path,
                "security alert archive",
            ),
            (
                &file_config.enterprise_migration.state_database_path,
                "enterprise migration state database",
            ),
        ])?;
        let migration_bindings = Arc::new(load_production_broker_migration_bindings(
            &file_config.enterprise_migration,
        )?);
        let host_database_paths = ProductionBrokerHostDatabasePaths {
            receipt_database_path: file_config.native_receipt_database_path.clone(),
            revocation_database_path: file_config.execution_authority_database_path.clone(),
            budget_database_path: file_config.execution_authority_database_path.clone(),
            admission_operation_database_path: file_config
                .kernel_admission_operation_database_path
                .clone(),
            approval_database_path: file_config.security_runtime.approval_database_path.clone(),
        };
        let host_database_identities = ProductionBrokerHostDatabaseIdentities {
            receipt_database: RetainedDatabaseFileIdentity::open(
                &host_database_paths.receipt_database_path,
                "normal receipt database",
            )?,
            revocation_database: RetainedDatabaseFileIdentity::open(
                &host_database_paths.revocation_database_path,
                "kernel revocation database",
            )?,
            budget_database: RetainedDatabaseFileIdentity::open(
                &host_database_paths.budget_database_path,
                "kernel budget database",
            )?,
            admission_operation_database: RetainedDatabaseFileIdentity::open(
                &host_database_paths.admission_operation_database_path,
                "kernel admission operation database",
            )?,
            approval_database: RetainedDatabaseFileIdentity::open(
                &host_database_paths.approval_database_path,
                "kernel approval database",
            )?,
        };
        let migration_enforcer: Arc<dyn BrokerMigrationEnforcer> = migration_bindings.clone();
        let composition = ProductionBrokerComposition::open(
            composition_config,
            keys,
            migration_enforcer,
        )?;
        let budget_store = composition.budget_store();
        migration_bindings.ensure_fail_closed()?;
        let authority = composition.start_authority()?;

        let security_runtime_factory = ProductionSecurityRuntimeFactory::open(
            ProductionSecurityRuntimeFactoryConfig {
                runtime: file_config.security_runtime.clone(),
                admission_operation_database_path: file_config
                    .kernel_admission_operation_database_path
                    .clone(),
                budget_database_path: file_config.execution_authority_database_path.clone(),
                native_receipt_database_path: file_config.native_receipt_database_path.clone(),
                tripwire_tenant_id: TenantId::new(file_config.receipt_tenant_id.clone()).map_err(
                    |error| {
                        BrokerIntegrationError::InvalidConfiguration(format!(
                            "tripwire tenant id is invalid: {error}"
                        ))
                    },
                )?,
            },
            decoy_registry_master_key,
            budget_store,
        )?;
        validate_host_database_identities(&host_database_paths, &host_database_identities)?;

        let reserved_database_paths = vec![
            (
                file_config.execution_authority_database_path.clone(),
                "execution authority database",
            ),
            (
                file_config.governed_admin_database_path.clone(),
                "governed admin database",
            ),
            (
                file_config.broker_receipt_database_path.clone(),
                "broker receipt database",
            ),
            (
                file_config.issuance_database_path.clone(),
                "issuance database",
            ),
            (
                file_config.native_receipt_database_path.clone(),
                "native receipt database",
            ),
            (
                file_config.kernel_admission_operation_database_path.clone(),
                "kernel admission operation database",
            ),
            (
                file_config
                    .security_runtime
                    .security_state_database_path
                    .clone(),
                "security state database",
            ),
            (
                file_config
                    .security_runtime
                    .decoy_registry_database_path
                    .clone(),
                "decoy registry database",
            ),
            (
                file_config.security_runtime.approval_database_path.clone(),
                "security approval database",
            ),
            (
                file_config
                    .security_runtime
                    .alert_outbox_database_path
                    .clone(),
                "security alert outbox database",
            ),
            (
                file_config.security_runtime.alert_archive_path.clone(),
                "security alert archive",
            ),
            (
                file_config.enterprise_migration.state_database_path.clone(),
                "enterprise migration state database",
            ),
        ];
        let active_defense_config = file_config.active_defense.clone();
        let active_defense_tenant_id = file_config.receipt_tenant_id.clone();
        let active_defense_producer_id = file_config.security_runtime.tripwire_producer_id.clone();
        let active_defense_producer_key_id = file_config
            .security_runtime
            .tripwire_producer_key_id
            .clone();
        let active_defense_policy_version = file_config
            .security_runtime
            .tripwire_policy_version
            .clone();
        let active_defense_max_event_age_ms =
            file_config.security_runtime.tripwire_max_event_age_ms;
        let active_defense_max_future_skew_ms =
            file_config.security_runtime.tripwire_max_future_skew_ms;
        let mut active_defense_disallowed_signer_keys = [
            &file_config.authority_public_key,
            &file_config.trusted_broker,
            &file_config.trusted_capability_issuer,
            &file_config.trusted_release_receipt_signer,
            &file_config.active_defense.response_authority.trusted_authority,
            &file_config.broker_manifest_public_key,
            &file_config.admin.subject,
        ]
        .into_iter()
        .map(PublicKey::to_hex)
        .collect::<BTreeSet<_>>();
        active_defense_disallowed_signer_keys.extend(
            file_config
                .admin
                .trusted_approvers
                .iter()
                .map(PublicKey::to_hex),
        );
        let broker_server_id = file_config.broker_server_id;
        let broker_tool_name = file_config.broker_tool_name;
        let broker_manifest_public_key = file_config.broker_manifest_public_key;
        Ok(Self {
            authority: Some(authority),
            composition,
            broker_manifest,
            broker_manifest_public_key,
            broker_server_id,
            broker_tool_name,
            contract_digest,
            host_database_paths,
            host_database_identities,
            reserved_database_paths,
            security_runtime_factory,
            active_defense_config,
            active_defense_tenant_id,
            active_defense_producer_id,
            active_defense_producer_key_id,
            active_defense_policy_version,
            active_defense_max_event_age_ms,
            active_defense_max_future_skew_ms,
            active_defense_disallowed_signer_keys,
            active_defense_executor_signer,
            active_defense_host: None,
            canonical_active_defense_signer: None,
            migration_bindings,
        })
    }

    /// Start the production correlator and TTL response worker from the exact
    /// durable authorities owned by this broker product.
    ///
    /// The caller supplies policy material and signed response authorization
    /// artifacts. The fully composed enforce-mode kernel is bound separately
    /// before the host can report full readiness. The policy planner cannot
    /// acknowledge execution on its own.
    /// Durable planning identities, stores, evidence indexing, alerting,
    /// blast-radius resolution, and the clock cannot be substituted
    /// independently of the broker product.
    async fn start_active_defense(
        &mut self,
        config: &ProductionBrokerActiveDefenseStartConfig,
    ) -> Result<(), BrokerIntegrationError> {
        self.migration_bindings.ensure_fail_closed()?;
        if self.active_defense_host.is_some() {
            return Err(BrokerIntegrationError::Conflict(
                "production active-defense host is already started".to_string(),
            ));
        }
        let signer = Arc::clone(&self.active_defense_executor_signer);
        ensure_active_defense_signer_role_separation(
            &signer.public_key(),
            &self.active_defense_disallowed_signer_keys,
        )?;
        let signer = retain_exact_active_defense_signer(
            &mut self.canonical_active_defense_signer,
            &signer,
        )?;
        let (host_config, declassification_lifecycle) =
            self.security_runtime_factory.active_defense_host_config(
                Arc::clone(&signer),
                Arc::clone(&config.response_policy_planner),
                config.active_defense.clone(),
                config.worker_loop,
            )?;
        let registry = Arc::new(ActiveDefenseServiceRegistry::default());
        let host = ProductionActiveDefenseHost::start_with_declassification_lifecycle(
            registry,
            host_config,
            declassification_lifecycle,
        )
        .await
        .map_err(|error| {
            BrokerIntegrationError::Conflict(format!(
                "production active-defense startup failed: {error}"
            ))
        })?;
        self.active_defense_host = Some(host);
        Ok(())
    }

    /// Start the broker-owned active-defense host from one authenticated Chio
    /// policy and the external response authority pinned in the product
    /// contract. This is the production entry point used by CLI and remote MCP
    /// startup. It deliberately offers no in-process fallback planner.
    pub async fn start_configured_active_defense(
        &mut self,
        loaded_policy: &crate::policy::LoadedPolicy,
    ) -> Result<(), BrokerIntegrationError> {
        if !matches!(
            loaded_policy.active_defense.mode,
            super::runtime::ActiveDefenseMode::Enforce
        ) {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "production broker active defense requires enforce mode".to_string(),
            ));
        }
        if loaded_policy.active_defense_rules.is_empty() {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "production broker active defense requires at least one authenticated temporal rule"
                    .to_string(),
            ));
        }
        let signer = Arc::clone(&self.active_defense_executor_signer);
        ensure_active_defense_signer_role_separation(
            &signer.public_key(),
            &self.active_defense_disallowed_signer_keys,
        )?;
        let tenant_id = TenantId::new(self.active_defense_tenant_id.clone()).map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-defense tenant id is invalid: {error}"
            ))
        })?;
        let producer_id = ProducerId::new(self.active_defense_producer_id.clone()).map_err(
            |error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "active-defense producer id is invalid: {error}"
                ))
            },
        )?;
        let producer_key_id =
            RecordId::new(self.active_defense_producer_key_id.clone()).map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "active-defense producer key id is invalid: {error}"
                ))
            })?;
        let policy_version =
            RecordId::new(self.active_defense_policy_version.clone()).map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "active-defense policy version is invalid: {error}"
                ))
            })?;
        if loaded_policy
            .active_defense_rules
            .iter()
            .any(|rule| rule.policy_version() != &policy_version)
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "active-defense temporal rule policy version does not match the production event authority"
                    .to_string(),
            ));
        }

        let authority = ProductionActiveResponseAuthorityClient::new(
            self.active_defense_config.response_authority.clone(),
            Arc::clone(&signer),
        )
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-response authority client is invalid: {error}"
            ))
        })?;
        authority.ensure_ready().map_err(|_| {
            BrokerIntegrationError::Conflict(
                "active-response policy and artifact authority is unavailable".to_string(),
            )
        })?;
        let response_policy_planner: Arc<dyn AttestedFindingResponsePolicyPlanner> =
            Arc::new(authority);

        let correlation_policy = chio_quarantine::CorrelationPolicy::new(
            self.active_defense_config
                .correlation_bounded_lateness_ms,
            self.active_defense_config.correlation_max_scan_events,
            self.active_defense_config.correlation_cas_retries,
            self.active_defense_config
                .correlation_allow_verified_receipts,
        )
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-defense correlation policy is invalid: {error}"
            ))
        })?;
        let scheduler_policy = chio_quarantine::SchedulerPolicy {
            lease_duration_ms: self.active_defense_config.scheduler_lease_duration_ms,
            base_backoff_ms: self.active_defense_config.scheduler_base_backoff_ms,
            max_backoff_ms: self.active_defense_config.scheduler_max_backoff_ms,
            operator_page_threshold_ms: self
                .active_defense_config
                .scheduler_operator_page_threshold_ms,
            max_claims: self.active_defense_config.scheduler_max_claims,
        }
        .validate()
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-defense scheduler policy is invalid: {error}"
            ))
        })?;
        let lease_owner_id = LeaseOwnerId::new(
            self.active_defense_config.scheduler_lease_owner_id.clone(),
        )
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "active-defense scheduler owner is invalid: {error}"
            ))
        })?;
        let policy_hash = decode_runtime_policy_digest(&loaded_policy.identity.runtime_hash)?;
        let policy_hashes = BTreeMap::from([(policy_version.clone(), policy_hash)]);
        let active_defense = ProductionActiveDefenseConfig {
            scheduler: ProductionResponseSchedulerConfig {
                tenant_id: tenant_id.clone(),
                lease_owner_id,
                scheduler_policy,
                renewal_margin_ms: self.active_defense_config.scheduler_renewal_margin_ms,
            },
            correlation_policy,
            rules: loaded_policy.active_defense_rules.clone(),
            policy_hashes,
            trusted_event_producers: vec![TrustedSecurityEventProducer {
                tenant_id,
                producer_id,
                producer_key_id,
                policy_version,
                producer_key: signer.public_key(),
            }],
            trusted_event_receipt_producers: Vec::new(),
            max_event_age_ms: self.active_defense_max_event_age_ms,
            max_future_skew_ms: self.active_defense_max_future_skew_ms,
            response_recovery_limits: AttestedFindingResponseRecoveryLimits::new(
                self.active_defense_config.recovery_max_records_per_pass,
                self.active_defense_config.recovery_max_startup_records,
                self.active_defense_config.recovery_max_startup_wall_clock_ms,
            )
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "active-response recovery bounds are invalid: {error}"
                ))
            })?,
        };
        let config = ProductionBrokerActiveDefenseStartConfig {
            response_policy_planner,
            active_defense,
            worker_loop: ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_millis(
                    self.active_defense_config.worker_tick_interval_ms,
                ),
            },
        };
        self.start_active_defense(&config).await?;
        self.ensure_active_defense_bootstrap_ready()
    }

    #[must_use]
    pub fn active_defense_host(&self) -> Option<&ProductionActiveDefenseHost> {
        self.active_defense_host.as_ref()
    }

    /// Fail closed unless the live correlator owns a running or ready TTL
    /// worker and every underlying production port still passes readiness.
    pub fn ensure_active_defense_ready(&self) -> Result<(), BrokerIntegrationError> {
        self.migration_bindings.ensure_fail_closed()?;
        let host = self
            .active_defense_host
            .as_ref()
            .ok_or(BrokerIntegrationError::MissingComponent(
                "production active-defense host",
            ))?;
        self.security_runtime_factory
            .ensure_active_response_kernel_bound()?;
        host.ensure_ready().map_err(|error| {
            BrokerIntegrationError::Conflict(format!(
                "production active-defense host is unavailable: {error}"
            ))
        })
    }

    fn ensure_active_defense_bootstrap_ready(&self) -> Result<(), BrokerIntegrationError> {
        self.migration_bindings.ensure_fail_closed()?;
        self.active_defense_host
            .as_ref()
            .ok_or(BrokerIntegrationError::MissingComponent(
                "production active-defense host",
            ))?
            .ensure_bootstrap_ready()
            .map_err(|error| {
                BrokerIntegrationError::Conflict(format!(
                    "production active-defense bootstrap is unavailable: {error}"
                ))
            })
    }

    /// Bind the dedicated, fully composed enforce-mode response kernel before
    /// response recovery or product traffic begins. A changed authority,
    /// generation, or incomplete runtime is rejected.
    pub fn bind_active_response_kernel(
        &self,
        kernel: Arc<ChioKernel>,
    ) -> Result<(), BrokerIntegrationError> {
        self.ensure_active_defense_bootstrap_ready()?;
        ensure_active_response_submission_authority_is_pinned(
            kernel.as_ref(),
            &self
                .active_defense_config
                .response_authority
                .trusted_authority,
        )?;
        self.security_runtime_factory
            .bind_active_response_kernel(kernel)?;
        self.active_defense_host
            .as_ref()
            .ok_or(BrokerIntegrationError::MissingComponent(
                "production active-defense host",
            ))?
            .resume_incomplete_active_responses()
            .map_err(|error| {
                BrokerIntegrationError::Conflict(format!(
                    "production active-response recovery failed: {error}"
                ))
            })?;
        self.ensure_active_defense_ready()
    }

    /// Stop and unpublish the worker before tearing down the broker authority.
    /// Active overlay contributions keep the host owned and fail the shutdown.
    pub async fn shutdown_active_defense(&mut self) -> Result<(), BrokerIntegrationError> {
        let Some(host) = self.active_defense_host.as_mut() else {
            return Ok(());
        };
        host.shutdown().await.map_err(|error| {
            BrokerIntegrationError::Conflict(format!(
                "production active-defense shutdown failed: {error}"
            ))
        })?;
        self.active_defense_host = None;
        Ok(())
    }

    pub(crate) fn install_kernel_authorities_before_security_publication(
        &self,
        kernel: &mut ChioKernel,
    ) -> Result<(), BrokerIntegrationError> {
        self.migration_bindings.ensure_fail_closed()?;
        self.ensure_active_defense_bootstrap_ready()?;
        self.security_runtime_factory
            .install_kernel_authorities_before_publication(kernel)?;
        install_active_response_submission_authority_before_publication(
            kernel,
            &self
                .active_defense_config
                .response_authority
                .trusted_authority,
        )?;
        self.composition
            .install_kernel_authorities_before_security_publication(kernel)
    }

    pub(crate) fn register_kernel_route_after_security_publication(
        &self,
        kernel: &mut ChioKernel,
    ) -> Result<(), BrokerIntegrationError> {
        self.migration_bindings.ensure_fail_closed()?;
        self.ensure_active_defense_bootstrap_ready()?;
        self.composition
            .register_kernel_route_after_security_publication(kernel)
    }

    pub fn compose_manifest_registry(
        &self,
        mut registry: VerifiedManifestRegistry,
    ) -> Result<ProductionBrokerManifestRegistry, BrokerIntegrationError> {
        self.migration_bindings.ensure_fail_closed()?;
        if registry.verified_manifests().next().is_none() {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker product requires at least one admitted ordinary tool manifest".to_string(),
            ));
        }
        if registry
            .verified_manifests()
            .any(|signed| signed.manifest.server_id == self.broker_server_id)
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker server identity conflicts with an admitted direct route".to_string(),
            ));
        }
        registry
            .register_public_only(
                self.broker_manifest.clone(),
                &self.broker_manifest_public_key,
                RuntimeToolTopology::remote(),
            )
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker manifest registration failed: {error}"
                ))
            })?;
        Ok(ProductionBrokerManifestRegistry {
            registry: Arc::new(registry),
            broker_contract_digest: self.contract_digest.clone(),
        })
    }

    pub fn build_security_runtime(
        &self,
        manifests: &ProductionBrokerManifestRegistry,
        runtime_policy_hash: &str,
    ) -> Result<super::SecurityRuntime, BrokerIntegrationError> {
        self.ensure_active_defense_bootstrap_ready()?;
        let signer = Arc::clone(&self.active_defense_executor_signer);
        if !exact_active_defense_signer_matches(
            self.canonical_active_defense_signer.as_ref(),
            &signer,
        ) {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "security runtime signer does not match the active-defense evidence authority"
                    .to_string(),
            ));
        }
        if manifests.broker_contract_digest != self.contract_digest
            || manifests
                .registry
                .verified_manifest(&self.broker_server_id)
                .is_none()
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker security runtime received a foreign or incomplete manifest registry"
                    .to_string(),
            ));
        }
        self.security_runtime_factory.build(
            Arc::clone(&manifests.registry),
            signer,
            runtime_policy_hash,
        )
    }

    /// Bind one MCP edge to the exact broker-owned tenant, durable flow store,
    /// agent principal, and server-issued capability set.
    pub fn security_invocation_context_authority(
        &self,
        authenticated_tenant_id: Option<&str>,
        agent_id: &str,
        issued_capabilities: &[CapabilityToken],
    ) -> Result<Arc<dyn chio_kernel::SecurityInvocationContextAuthority>, BrokerIntegrationError>
    {
        self.security_runtime_factory
            .security_invocation_context_authority(
                authenticated_tenant_id,
                agent_id,
                issued_capabilities,
            )
    }

    pub fn resolve_host_database_paths(
        &self,
        receipt_database_path: Option<&Path>,
        revocation_database_path: Option<&Path>,
        budget_database_path: Option<&Path>,
        admission_operation_database_path: Option<&Path>,
        authority_database_path: Option<&Path>,
        approval_database_path: Option<&Path>,
        session_database_path: Option<&Path>,
    ) -> Result<ProductionBrokerHostDatabasePaths, BrokerIntegrationError> {
        require_matching_runtime_path(
            receipt_database_path,
            &self.host_database_paths.receipt_database_path,
            &self.host_database_identities.receipt_database,
            "normal receipt database",
        )?;
        require_matching_runtime_path(
            revocation_database_path,
            &self.host_database_paths.revocation_database_path,
            &self.host_database_identities.revocation_database,
            "kernel revocation database",
        )?;
        require_matching_runtime_path(
            budget_database_path,
            &self.host_database_paths.budget_database_path,
            &self.host_database_identities.budget_database,
            "kernel budget database",
        )?;
        require_matching_runtime_path(
            admission_operation_database_path,
            &self.host_database_paths.admission_operation_database_path,
            &self.host_database_identities.admission_operation_database,
            "kernel admission operation database",
        )?;
        require_matching_runtime_path(
            approval_database_path,
            &self.host_database_paths.approval_database_path,
            &self.host_database_identities.approval_database,
            "kernel approval database",
        )?;
        for (path, label) in [
            (
                authority_database_path,
                "kernel capability authority database",
            ),
            (session_database_path, "remote MCP session database"),
        ] {
            if let Some(path) = path {
                require_disjoint_runtime_path(path, label, &self.reserved_database_paths)?;
            }
        }
        Ok(self.host_database_paths.clone())
    }

    pub(crate) fn validate_host_database_bindings(&self) -> Result<(), BrokerIntegrationError> {
        validate_host_database_identities(&self.host_database_paths, &self.host_database_identities)
    }

    pub(crate) fn validate_kernel_receipt_store_binding(
        &self,
        receipt_store: &dyn ReceiptStore,
    ) -> Result<(), BrokerIntegrationError> {
        self.validate_host_database_bindings()?;
        let actual = receipt_store
            .durable_storage_identity()
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "normal receipt database identity lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                BrokerIntegrationError::InvalidConfiguration(
                    "normal receipt store does not expose a durable identity".to_string(),
                )
            })?;
        let expected =
            receipt_store_identity_hash(self.host_database_identities.receipt_database.identity)?;
        if actual != expected {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "normal receipt store opened a different durable commit domain".to_string(),
            ));
        }
        Ok(())
    }

    pub fn require_default_route_capability(
        &self,
        capabilities: &[crate::policy::DefaultCapability],
    ) -> Result<(), BrokerIntegrationError> {
        require_broker_route_default_capability(
            capabilities,
            &self.broker_server_id,
            &self.broker_tool_name,
        )
    }

    #[must_use]
    pub fn broker_server_id(&self) -> &str {
        &self.broker_server_id
    }

    #[must_use]
    pub fn contract_digest(&self) -> &str {
        &self.contract_digest
    }
}

impl Drop for ProductionBrokerProductRuntime {
    fn drop(&mut self) {
        let authority = self.authority.take();
        if let Some(mut host) = self.active_defense_host.take() {
            host.schedule_detached_teardown(Box::new(move || {
                if let Some(authority) = authority {
                    let _ = authority.shutdown();
                }
            }));
            drop(host);
        } else if let Some(authority) = authority {
            let _ = authority.shutdown();
        }
        self.canonical_active_defense_signer = None;
    }
}

fn validate_broker_only_manifest(
    signed: &SignedManifest,
    broker_server_id: &str,
    broker_tool_name: &str,
) -> Result<(), BrokerIntegrationError> {
    let manifest = &signed.manifest;
    if manifest.server_id != broker_server_id
        || manifest.tools.len() != 1
        || manifest.tools[0].name != broker_tool_name
        || !manifest.server_tools.is_empty()
        || manifest.required_permissions.is_some()
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(
            "broker manifest must expose only the broker route and grant no direct host access"
                .to_string(),
        ));
    }
    Ok(())
}

fn require_broker_route_default_capability(
    capabilities: &[crate::policy::DefaultCapability],
    broker_server_id: &str,
    broker_tool_name: &str,
) -> Result<(), BrokerIntegrationError> {
    let reachable = capabilities.iter().any(|capability| {
        capability.scope.grants.iter().any(|grant| {
            (grant.server_id == "*" || grant.server_id == broker_server_id)
                && (grant.tool_name == "*" || grant.tool_name == broker_tool_name)
                && grant.operations.contains(&Operation::Invoke)
        })
    });
    if !reachable {
        return Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "default policy does not authorize the broker-only route {broker_server_id}/{broker_tool_name}"
        )));
    }
    Ok(())
}

fn require_matching_runtime_path(
    configured: Option<&Path>,
    authoritative: &Path,
    authoritative_identity: &RetainedDatabaseFileIdentity,
    label: &str,
) -> Result<(), BrokerIntegrationError> {
    let Some(configured) = configured else {
        return Ok(());
    };
    validate_database_path(configured, label, false)?;
    let configured_identity = stable_database_file_identity(configured, label)?;
    if normalized_path_identity(configured, label)?
        != normalized_path_identity(authoritative, label)?
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} conflicts with the broker product commit domain"
        )));
    }
    authoritative_identity.validate_path_binding(authoritative, label)?;
    if configured_identity != authoritative_identity.identity {
        return Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} descriptor identity conflicts with the broker product commit domain"
        )));
    }
    Ok(())
}

fn validate_host_database_identities(
    paths: &ProductionBrokerHostDatabasePaths,
    identities: &ProductionBrokerHostDatabaseIdentities,
) -> Result<(), BrokerIntegrationError> {
    for (path, expected, label) in [
        (
            paths.receipt_database_path.as_path(),
            &identities.receipt_database,
            "normal receipt database",
        ),
        (
            paths.revocation_database_path.as_path(),
            &identities.revocation_database,
            "kernel revocation database",
        ),
        (
            paths.budget_database_path.as_path(),
            &identities.budget_database,
            "kernel budget database",
        ),
        (
            paths.admission_operation_database_path.as_path(),
            &identities.admission_operation_database,
            "kernel admission operation database",
        ),
        (
            paths.approval_database_path.as_path(),
            &identities.approval_database,
            "kernel approval database",
        ),
    ] {
        expected.validate_path_binding(path, label)?;
    }
    Ok(())
}

fn require_disjoint_runtime_path(
    configured: &Path,
    label: &str,
    reserved: &[(PathBuf, &'static str)],
) -> Result<(), BrokerIntegrationError> {
    validate_database_path(configured, label, false)?;
    let configured_identity = normalized_path_identity(configured, label)?;
    for (reserved_path, reserved_label) in reserved {
        if configured_identity == normalized_path_identity(reserved_path, reserved_label)? {
            return Err(BrokerIntegrationError::InvalidConfiguration(format!(
                "{label} must not share the broker product database used by {reserved_label}"
            )));
        }
    }
    Ok(())
}

impl ProductionBrokerCompositionConfig {
    pub fn validate(&self, keys: &ProductionBrokerKeys) -> Result<(), BrokerIntegrationError> {
        self.validate_contract()?;
        if self.authority_public_key != keys.authority_signer.public_key()
            || self.trusted_capability_issuer != keys.capability_issuer_signer.public_key()
            || self.trusted_release_receipt_signer != keys.release_receipt_signer.public_key()
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "production broker signing keys do not match configured trust roots".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_contract(&self) -> Result<(), BrokerIntegrationError> {
        for (value, label) in [
            (&self.broker_server_id, "broker server id"),
            (&self.broker_tool_name, "broker tool name"),
            (&self.broker_audience, "broker audience"),
            (&self.parent_audience, "parent audience"),
            (&self.broker_client.tenant_scope, "broker tenant scope"),
            (&self.supplemental_verifier_id, "supplemental verifier id"),
            (
                &self.revocation_authority_domain,
                "revocation authority domain",
            ),
        ] {
            validate_identifier(value, label)?;
        }
        validate_identifier(&self.receipt_tenant_id, "broker receipt tenant id")?;
        if self.receipt_tenant_id != self.broker_client.tenant_scope
            || self.broker_client.timeout_ms == 0
            || self.broker_client.timeout_ms > 30_000
            || self.broker_client.expected_peer.process_id == 0
            || self.response_authority_expected_peer.process_id == 0
            || self.response_authority_expected_peer.process_id
                == self.broker_client.expected_peer.process_id
            || self.selected_provider_adapter_ids.is_empty()
            || self.selected_provider_adapter_ids.len() > MAX_PRODUCTION_SELECTED_PROVIDERS
            || self.maximum_pending_admissions == 0
            || self.maximum_pending_admissions > 65_536
            || self.authority_maximum_clock_skew_seconds == 0
            || self.authority_maximum_clock_skew_seconds > 30
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "production broker bounds or selected provider set is invalid".to_string(),
            ));
        }
        for provider in &self.selected_provider_adapter_ids {
            validate_identifier(provider, "selected provider adapter id")?;
        }
        if self.trusted_broker != self.broker_client.trusted_receipt_signer {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker IPC identity must match the broker receipt signer".to_string(),
            ));
        }
        let role_keys = [
            &self.authority_public_key,
            &self.trusted_broker,
            &self.trusted_capability_issuer,
            &self.trusted_release_receipt_signer,
            &self.trusted_response_authority,
        ]
        .into_iter()
        .map(PublicKey::to_hex)
        .collect::<BTreeSet<_>>();
        if role_keys.len() != 5
            || self.trusted_response_authority == self.admin_policy.subject
            || self
                .admin_policy
                .trusted_approvers
                .iter()
                .any(|approver| approver == &self.trusted_response_authority)
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "authority, issuer, release, broker, response, and governed admin signing roles are not separated"
                    .to_string(),
            ));
        }
        self.admin_policy.validate_for_runtime()?;

        let mut socket_identities = BTreeSet::new();
        for (path, label) in [
            (&self.authority_socket_path, "authority socket"),
            (&self.broker_client.socket_path, "broker socket"),
            (
                &self.response_authority_socket_path,
                "active-response authority socket",
            ),
        ] {
            validate_socket_path(path, label)?;
            if !socket_identities.insert(normalized_path_identity(path, label)?) {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "production broker authority sockets must use distinct normalized paths"
                        .to_string(),
                ));
            }
        }

        let database_paths = [
            (
                &self.enterprise_migration_state_database_path,
                "enterprise migration state database",
                true,
            ),
            (
                &self.execution_authority_database_path,
                "execution authority database",
                false,
            ),
            (
                &self.kernel_admission_operation_database_path,
                "kernel admission operation database",
                false,
            ),
            (
                &self.governed_admin_database_path,
                "governed admin database",
                false,
            ),
            (
                &self.broker_receipt_database_path,
                "broker receipt database",
                false,
            ),
            (&self.issuance_database_path, "issuance database", false),
            (
                &self.native_receipt_database_path,
                "native receipt database",
                true,
            ),
        ];
        let mut unique_paths = BTreeSet::new();
        for (path, label, must_exist) in database_paths {
            validate_database_path(path, label, must_exist)?;
            let identity = normalized_path_identity(path, label)?;
            if socket_identities.contains(&identity) {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "production broker sockets and databases must be distinct".to_string(),
                ));
            }
            if !unique_paths.insert(identity) {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "production broker databases must use distinct files".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
pub(super) struct ProductionBrokerComposition {
    runtime: ProductionBrokerRuntime,
}
