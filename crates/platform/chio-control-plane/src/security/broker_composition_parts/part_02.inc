#[cfg(unix)]
impl ProductionBrokerComposition {
    pub(super) fn open(
        config: ProductionBrokerCompositionConfig,
        keys: ProductionBrokerKeys,
        migration: Arc<dyn BrokerMigrationEnforcer>,
    ) -> Result<Self, BrokerIntegrationError> {
        config.validate(&keys)?;
        let broker_client = Arc::new(BrokerIpcClient::new(
            config.broker_client.clone(),
            Arc::clone(&keys.authority_signer),
        )?);

        // Cold-start phase one constructs the peer-pinned broker client but
        // does not dial it. This composition binds the authority endpoint
        // below, which lets brokerd authenticate and reconcile before it
        // publishes broker IPC. Kernel installation and route publication
        // remain closed on an authenticated broker connection.

        let prepared_database_files: [(&Path, &str); 5] = [
            (
                &config.execution_authority_database_path,
                "execution authority database",
            ),
            (
                &config.kernel_admission_operation_database_path,
                "kernel admission operation database",
            ),
            (
                &config.governed_admin_database_path,
                "governed admin database",
            ),
            (
                &config.broker_receipt_database_path,
                "broker receipt database",
            ),
            (&config.issuance_database_path, "issuance database"),
        ];
        for &(path, label) in &prepared_database_files {
            prepare_private_database(path, label)?;
        }
        validate_distinct_database_files(&[
            (
                &config.enterprise_migration_state_database_path,
                "enterprise migration state database",
            ),
            prepared_database_files[0],
            prepared_database_files[1],
            prepared_database_files[2],
            prepared_database_files[3],
            prepared_database_files[4],
            (
                &config.native_receipt_database_path,
                "native receipt database",
            ),
        ])?;

        let native_receipts = Arc::new(
            SqliteReceiptStore::open_existing_strict(&config.native_receipt_database_path)
                .map_err(|error| {
                    BrokerIntegrationError::InvalidConfiguration(format!(
                        "native broker receipt store is unavailable or invalid: {error}"
                    ))
                })?,
        );
        let registration: Arc<dyn BrokerAttemptRegistrationPort> = broker_client.clone();
        let execution_authority = Arc::new(AuthoritativeBrokerExecutionAdapter::open(
            &config.execution_authority_database_path,
            &config.kernel_admission_operation_database_path,
            AuthoritativeBrokerExecutionConfig {
                revocation_authority_domain: config.revocation_authority_domain.clone(),
                supplemental_verifier_id: config.supplemental_verifier_id.clone(),
                maximum_pending_admissions: config.maximum_pending_admissions,
            },
            registration,
            Arc::clone(&migration),
        )?);
        let supplemental_verifier = Arc::new(BrokerSupplementalQuotaVerifier::new(
            config.trusted_capability_issuer.clone(),
            config.broker_audience.clone(),
            SupplementalQuotaDestination::new(
                config.broker_server_id.clone(),
                config.broker_tool_name.clone(),
            )
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker supplemental destination is invalid: {error}"
                ))
            })?,
            true,
            config.supplemental_verifier_id.clone(),
        )?);
        let admin_authorizer = Arc::new(GovernedAdminAuthorizer::open(
            &config.governed_admin_database_path,
            config.admin_policy.clone(),
            config.broker_client.trusted_receipt_signer.clone(),
            Arc::new(SystemAdminClock),
        )?);
        let broker_receipt_sink = Arc::new(SqliteBrokerReceiptSink::open(
            &config.broker_receipt_database_path,
            config.broker_client.trusted_receipt_signer.clone(),
        )?);
        let integration_runtime = Arc::new(
            BrokerIntegrationRuntimeParts::default()
                .with_supplemental_verifier(supplemental_verifier)
                .with_execution_authority(Arc::clone(&execution_authority))
                .with_admin_authorizer(Arc::clone(&admin_authorizer))
                .with_receipt_sink(broker_receipt_sink)
                .build()?,
        );

        let receipt_store: Arc<dyn ReceiptStore> = native_receipts;
        let liveness = Arc::new(ReceiptStoreCapabilityLiveness::new(
            Arc::clone(&receipt_store),
            config.parent_audience.clone(),
        )?);
        let combined_authority = execution_authority.combined_authority();
        let revocations = Arc::new(CombinedAuthorityBrokerRevocations::new(
            Arc::clone(&combined_authority),
            config.revocation_authority_domain.clone(),
        )?);
        let control = Arc::new(DurableBrokerControlAuthority::open(
            &config.issuance_database_path,
            DurableBrokerControlConfig {
                tenant_scope: config.broker_client.tenant_scope.clone(),
                broker_audience: config.broker_audience.clone(),
                parent_audience: config.parent_audience.clone(),
                maximum_clock_skew_seconds: config.authority_maximum_clock_skew_seconds,
                selected_provider_adapter_ids: config.selected_provider_adapter_ids.clone(),
            },
            DurableBrokerControlAuthorities {
                issuer: Arc::clone(&keys.capability_issuer_signer),
                admin: Arc::clone(&admin_authorizer),
                liveness: Arc::clone(&liveness) as Arc<dyn CapabilityLiveness>,
                combined: Arc::clone(&combined_authority),
                migration: Arc::clone(&migration),
            },
        )?);

        let runtime = ProductionBrokerRuntime::bind_with_client(
            ProductionBrokerRuntimeConfig {
                authority_socket_path: config.authority_socket_path,
                authority_maximum_clock_skew_seconds: config.authority_maximum_clock_skew_seconds,
                broker_client: config.broker_client,
                broker_server_id: config.broker_server_id,
                broker_tool_name: config.broker_tool_name,
                selected_provider_adapter_ids: config.selected_provider_adapter_ids,
            },
            ProductionBrokerAuthorityBinding {
                runtime: integration_runtime,
                trusted_broker: config.trusted_broker,
                authority_signer: keys.authority_signer,
                broker_client,
                liveness,
                revocations: revocations as Arc<dyn BrokerRevocations>,
                control,
                migration,
            },
            ProductionBrokerReceiptBinding {
                store: receipt_store,
                signer: keys.release_receipt_signer,
                trusted_signer: config.trusted_release_receipt_signer,
                tenant_id: Some(config.receipt_tenant_id),
            },
        )?;
        Ok(Self { runtime })
    }

    pub(super) fn start_authority(
        &self,
    ) -> Result<ProductionBrokerAuthorityHandle, BrokerIntegrationError> {
        self.runtime.start_authority()
    }

    pub(super) fn budget_store(&self) -> Arc<dyn chio_kernel::budget_store::BudgetStore> {
        self.runtime.budget_store()
    }

    pub(super) fn install_kernel_authorities_before_security_publication(
        &self,
        kernel: &mut ChioKernel,
    ) -> Result<(), BrokerIntegrationError> {
        self.runtime
            .install_kernel_authorities_before_security_publication(kernel)
    }

    pub(super) fn register_kernel_route_after_security_publication(
        &self,
        kernel: &mut ChioKernel,
    ) -> Result<(), BrokerIntegrationError> {
        self.runtime
            .register_kernel_route_after_security_publication(kernel)
    }
}

trait BrokerControlClock: Send + Sync {
    fn now_unix_seconds(&self) -> BrokerResult<u64>;
}

#[derive(Debug)]
struct SystemBrokerControlClock;

impl BrokerControlClock for SystemBrokerControlClock {
    fn now_unix_seconds(&self) -> BrokerResult<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|error| {
                BrokerError::AuthorityUnavailable(format!(
                    "broker control clock is unavailable: {error}"
                ))
            })
    }
}

pub struct DurableBrokerControlAuthority {
    connection: Mutex<Connection>,
    operation_lock: Mutex<()>,
    tenant_scope: String,
    broker_audience: String,
    parent_audience: String,
    maximum_clock_skew_seconds: u64,
    selected_provider_adapter_ids: BTreeSet<String>,
    issuer: Arc<dyn SigningBackend>,
    admin: Arc<GovernedAdminAuthorizer>,
    liveness: Arc<dyn CapabilityLiveness>,
    combined_authority: Arc<SqliteAdmissionCaptureAuthority>,
    migration: Arc<dyn BrokerMigrationEnforcer>,
    clock: Arc<dyn BrokerControlClock>,
}

struct DurableBrokerControlConfig {
    tenant_scope: String,
    broker_audience: String,
    parent_audience: String,
    maximum_clock_skew_seconds: u64,
    selected_provider_adapter_ids: BTreeSet<String>,
}

struct DurableBrokerControlAuthorities {
    issuer: Arc<dyn SigningBackend>,
    admin: Arc<GovernedAdminAuthorizer>,
    liveness: Arc<dyn CapabilityLiveness>,
    combined: Arc<SqliteAdmissionCaptureAuthority>,
    migration: Arc<dyn BrokerMigrationEnforcer>,
}

#[derive(Debug, Clone)]
struct StoredBrokerCapability {
    capability_id: String,
    revocation_id: String,
    command_digest: String,
    request_authorization_digest: String,
    admin_authorization_digest: String,
    canonical_capability: Vec<u8>,
    capability: SignedBrokerCapability,
}

impl DurableBrokerControlAuthority {
    fn open(
        path: impl AsRef<Path>,
        config: DurableBrokerControlConfig,
        authorities: DurableBrokerControlAuthorities,
    ) -> Result<Self, BrokerIntegrationError> {
        Self::open_with_clock(
            path,
            config,
            authorities,
            Arc::new(SystemBrokerControlClock),
        )
    }

    fn open_with_clock(
        path: impl AsRef<Path>,
        config: DurableBrokerControlConfig,
        authorities: DurableBrokerControlAuthorities,
        clock: Arc<dyn BrokerControlClock>,
    ) -> Result<Self, BrokerIntegrationError> {
        let DurableBrokerControlConfig {
            tenant_scope,
            broker_audience,
            parent_audience,
            maximum_clock_skew_seconds,
            selected_provider_adapter_ids,
        } = config;
        let DurableBrokerControlAuthorities {
            issuer,
            admin,
            liveness,
            combined: combined_authority,
            migration,
        } = authorities;
        validate_identifier(&tenant_scope, "broker control tenant scope")?;
        validate_identifier(&broker_audience, "broker control audience")?;
        validate_identifier(&parent_audience, "broker parent audience")?;
        if maximum_clock_skew_seconds == 0
            || maximum_clock_skew_seconds > 30
            || selected_provider_adapter_ids.is_empty()
            || selected_provider_adapter_ids.len() > MAX_PRODUCTION_SELECTED_PROVIDERS
        {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker control clock skew or provider set is invalid".to_string(),
            ));
        }
        for provider in &selected_provider_adapter_ids {
            validate_identifier(provider, "broker control provider adapter id")?;
        }
        prepare_private_database(path.as_ref(), "broker issuance database")?;
        let connection = Connection::open_with_flags(
            path.as_ref(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "broker issuance database open failed: {error}"
            ))
        })?;
        let authority = Self {
            connection: Mutex::new(connection),
            operation_lock: Mutex::new(()),
            tenant_scope,
            broker_audience,
            parent_audience,
            maximum_clock_skew_seconds,
            selected_provider_adapter_ids,
            issuer,
            admin,
            liveness,
            combined_authority,
            migration,
            clock,
        };
        authority.migrate()?;
        authority.audit_persisted_state()?;
        Ok(authority)
    }

    fn connection(&self) -> BrokerResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| {
            BrokerError::Storage("broker issuance database lock is poisoned".to_string())
        })
    }

    fn operation(&self) -> BrokerResult<MutexGuard<'_, ()>> {
        self.operation_lock.lock().map_err(|_| {
            BrokerError::AuthorityUnavailable("broker control lock is poisoned".to_string())
        })
    }

    fn migrate(&self) -> Result<(), BrokerIntegrationError> {
        self.connection
            .lock()
            .map_err(|_| {
                BrokerIntegrationError::Conflict(
                    "broker issuance database lock is poisoned".to_string(),
                )
            })?
            .execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;
                PRAGMA foreign_keys = ON;
                PRAGMA trusted_schema = OFF;

                CREATE TABLE IF NOT EXISTS broker_capability_issuance (
                    capability_id TEXT PRIMARY KEY,
                    revocation_id TEXT NOT NULL UNIQUE,
                    parent_capability_id TEXT NOT NULL,
                    subject_key TEXT NOT NULL,
                    expires_at INTEGER NOT NULL CHECK(expires_at > 0),
                    command_digest TEXT NOT NULL,
                    request_authorization_digest TEXT NOT NULL,
                    admin_authorization_digest TEXT NOT NULL,
                    canonical_capability BLOB NOT NULL
                ) STRICT;

                CREATE TRIGGER IF NOT EXISTS broker_capability_issuance_no_update
                BEFORE UPDATE ON broker_capability_issuance
                BEGIN
                    SELECT RAISE(ABORT, 'broker capability issuance is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS broker_capability_issuance_no_delete
                BEFORE DELETE ON broker_capability_issuance
                BEGIN
                    SELECT RAISE(ABORT, 'broker capability issuance is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS broker_capability_issuance_distinct_identities
                BEFORE INSERT ON broker_capability_issuance
                WHEN EXISTS (
                    SELECT 1 FROM broker_capability_issuance
                    WHERE capability_id = NEW.revocation_id
                       OR revocation_id = NEW.capability_id
                )
                BEGIN
                    SELECT RAISE(ABORT, 'broker capability identities collide');
                END;
                "#,
            )
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker issuance database migration failed: {error}"
                ))
            })?;
        Ok(())
    }

    fn audit_persisted_state(&self) -> Result<(), BrokerIntegrationError> {
        let connection = self.connection.lock().map_err(|_| {
            BrokerIntegrationError::Conflict(
                "broker issuance database lock is poisoned".to_string(),
            )
        })?;
        let integrity: String = connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker issuance integrity check failed: {error}"
                ))
            })?;
        if integrity != "ok" {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "broker issuance database failed its integrity check".to_string(),
            ));
        }
        let mut statement = connection
            .prepare(
                r#"
                SELECT capability_id, revocation_id, parent_capability_id,
                       subject_key, expires_at, command_digest,
                       request_authorization_digest, admin_authorization_digest,
                       canonical_capability
                FROM broker_capability_issuance
                ORDER BY capability_id
                "#,
            )
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker issuance audit preparation failed: {error}"
                ))
            })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            })
            .map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker issuance audit query failed: {error}"
                ))
            })?;
        let mut issuance_identities = BTreeSet::new();
        for row in rows {
            let (
                capability_id,
                revocation_id,
                parent_capability_id,
                subject_key,
                expires_at,
                command_digest,
                request_authorization_digest,
                admin_authorization_digest,
                canonical_capability,
            ) = row.map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker issuance row is unreadable: {error}"
                ))
            })?;
            let capability: SignedBrokerCapability =
                decode_canonical(&canonical_capability, "persisted broker capability").map_err(
                    |error| {
                        BrokerIntegrationError::InvalidConfiguration(format!(
                            "broker issuance row is invalid: {error}"
                        ))
                    },
                )?;
            let command = IssueCapabilityCommand {
                schema: ISSUE_CAPABILITY_SCHEMA.to_string(),
                body: capability.body.clone(),
            };
            let expected_command_digest = digest_canonical(&command).map_err(|error| {
                BrokerIntegrationError::InvalidConfiguration(format!(
                    "broker issuance command audit failed: {error}"
                ))
            })?;
            let audited_expiry = u64::try_from(expires_at).map_err(|_| {
                BrokerIntegrationError::InvalidConfiguration(
                    "broker issuance row has an invalid expiry".to_string(),
                )
            })?;
            verify_capability(
                &capability,
                &self.issuer.public_key(),
                &self.broker_audience,
                capability.body.not_before_unix_seconds,
                true,
            )
            .map_err(BrokerIntegrationError::Broker)?;
            if capability_id != capability.body.capability_id
                || revocation_id != capability.body.revocation_id
                || parent_capability_id != capability.body.parent_capability_id
                || subject_key != capability.body.subject.to_hex()
                || audited_expiry != capability.body.expires_at_unix_seconds
                || command_digest != expected_command_digest
                || !is_digest(&request_authorization_digest)
                || !is_digest(&admin_authorization_digest)
            {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "broker issuance row failed its signed binding audit".to_string(),
                ));
            }
            if !issuance_identities.insert(capability_id)
                || !issuance_identities.insert(revocation_id)
            {
                return Err(BrokerIntegrationError::InvalidConfiguration(
                    "broker issuance state contains a cross-domain identity collision".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn issue(&self, request: &AuthorityControlRequest) -> BrokerResult<Vec<u8>> {
        let command: IssueCapabilityCommand =
            decode_canonical(&request.payload, "broker issue command")?;
        if command.schema != ISSUE_CAPABILITY_SCHEMA {
            return Err(BrokerError::InvalidRequest(
                "broker issue command schema is invalid".to_string(),
            ));
        }
        command.body.validate(true)?;
        self.migration
            .require_provider_enforced(&command.body.credential.provider)?;
        if command.body.issuer != self.issuer.public_key()
            || command.body.audience != self.broker_audience
            || !self
                .selected_provider_adapter_ids
                .contains(&command.body.provider_adapter_id)
        {
            return Err(BrokerError::AuthorizationDenied(
                "broker issue command issuer, audience, or provider is not selected".to_string(),
            ));
        }
        let now = self.clock.now_unix_seconds()?;
        if now == 0
            || command.body.not_before_unix_seconds > now
            || command.body.expires_at_unix_seconds <= now
        {
            return Err(BrokerError::AuthorizationDenied(
                "broker issue command is not currently live".to_string(),
            ));
        }
        let command_digest = digest_canonical(&command)?;
        let request_authorization_digest = sha256_hex(&request.authorization);
        if let Some(existing) =
            self.load_by_identity(&command.body.capability_id, &command.body.revocation_id)?
        {
            self.migration
                .require_provider_enforced(&command.body.credential.provider)?;
            let exact_authorization_replay = self.verify_existing_issue(
                &existing,
                &command,
                &command_digest,
                &request_authorization_digest,
                now,
            )?;
            if !exact_authorization_replay {
                let _authorization_digest = self.govern(request)?;
            }
            self.migration
                .require_provider_enforced(&command.body.credential.provider)?;
            return Ok(existing.canonical_capability);
        }
        if command.body.issued_at_unix_seconds > now
            || now.saturating_sub(command.body.issued_at_unix_seconds)
                > self.maximum_clock_skew_seconds
        {
            return Err(BrokerError::AuthorizationDenied(
                "new broker issue command is outside the authority clock window".to_string(),
            ));
        }
        self.verify_parent_and_revocations(&command.body, now)?;
        self.migration
            .require_provider_enforced(&command.body.credential.provider)?;
        let capability = issue_capability(command.body.clone(), self.issuer.as_ref(), true)?;
        let canonical_capability = canonical_json_bytes(&capability).map_err(|error| {
            BrokerError::Invariant(format!("broker capability encoding failed: {error}"))
        })?;
        self.migration
            .require_provider_enforced(&command.body.credential.provider)?;
        let admin_authorization_digest = self.govern(request)?;
        let expires_at = i64::try_from(command.body.expires_at_unix_seconds).map_err(|_| {
            BrokerError::InvalidRequest("broker capability expiry exceeds SQLite range".to_string())
        })?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        self.migration
            .require_provider_enforced(&command.body.credential.provider)?;
        transaction
            .execute(
                r#"
                INSERT INTO broker_capability_issuance (
                    capability_id, revocation_id, parent_capability_id,
                    subject_key, expires_at, command_digest,
                    request_authorization_digest, admin_authorization_digest,
                    canonical_capability
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    command.body.capability_id,
                    command.body.revocation_id,
                    command.body.parent_capability_id,
                    command.body.subject.to_hex(),
                    expires_at,
                    command_digest,
                    request_authorization_digest,
                    admin_authorization_digest,
                    canonical_capability,
                ],
            )
            .map_err(|error| {
                BrokerError::Conflict(format!(
                    "broker capability issuance persistence conflicted: {error}"
                ))
            })?;
        transaction.commit().map_err(storage_error)?;
        canonical_json_bytes(&capability).map_err(|error| {
            BrokerError::Invariant(format!(
                "broker capability response encoding failed: {error}"
            ))
        })
    }

    fn verify_existing_issue(
        &self,
        existing: &StoredBrokerCapability,
        command: &IssueCapabilityCommand,
        command_digest: &str,
        request_authorization_digest: &str,
        now: u64,
    ) -> BrokerResult<bool> {
        if existing.capability_id != command.body.capability_id
            || existing.revocation_id != command.body.revocation_id
            || existing.command_digest != command_digest
            || existing.capability.body != command.body
            || !is_digest(&existing.admin_authorization_digest)
        {
            return Err(BrokerError::Conflict(
                "broker capability identity was reused by a conflicting issue command".to_string(),
            ));
        }
        if existing.request_authorization_digest == request_authorization_digest {
            return Ok(true);
        }
        verify_capability(
            &existing.capability,
            &self.issuer.public_key(),
            &self.broker_audience,
            now,
            true,
        )?;
        self.verify_parent_and_revocations(&command.body, now)?;
        Ok(false)
    }

    fn verify_parent_and_revocations(
        &self,
        body: &BrokerCapabilityBody,
        now: u64,
    ) -> BrokerResult<()> {
        let parent = self
            .liveness
            .verify_live_parent(&CapabilityLivenessRequest {
                parent_capability_id: body.parent_capability_id.clone(),
                expected_subject: body.subject.clone(),
                expected_audience: self.parent_audience.clone(),
                now_unix_seconds: now,
            })?;
        if parent.capability_id != body.parent_capability_id
            || parent.subject != body.subject
            || parent.audience != self.parent_audience
            || parent.verified_at_unix_seconds != now
            || body.expires_at_unix_seconds > parent.expires_at_unix_seconds
        {
            return Err(BrokerError::AuthorizationDenied(
                "broker capability is not bounded by its live parent".to_string(),
            ));
        }
        let mut revocation_ids =
            Vec::with_capacity(parent.delegation_ancestor_ids.len().saturating_add(3));
        revocation_ids.push(body.parent_capability_id.clone());
        revocation_ids.extend(parent.delegation_ancestor_ids);
        revocation_ids.push(body.capability_id.clone());
        revocation_ids.push(body.revocation_id.clone());
        revocation_ids.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if revocation_ids.len() > 128 || revocation_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BrokerError::AuthorityUnavailable(
                "parent liveness returned an invalid revocation lineage".to_string(),
            ));
        }
        let snapshot = self
            .combined_authority
            .broker_revocation_snapshot(&revocation_ids)
            .map_err(|error| {
                BrokerError::AuthorityUnavailable(format!(
                    "broker issue revocation snapshot failed: {error}"
                ))
            })?;
        if !snapshot.revoked_ids().is_empty() {
            return Err(BrokerError::AuthorizationDenied(
                "broker capability or its parent lineage is revoked".to_string(),
            ));
        }
        Ok(())
    }

    fn status(&self, request: &AuthorityControlRequest) -> BrokerResult<Vec<u8>> {
        let command = self.decode_control_command(request)?;
        let stored = self.load_controlled_capability(&command)?;
        let _authorization_digest = self.govern(request)?;
        self.status_response(&stored, self.clock.now_unix_seconds()?)
    }

    fn revoke(&self, request: &AuthorityControlRequest) -> BrokerResult<Vec<u8>> {
        let command = self.decode_control_command(request)?;
        let stored = self.load_controlled_capability(&command)?;
        let _authorization_digest = self.govern(request)?;
        self.combined_authority
            .revoke(&stored.revocation_id)
            .map_err(|error| {
                BrokerError::AuthorityUnavailable(format!(
                    "combined broker revocation commit failed: {error}"
                ))
            })?;
        self.status_response(&stored, self.clock.now_unix_seconds()?)
    }

    fn decode_control_command(
        &self,
        request: &AuthorityControlRequest,
    ) -> BrokerResult<CapabilityControlCommand> {
        let command: CapabilityControlCommand =
            decode_canonical(&request.payload, "broker capability control command")?;
        if command.schema != CAPABILITY_CONTROL_SCHEMA
            || command.capability_id == command.revocation_id
        {
            return Err(BrokerError::InvalidRequest(
                "broker capability control schema or identity is invalid".to_string(),
            ));
        }
        validate_broker_identifier(&command.capability_id, "broker capability id")?;
        validate_broker_identifier(&command.revocation_id, "broker revocation id")?;
        command.credential.validate()?;
        Ok(command)
    }

    fn load_controlled_capability(
        &self,
        command: &CapabilityControlCommand,
    ) -> BrokerResult<StoredBrokerCapability> {
        let stored = self
            .load_by_identity(&command.capability_id, &command.revocation_id)?
            .ok_or_else(|| {
                BrokerError::AuthorizationDenied(
                    "broker capability was not issued by this authority".to_string(),
                )
            })?;
        if stored.capability_id != command.capability_id
            || stored.revocation_id != command.revocation_id
            || stored.capability.body.credential != command.credential
        {
            return Err(BrokerError::Conflict(
                "broker capability control command is misbound".to_string(),
            ));
        }
        Ok(stored)
    }

    fn status_response(&self, stored: &StoredBrokerCapability, now: u64) -> BrokerResult<Vec<u8>> {
        if now == 0 {
            return Err(BrokerError::AuthorityUnavailable(
                "broker control clock returned the epoch".to_string(),
            ));
        }
        let snapshot = self
            .combined_authority
            .broker_revocation_snapshot(&[
                stored.capability_id.clone(),
                stored.revocation_id.clone(),
            ])
            .map_err(|error| {
                BrokerError::AuthorityUnavailable(format!(
                    "combined broker status snapshot failed: {error}"
                ))
            })?;
        canonical_json_bytes(&CapabilityStatusResponse {
            schema: CAPABILITY_STATUS_SCHEMA.to_string(),
            capability_id: stored.capability_id.clone(),
            revocation_id: stored.revocation_id.clone(),
            revoked: !snapshot.revoked_ids().is_empty(),
            authority_commit_index: snapshot.authority_commit_index(),
            observed_at_unix_seconds: now,
        })
        .map_err(|error| {
            BrokerError::Invariant(format!("broker status response encoding failed: {error}"))
        })
    }

    fn govern(&self, request: &AuthorityControlRequest) -> BrokerResult<String> {
        let intent =
            daemon_admin_intent_digest(request.operation, &request.tenant_scope, &request.payload)?;
        let operation = self.admin.begin_intent_digest(
            &AdminAuthorization::new(request.authorization.clone())?,
            &intent,
        )?;
        Ok(operation.authorization_digest().to_string())
    }

    fn load_by_identity(
        &self,
        capability_id: &str,
        revocation_id: &str,
    ) -> BrokerResult<Option<StoredBrokerCapability>> {
        let row = self
            .connection()?
            .query_row(
                r#"
                SELECT capability_id, revocation_id, command_digest,
                       request_authorization_digest, admin_authorization_digest,
                       canonical_capability
                FROM broker_capability_issuance
                WHERE capability_id = ?1 OR capability_id = ?2
                   OR revocation_id = ?1 OR revocation_id = ?2
                "#,
                params![capability_id, revocation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?;
        row.map(
            |(
                capability_id,
                revocation_id,
                command_digest,
                request_authorization_digest,
                admin_authorization_digest,
                canonical_capability,
            )| {
                let capability =
                    decode_canonical(&canonical_capability, "stored broker capability")?;
                verify_capability(
                    &capability,
                    &self.issuer.public_key(),
                    &self.broker_audience,
                    capability.body.not_before_unix_seconds,
                    true,
                )?;
                Ok(StoredBrokerCapability {
                    capability_id,
                    revocation_id,
                    command_digest,
                    request_authorization_digest,
                    admin_authorization_digest,
                    canonical_capability,
                    capability,
                })
            },
        )
        .transpose()
    }
}

impl BrokerControlAuthority for DurableBrokerControlAuthority {
    fn control(&self, request: &AuthorityControlRequest) -> BrokerResult<Vec<u8>> {
        validate_control_request(request, &self.tenant_scope)?;
        let _operation = self.operation()?;
        match request.operation {
            IpcOperation::Issue => self.issue(request),
            IpcOperation::Revoke => self.revoke(request),
            IpcOperation::Status => self.status(request),
            _ => Err(BrokerError::InvalidRequest(
                "broker control operation is not supported".to_string(),
            )),
        }
    }
}

fn validate_control_request(
    request: &AuthorityControlRequest,
    tenant_scope: &str,
) -> BrokerResult<()> {
    if request.tenant_scope != tenant_scope {
        return Err(BrokerError::AuthorizationDenied(
            "broker control tenant scope is invalid".to_string(),
        ));
    }
    if !matches!(
        request.operation,
        IpcOperation::Issue | IpcOperation::Revoke | IpcOperation::Status
    ) || request.authorization.is_empty()
        || request.authorization.len() > 65_536
        || request.payload.is_empty()
        || request.payload.len() > chio_secret_broker::protocol::MAX_WIRE_BYTES
    {
        return Err(BrokerError::InvalidRequest(
            "broker control envelope is incomplete or oversized".to_string(),
        ));
    }
    Ok(())
}

fn decode_canonical<T>(bytes: &[u8], label: &str) -> BrokerResult<T>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|error| {
        BrokerError::InvalidRequest(format!("{label} decoding failed: {error}"))
    })?;
    let canonical = canonical_json_bytes(&value).map_err(|error| {
        BrokerError::InvalidRequest(format!("{label} encoding failed: {error}"))
    })?;
    if canonical != bytes {
        return Err(BrokerError::InvalidRequest(format!(
            "{label} is not canonical JSON"
        )));
    }
    Ok(value)
}

fn digest_canonical(value: &impl Serialize) -> BrokerResult<String> {
    canonical_json_bytes(value)
        .map(|canonical| sha256_hex(&canonical))
        .map_err(|error| {
            BrokerError::Invariant(format!("broker control digest encoding failed: {error}"))
        })
}

fn storage_error(error: rusqlite::Error) -> BrokerError {
    BrokerError::Storage(format!("broker issuance database failed: {error}"))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_broker_identifier(value: &str, label: &str) -> BrokerResult<()> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(BrokerError::InvalidRequest(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<(), BrokerIntegrationError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} is empty, oversized, padded, or contains a control byte"
        )));
    }
    Ok(())
}

fn validate_socket_path(path: &Path, label: &str) -> Result<(), BrokerIntegrationError> {
    let encoded = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute() || encoded.is_empty() || encoded.len() > 100 {
        return Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} path is not an absolute bounded Unix socket path"
        )));
    }
    validate_parent_directory(path, label)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(()),
        Ok(_) => Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} path exists but is not a Unix socket"
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} metadata failed: {error}"
        ))),
    }
}

fn validate_database_path(
    path: &Path,
    label: &str,
    must_exist: bool,
) -> Result<(), BrokerIntegrationError> {
    let encoded = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute()
        || encoded.is_empty()
        || encoded.len() > MAX_PRODUCTION_DATABASE_PATH_BYTES
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} path is not absolute and bounded"
        )));
    }
    let parent = open_trusted_parent_directory(path, label)?;
    match try_open_private_file_at(&parent, path, false, false) {
        Ok(file) => validate_private_file_descriptor(&file, label)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !must_exist => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(BrokerIntegrationError::InvalidConfiguration(format!(
                "{label} must already exist"
            )));
        }
        Err(error) => {
            return Err(BrokerIntegrationError::InvalidConfiguration(format!(
                "{label} metadata failed: {error}"
            )));
        }
    }
    Ok(())
}

fn validate_parent_directory(path: &Path, label: &str) -> Result<(), BrokerIntegrationError> {
    let _parent = open_trusted_parent_directory(path, label)?;
    Ok(())
}

fn validate_bounded_absolute_path(path: &Path, label: &str) -> Result<(), BrokerIntegrationError> {
    let encoded = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute()
        || encoded.is_empty()
        || encoded.len() > MAX_PRODUCTION_DATABASE_PATH_BYTES
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} path is not absolute and bounded"
        )));
    }
    Ok(())
}

fn open_trusted_parent_directory(path: &Path, label: &str) -> Result<File, BrokerIntegrationError> {
    validate_bounded_absolute_path(path, label)?;
    let parent = path.parent().ok_or_else(|| {
        BrokerIntegrationError::InvalidConfiguration(format!("{label} has no parent directory"))
    })?;
    let mut names = Vec::new();
    for component in parent.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => names.push(name.to_os_string()),
            std::path::Component::Prefix(_) => {
                return Err(BrokerIntegrationError::InvalidConfiguration(format!(
                    "{label} has an unsupported path prefix"
                )));
            }
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err(BrokerIntegrationError::InvalidConfiguration(format!(
                    "{label} path contains a dot component"
                )));
            }
        }
    }

    let root = rustix::fs::open(
        "/",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} root directory open failed: {error}"
        ))
    })?;
    let mut directory = File::from(root);
    validate_trusted_directory_descriptor(&directory, label, !names.is_empty())?;
    let name_count = names.len();
    for (index, name) in names.into_iter().enumerate() {
        let descriptor = rustix::fs::openat(
            &directory,
            &name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "{label} ancestor directory open failed: {error}"
            ))
        })?;
        let next = File::from(descriptor);
        validate_trusted_directory_descriptor(&next, label, index + 1 != name_count)?;
        directory = next;
    }
    Ok(directory)
}

fn validate_trusted_directory_descriptor(
    directory: &File,
    label: &str,
    allow_sticky_write: bool,
) -> Result<(), BrokerIntegrationError> {
    let metadata = directory.metadata().map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} parent descriptor metadata failed: {error}"
        ))
    })?;
    let effective_uid = rustix::process::geteuid().as_raw();
    let trusted_owner = metadata.uid() == effective_uid || metadata.uid() == 0;
    let group_or_world_writable = metadata.mode() & 0o022 != 0;
    let sticky = metadata.mode() & 0o1000 != 0;
    if !metadata.file_type().is_dir()
        || !trusted_owner
        || (group_or_world_writable && !(allow_sticky_write && sticky))
        || broker_file_grants_extended_acl_authority(directory, label)?
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} parent chain grants untrusted write authority"
        )));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn broker_file_grants_extended_acl_authority(
    file: &File,
    label: &str,
) -> Result<bool, BrokerIntegrationError> {
    for attribute in ["system.posix_acl_access", "system.posix_acl_default"] {
        let mut value = Vec::<u8>::with_capacity(1);
        match rustix::fs::fgetxattr(file, attribute, &mut value) {
            Ok(_) | Err(rustix::io::Errno::RANGE) => return Ok(true),
            Err(error) if error == rustix::io::Errno::NODATA => {}
            Err(error) if error == rustix::io::Errno::NOTSUP => {}
            Err(error) => {
                return Err(BrokerIntegrationError::InvalidConfiguration(format!(
                    "{label} ACL inspection failed: {error}"
                )));
            }
        }
    }
    Ok(false)
}

#[cfg(target_vendor = "apple")]
fn broker_file_grants_extended_acl_authority(
    file: &File,
    label: &str,
) -> Result<bool, BrokerIntegrationError> {
    chio_keyring::darwin_descriptor_grants_extended_acl_authority(file).map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} ACL inspection failed: {error}"
        ))
    })
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn broker_file_grants_extended_acl_authority(
    _file: &File,
    label: &str,
) -> Result<bool, BrokerIntegrationError> {
    Err(BrokerIntegrationError::InvalidConfiguration(format!(
        "{label} ACL inspection is unsupported on this platform"
    )))
}

fn try_open_private_file_at(
    parent: &File,
    path: &Path,
    writable: bool,
    create: bool,
) -> std::io::Result<File> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private file path has no file name",
        )
    })?;
    let mut flags = rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW;
    flags |= if writable {
        rustix::fs::OFlags::RDWR
    } else {
        rustix::fs::OFlags::RDONLY
    };
    if create {
        flags |= rustix::fs::OFlags::CREATE;
    }
    rustix::fs::openat(
        parent,
        file_name,
        flags,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map(File::from)
    .map_err(Into::into)
}

fn open_private_file_at(
    parent: &File,
    path: &Path,
    writable: bool,
    create: bool,
    label: &str,
) -> Result<File, BrokerIntegrationError> {
    try_open_private_file_at(parent, path, writable, create).map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} descriptor-relative open failed: {error}"
        ))
    })
}

fn validate_private_file_ownership_and_links(
    file: &File,
    label: &str,
) -> Result<(), BrokerIntegrationError> {
    let metadata = file.metadata().map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} descriptor metadata failed: {error}"
        ))
    })?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file()
        || (metadata.uid() != effective_uid && metadata.uid() != 0)
        || metadata.nlink() != 1
        || broker_file_grants_extended_acl_authority(file, label)?
    {
        return Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} must be a trusted, singly linked regular file without an authority-granting ACL"
        )));
    }
    Ok(())
}

fn validate_private_file_descriptor(
    file: &File,
    label: &str,
) -> Result<(), BrokerIntegrationError> {
    validate_private_file_ownership_and_links(file, label)?;
    let metadata = file.metadata().map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} descriptor metadata failed: {error}"
        ))
    })?;
    if metadata.mode() & 0o077 != 0 {
        return Err(BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} must have mode 0600 or stricter"
        )));
    }
    Ok(())
}

fn database_file_identity(
    file: &File,
    label: &str,
) -> Result<DatabaseFileIdentity, BrokerIntegrationError> {
    let metadata = file.metadata().map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} descriptor identity lookup failed: {error}"
        ))
    })?;
    Ok(DatabaseFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn receipt_store_identity_hash(
    identity: DatabaseFileIdentity,
) -> Result<chio_core::Hash, BrokerIntegrationError> {
    #[derive(Serialize)]
    struct StorageIdentity {
        schema: &'static str,
        device: u64,
        inode: u64,
    }

    canonical_json_bytes(&StorageIdentity {
        schema: "chio.receipt-store.storage-identity.v1",
        device: identity.device,
        inode: identity.inode,
    })
    .map(|canonical| chio_core::sha256(&canonical))
    .map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "normal receipt database identity encoding failed: {error}"
        ))
    })
}

fn normalized_path_identity(path: &Path, label: &str) -> Result<PathBuf, BrokerIntegrationError> {
    let file_name = path.file_name().ok_or_else(|| {
        BrokerIntegrationError::InvalidConfiguration(format!("{label} has no file name"))
    })?;
    let parent = path.parent().ok_or_else(|| {
        BrokerIntegrationError::InvalidConfiguration(format!("{label} has no parent directory"))
    })?;
    let canonical_parent = fs::canonicalize(parent).map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} parent canonicalization failed: {error}"
        ))
    })?;
    Ok(canonical_parent.join(file_name))
}

#[cfg(unix)]
fn stable_database_file_identity(
    path: &Path,
    label: &str,
) -> Result<DatabaseFileIdentity, BrokerIntegrationError> {
    RetainedDatabaseFileIdentity::open(path, label).map(|retained| retained.identity)
}

#[cfg(unix)]
fn validate_distinct_database_files(paths: &[(&Path, &str)]) -> Result<(), BrokerIntegrationError> {
    let mut identities = BTreeSet::new();
    for &(path, label) in paths {
        if !identities.insert(stable_database_file_identity(path, label)?) {
            return Err(BrokerIntegrationError::InvalidConfiguration(
                "production broker databases must have distinct descriptor identities".to_string(),
            ));
        }
    }
    Ok(())
}

fn prepare_private_database(path: &Path, label: &str) -> Result<(), BrokerIntegrationError> {
    validate_bounded_absolute_path(path, label)?;
    let parent = open_trusted_parent_directory(path, label)?;
    let file = open_private_file_at(&parent, path, true, true, label)?;
    validate_private_file_ownership_and_links(&file, label)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "{label} permission hardening failed: {error}"
            ))
        })?;
    validate_private_file_descriptor(&file, label)?;
    file.sync_all().map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} durable file sync failed: {error}"
        ))
    })?;
    parent.sync_all().map_err(|error| {
        BrokerIntegrationError::InvalidConfiguration(format!(
            "{label} parent directory sync failed: {error}"
        ))
    })?;
    Ok(())
}

fn read_decoy_registry_master_key(
    mut file: std::fs::File,
) -> Result<[u8; 32], BrokerIntegrationError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(33));
    file.by_ref()
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            BrokerIntegrationError::InvalidConfiguration(format!(
                "decoy registry master key read failed: {error}"
            ))
        })?;
    if bytes.len() != 32 {
        return Err(BrokerIntegrationError::InvalidConfiguration(
            "decoy registry master key must contain exactly 32 bytes".to_string(),
        ));
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(bytes.as_slice());
    Ok(key)
}
