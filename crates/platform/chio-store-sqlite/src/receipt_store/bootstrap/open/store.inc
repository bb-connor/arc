impl SqliteReceiptStore {
    /// Open a co-located external connection through this store's retained
    /// receipt-database identity. Binding is validated before connection
    /// configuration can mutate the database and again before return.
    pub fn open_bound_colocated_connection(
        &self,
    ) -> Result<SqliteReceiptBoundConnection, ReceiptStoreError> {
        self.database_identity_file.validate()?;
        let mut connection = open_receipt_connection(
            self.database_identity_file.path(),
            existing_database_open_flags(),
            ReceiptConnectionOpenStage::Pool,
        )?;
        self.database_identity_file
            .validate_live_connection(&connection)?;
        configure_sqlite_connection(&mut connection, self.max_page_count)?;
        self.database_identity_file
            .validate_live_connection(&connection)?;
        let state = Arc::new(SqliteReceiptBoundConnectionState::new(
            connection,
            Arc::clone(&self.database_identity_file),
        ));
        self.receipt_commit_actor
            .register_bound_connection(&state)?;
        Ok(SqliteReceiptBoundConnection { state })
    }

    /// Clone the store's descriptor-validating reader pool for a co-located
    /// authority in this crate.
    pub(crate) fn colocated_connection_pool(&self) -> Pool<ReceiptConnectionManager> {
        self.pool.clone()
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError> {
        Self::open_with_pool_config(path, crate::SqlitePoolConfig::default())
    }

    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError> {
        Self::open_existing_with_pool_config(path, crate::SqlitePoolConfig::default())
    }

    pub fn open_existing_strict(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError> {
        Self::open_existing_strict_with_pool_config(path, crate::SqlitePoolConfig::default())
    }

    pub fn open_with_pool_config(
        path: impl AsRef<Path>,
        pool_config: crate::SqlitePoolConfig,
    ) -> Result<Self, ReceiptStoreError> {
        Self::open_with_options(
            path,
            crate::SqliteStoreOptions {
                pool: pool_config,
                ..crate::SqliteStoreOptions::default()
            },
        )
    }

    fn open_existing_with_pool_config(
        path: impl AsRef<Path>,
        pool_config: crate::SqlitePoolConfig,
    ) -> Result<Self, ReceiptStoreError> {
        Self::open_existing_with_options(
            path,
            crate::SqliteStoreOptions {
                pool: pool_config,
                ..crate::SqliteStoreOptions::default()
            },
        )
    }

    fn open_existing_strict_with_pool_config(
        path: impl AsRef<Path>,
        pool_config: crate::SqlitePoolConfig,
    ) -> Result<Self, ReceiptStoreError> {
        Self::open_with_pool_config_and_flags(
            path,
            crate::SqliteStoreOptions {
                pool: pool_config,
                ..crate::SqliteStoreOptions::default()
            },
            false,
            false,
        )
    }

    pub fn open_with_options(
        path: impl AsRef<Path>,
        options: crate::SqliteStoreOptions,
    ) -> Result<Self, ReceiptStoreError> {
        Self::open_with_pool_config_and_flags(path, options, true, false)
    }

    pub fn open_existing_with_options(
        path: impl AsRef<Path>,
        options: crate::SqliteStoreOptions,
    ) -> Result<Self, ReceiptStoreError> {
        Self::open_with_pool_config_and_flags(path, options, false, true)
    }

    fn open_with_pool_config_and_flags(
        path: impl AsRef<Path>,
        options: crate::SqliteStoreOptions,
        create_if_missing: bool,
        repair_existing: bool,
    ) -> Result<Self, ReceiptStoreError> {
        let requested_path = path.as_ref();
        let initial_connection_flags = if create_if_missing {
            create_database_open_flags()
        } else {
            existing_database_open_flags()
        };

        let database_identity_file = Arc::new(ReceiptDatabaseIdentityFile::open(
            requested_path,
            create_if_missing,
        )?);
        let database_identity = database_identity_file.identity();
        let path = database_identity_file.path().to_path_buf();

        let mut connection = open_receipt_connection(
            &path,
            initial_connection_flags,
            ReceiptConnectionOpenStage::Initial,
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::CannotOpen) {
                ReceiptStoreError::NotFound(format!(
                    "receipt database {} does not exist",
                    path.display()
                ))
            } else {
                ReceiptStoreError::Sqlite(error)
            }
        })?;
        database_identity_file.validate_live_connection(&connection)?;
        if !create_if_missing {
            require_existing_receipt_schema(&path, &connection)?;
            let on_disk_version = crate::check_schema_version(
                &connection,
                RECEIPT_STORE_SCHEMA_KEY,
                RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION,
                RECEIPT_STORE_LEGACY_ANCHOR_TABLES,
            )
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
            configure_sqlite_connection(&mut connection, options.pool.max_page_count)?;
            database_identity_file.validate_live_connection(&connection)?;
            if on_disk_version < RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION {
                upgrade_receipt_store_schema(&mut connection, on_disk_version)?;
            }
            validate_settlement_observer_outbox_schema(&connection, false)?;
            if repair_existing {
                ensure_indexed_security_evidence_schema(&mut connection)?;
                crate::aggregate_family_root::ensure_aggregate_family_root_schema(&mut connection)?;
                crate::capability_lineage::ensure_causal_lineage_schema(&mut connection)?;
                ensure_capability_lineage_provenance_columns(&connection)?;
                super::support::ensure_receipt_retention_watermark_table(&connection)?;
                super::support::ensure_receipt_retention_tombstones(&connection)?;
                super::support::ensure_transparency_projection_guards(&connection)?;
            } else {
                validate_indexed_security_evidence_schema(&connection)?;
                crate::aggregate_family_root::validate_existing_aggregate_family_root_schema(
                    &connection,
                )?;
                super::support::validate_receipt_retention_watermark_schema(&connection)?;
                super::support::validate_receipt_retention_tombstones_schema(&connection)?;
            }
            super::support::ensure_transparency_projection_guards(&connection)?;
            database_identity_file.validate_live_connection(&connection)?;
            drop(connection);

            let reader_pool = build_receipt_pool(
                &path,
                options.pool.reader_pool_max_size,
                "reader",
                Arc::clone(&database_identity_file),
                options.pool.max_page_count,
            )?;
            let writer_pool = build_receipt_pool(
                &path,
                options.pool.writer_pool_max_size,
                "writer",
                Arc::clone(&database_identity_file),
                options.pool.max_page_count,
            )?;
            database_identity_file.validate_path_binding(&path)?;

            let instance_token = fresh_instance_token();
            let writer_lifetime_lock = acquire_writer_lifetime_lock(&path, &instance_token)?;
            return Ok(Self {
                receipt_commit_actor: ReceiptCommitActor::start(
                    writer_pool,
                    options.incremental_verification,
                    Arc::clone(&database_identity_file),
                ),
                pool: reader_pool,
                database_identity,
                database_identity_file,
                max_page_count: options.pool.max_page_count,
                strict_tenant_isolation: std::sync::atomic::AtomicBool::new(true),
                incremental_verification: options.incremental_verification,
                writer_lifetime_lock,
                instance_token,
            });
        }

        // Validate provenance before configuring pragmas: an existing file that
        // is a foreign database must be refused before any write touches its
        // header, so a mistargeted path is never mutated into WAL mode. The
        // schema-version check adopts an unstamped database on a legacy anchor
        // name alone, so first reject one whose generic anchor lacks the receipt
        // shape, keeping a foreign file that merely reuses the name out.
        reject_foreign_legacy_receipt_anchor(&connection)?;
        let on_disk_version = crate::check_schema_version(
            &connection,
            RECEIPT_STORE_SCHEMA_KEY,
            RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION,
            RECEIPT_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        configure_sqlite_connection(&mut connection, options.pool.max_page_count)?;
        database_identity_file.validate_live_connection(&connection)?;
        if on_disk_version == 2 {
            upgrade_receipt_store_schema(&mut connection, on_disk_version)?;
        }
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS chio_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                grant_index INTEGER,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_timestamp
                ON chio_tool_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_capability
                ON chio_tool_receipts(capability_id);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_subject
                ON chio_tool_receipts(subject_key);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_grant
                ON chio_tool_receipts(capability_id, grant_index);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_tool
                ON chio_tool_receipts(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_decision
                ON chio_tool_receipts(decision_kind);

            CREATE TABLE IF NOT EXISTS chio_security_evidence_index (
                evidence_id TEXT NOT NULL PRIMARY KEY,
                receipt_id TEXT NOT NULL UNIQUE
                    REFERENCES chio_tool_receipts(receipt_id) ON DELETE RESTRICT
            );

            CREATE TRIGGER IF NOT EXISTS chio_security_evidence_index_reject_update
            BEFORE UPDATE ON chio_security_evidence_index
            BEGIN
                SELECT RAISE(ABORT, 'security evidence index entries are immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS chio_security_evidence_index_reject_delete
            BEFORE DELETE ON chio_security_evidence_index
            BEGIN
                SELECT RAISE(ABORT, 'security evidence index entries are immutable');
            END;

            CREATE TABLE IF NOT EXISTS chio_authorization_receipt_consumptions (
                authorization_receipt_id TEXT PRIMARY KEY REFERENCES chio_tool_receipts(receipt_id) ON DELETE RESTRICT,
                consumer_receipt_id TEXT NOT NULL UNIQUE,
                request_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                tool_call_id TEXT NOT NULL,
                -- tenant_id may be NULL for non-enterprise / single-tenant
                -- deployments where the authorization receipt itself carries
                -- `tenant_id: None`. The consumption record mirrors the
                -- receipt's tenant scope verbatim.
                tenant_id TEXT,
                parameter_hash TEXT NOT NULL,
                consumed_at_unix_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chio_authorization_consumptions_consumer
                ON chio_authorization_receipt_consumptions(consumer_receipt_id);
            CREATE INDEX IF NOT EXISTS idx_chio_authorization_consumptions_scope
                ON chio_authorization_receipt_consumptions(session_id, tool_call_id, request_id);

            CREATE TABLE IF NOT EXISTS settlement_reconciliations (
                receipt_id TEXT PRIMARY KEY REFERENCES chio_tool_receipts(receipt_id) ON DELETE CASCADE,
                reconciliation_state TEXT NOT NULL,
                note TEXT,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_settlement_reconciliations_updated_at
                ON settlement_reconciliations(updated_at);

            CREATE TABLE IF NOT EXISTS metered_billing_reconciliations (
                receipt_id TEXT PRIMARY KEY REFERENCES chio_tool_receipts(receipt_id) ON DELETE CASCADE,
                adapter_kind TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                observed_units INTEGER NOT NULL,
                billed_cost_units INTEGER NOT NULL,
                billed_cost_currency TEXT NOT NULL,
                evidence_sha256 TEXT,
                recorded_at INTEGER NOT NULL,
                reconciliation_state TEXT NOT NULL,
                note TEXT,
                updated_at INTEGER NOT NULL,
                UNIQUE (adapter_kind, evidence_id)
            );
            CREATE INDEX IF NOT EXISTS idx_metered_billing_reconciliations_updated_at
                ON metered_billing_reconciliations(updated_at);

            CREATE TABLE IF NOT EXISTS underwriting_decisions (
                decision_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                outcome TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                review_state TEXT NOT NULL,
                risk_class TEXT NOT NULL,
                supersedes_decision_id TEXT REFERENCES underwriting_decisions(decision_id),
                superseded_by_decision_id TEXT REFERENCES underwriting_decisions(decision_id),
                premium_units INTEGER,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_issued_at
                ON underwriting_decisions(issued_at);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_capability
                ON underwriting_decisions(capability_id);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_subject
                ON underwriting_decisions(subject_key);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_tool
                ON underwriting_decisions(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_outcome
                ON underwriting_decisions(outcome);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_lifecycle
                ON underwriting_decisions(lifecycle_state);

            CREATE TABLE IF NOT EXISTS underwriting_appeals (
                appeal_id TEXT PRIMARY KEY,
                decision_id TEXT NOT NULL REFERENCES underwriting_decisions(decision_id) ON DELETE CASCADE,
                requested_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                note TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                resolved_by TEXT,
                replacement_decision_id TEXT REFERENCES underwriting_decisions(decision_id)
            );
            CREATE INDEX IF NOT EXISTS idx_underwriting_appeals_decision
                ON underwriting_appeals(decision_id);
            CREATE INDEX IF NOT EXISTS idx_underwriting_appeals_status
                ON underwriting_appeals(status);
            CREATE INDEX IF NOT EXISTS idx_underwriting_appeals_updated_at
                ON underwriting_appeals(updated_at);

            CREATE TABLE IF NOT EXISTS credit_facilities (
                facility_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                disposition TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                supersedes_facility_id TEXT REFERENCES credit_facilities(facility_id),
                superseded_by_facility_id TEXT REFERENCES credit_facilities(facility_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_issued_at
                ON credit_facilities(issued_at);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_expires_at
                ON credit_facilities(expires_at);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_capability
                ON credit_facilities(capability_id);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_subject
                ON credit_facilities(subject_key);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_tool
                ON credit_facilities(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_disposition
                ON credit_facilities(disposition);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_lifecycle
                ON credit_facilities(lifecycle_state);

            CREATE TABLE IF NOT EXISTS credit_bonds (
                bond_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                facility_id TEXT,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                disposition TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                supersedes_bond_id TEXT REFERENCES credit_bonds(bond_id),
                superseded_by_bond_id TEXT REFERENCES credit_bonds(bond_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_issued_at
                ON credit_bonds(issued_at);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_expires_at
                ON credit_bonds(expires_at);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_facility
                ON credit_bonds(facility_id);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_capability
                ON credit_bonds(capability_id);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_subject
                ON credit_bonds(subject_key);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_tool
                ON credit_bonds(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_disposition
                ON credit_bonds(disposition);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_lifecycle
                ON credit_bonds(lifecycle_state);

            CREATE TABLE IF NOT EXISTS liability_providers (
                provider_record_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                supersedes_provider_record_id TEXT REFERENCES liability_providers(provider_record_id),
                superseded_by_provider_record_id TEXT REFERENCES liability_providers(provider_record_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_providers_issued_at
                ON liability_providers(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_providers_provider_id
                ON liability_providers(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_providers_lifecycle
                ON liability_providers(lifecycle_state);

            CREATE TABLE IF NOT EXISTS liability_quote_requests (
                quote_request_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                jurisdiction TEXT NOT NULL,
                coverage_class TEXT NOT NULL,
                currency TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_quote_requests_issued_at
                ON liability_quote_requests(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_requests_provider
                ON liability_quote_requests(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_requests_subject
                ON liability_quote_requests(subject_key);

            CREATE TABLE IF NOT EXISTS liability_quote_responses (
                quote_response_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                provider_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                expires_at INTEGER,
                supersedes_quote_response_id TEXT REFERENCES liability_quote_responses(quote_response_id),
                superseded_by_quote_response_id TEXT REFERENCES liability_quote_responses(quote_response_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_quote_responses_issued_at
                ON liability_quote_responses(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_responses_request
                ON liability_quote_responses(quote_request_id);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_responses_provider
                ON liability_quote_responses(provider_id);

            CREATE TABLE IF NOT EXISTS liability_pricing_authorities (
                authority_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                provider_id TEXT NOT NULL,
                facility_id TEXT NOT NULL,
                underwriting_decision_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_pricing_authorities_request
                ON liability_pricing_authorities(quote_request_id);
            CREATE INDEX IF NOT EXISTS idx_liability_pricing_authorities_provider
                ON liability_pricing_authorities(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_pricing_authorities_facility
                ON liability_pricing_authorities(facility_id);

            CREATE TABLE IF NOT EXISTS liability_placements (
                placement_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                quote_response_id TEXT NOT NULL REFERENCES liability_quote_responses(quote_response_id),
                provider_id TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_placements_request
                ON liability_placements(quote_request_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_placements_response
                ON liability_placements(quote_response_id);
            CREATE INDEX IF NOT EXISTS idx_liability_placements_provider
                ON liability_placements(provider_id);

            CREATE TABLE IF NOT EXISTS liability_bound_coverages (
                bound_coverage_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                quote_response_id TEXT NOT NULL REFERENCES liability_quote_responses(quote_response_id),
                placement_id TEXT NOT NULL REFERENCES liability_placements(placement_id),
                provider_id TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_bound_coverages_request
                ON liability_bound_coverages(quote_request_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_bound_coverages_response
                ON liability_bound_coverages(quote_response_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_bound_coverages_placement
                ON liability_bound_coverages(placement_id);
            CREATE INDEX IF NOT EXISTS idx_liability_bound_coverages_provider
                ON liability_bound_coverages(provider_id);

            CREATE TABLE IF NOT EXISTS liability_auto_bind_decisions (
                decision_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                quote_response_id TEXT NOT NULL REFERENCES liability_quote_responses(quote_response_id),
                authority_id TEXT NOT NULL REFERENCES liability_pricing_authorities(authority_id),
                provider_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_auto_bind_decisions_response
                ON liability_auto_bind_decisions(quote_response_id);
            CREATE INDEX IF NOT EXISTS idx_liability_auto_bind_decisions_request
                ON liability_auto_bind_decisions(quote_request_id);
            CREATE INDEX IF NOT EXISTS idx_liability_auto_bind_decisions_authority
                ON liability_auto_bind_decisions(authority_id);

            CREATE TABLE IF NOT EXISTS liability_claim_packages (
                claim_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                policy_number TEXT NOT NULL,
                jurisdiction TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                claim_event_at INTEGER NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_issued_at
                ON liability_claim_packages(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_provider
                ON liability_claim_packages(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_policy_number
                ON liability_claim_packages(policy_number);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_subject
                ON liability_claim_packages(subject_key);

            CREATE TABLE IF NOT EXISTS liability_claim_responses (
                claim_response_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                provider_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_responses_issued_at
                ON liability_claim_responses(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_responses_provider
                ON liability_claim_responses(provider_id);

            CREATE TABLE IF NOT EXISTS liability_claim_disputes (
                dispute_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                claim_response_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_responses(claim_response_id),
                provider_id TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_disputes_issued_at
                ON liability_claim_disputes(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_disputes_provider
                ON liability_claim_disputes(provider_id);

            CREATE TABLE IF NOT EXISTS liability_claim_adjudications (
                adjudication_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                dispute_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_disputes(dispute_id),
                outcome TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_adjudications_issued_at
                ON liability_claim_adjudications(issued_at);

            CREATE TABLE IF NOT EXISTS liability_claim_payout_instructions (
                payout_instruction_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                adjudication_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_adjudications(adjudication_id),
                payout_amount_units INTEGER NOT NULL,
                payout_amount_currency TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_payout_instructions_issued_at
                ON liability_claim_payout_instructions(issued_at);

            CREATE TABLE IF NOT EXISTS liability_claim_payout_receipts (
                payout_receipt_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                payout_instruction_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_payout_instructions(payout_instruction_id),
                reconciliation_state TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_payout_receipts_issued_at
                ON liability_claim_payout_receipts(issued_at);

            CREATE TABLE IF NOT EXISTS liability_claim_settlement_instructions (
                settlement_instruction_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                payout_receipt_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_payout_receipts(payout_receipt_id),
                settlement_kind TEXT NOT NULL,
                payer_role TEXT NOT NULL,
                payer_id TEXT NOT NULL,
                payee_role TEXT NOT NULL,
                payee_id TEXT NOT NULL,
                settlement_amount_units INTEGER NOT NULL,
                settlement_amount_currency TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_settlement_instructions_issued_at
                ON liability_claim_settlement_instructions(issued_at);

            CREATE TABLE IF NOT EXISTS liability_claim_settlement_receipts (
                settlement_receipt_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                settlement_instruction_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_settlement_instructions(settlement_instruction_id),
                reconciliation_state TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_settlement_receipts_issued_at
                ON liability_claim_settlement_receipts(issued_at);

            CREATE TABLE IF NOT EXISTS credit_loss_lifecycle (
                event_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                bond_id TEXT NOT NULL REFERENCES credit_bonds(bond_id),
                facility_id TEXT,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                event_kind TEXT NOT NULL,
                projected_bond_lifecycle_state TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_issued_at
                ON credit_loss_lifecycle(issued_at);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_bond
                ON credit_loss_lifecycle(bond_id);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_facility
                ON credit_loss_lifecycle(facility_id);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_capability
                ON credit_loss_lifecycle(capability_id);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_subject
                ON credit_loss_lifecycle(subject_key);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_tool
                ON credit_loss_lifecycle(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_kind
                ON credit_loss_lifecycle(event_kind);

            CREATE TABLE IF NOT EXISTS chio_child_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                parent_request_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                operation_kind TEXT NOT NULL,
                terminal_state TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                outcome_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chio_child_receipts_timestamp
                ON chio_child_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_chio_child_receipts_session
                ON chio_child_receipts(session_id);
            CREATE INDEX IF NOT EXISTS idx_chio_child_receipts_parent
                ON chio_child_receipts(parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_chio_child_receipts_request
                ON chio_child_receipts(request_id);

            CREATE TABLE IF NOT EXISTS claim_receipt_log_entries (
                entry_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                receipt_kind TEXT NOT NULL,
                source_seq INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                capability_id TEXT,
                session_id TEXT,
                parent_request_id TEXT,
                request_id TEXT,
                subject_key TEXT,
                issuer_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                raw_json TEXT NOT NULL,
                CHECK (entry_seq > 0),
                CHECK (source_seq > 0),
                CHECK (receipt_kind IN ('tool_receipt', 'child_receipt')),
                CHECK (
                    (receipt_kind = 'tool_receipt'
                        AND capability_id IS NOT NULL
                        AND session_id IS NULL
                        AND parent_request_id IS NULL
                        AND request_id IS NULL
                        AND tool_server IS NOT NULL
                        AND tool_name IS NOT NULL)
                    OR
                    (receipt_kind = 'child_receipt'
                        AND capability_id IS NULL
                        AND session_id IS NOT NULL
                        AND parent_request_id IS NOT NULL
                        AND request_id IS NOT NULL
                        AND tool_server IS NULL
                        AND tool_name IS NULL)
                )
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_claim_receipt_log_kind_source
                ON claim_receipt_log_entries(receipt_kind, source_seq);
            CREATE INDEX IF NOT EXISTS idx_claim_receipt_log_timestamp
                ON claim_receipt_log_entries(timestamp, entry_seq);
            CREATE INDEX IF NOT EXISTS idx_claim_receipt_log_tool
                ON claim_receipt_log_entries(tool_server, tool_name, timestamp)
                WHERE receipt_kind = 'tool_receipt';
            CREATE INDEX IF NOT EXISTS idx_claim_receipt_log_child_request
                ON claim_receipt_log_entries(session_id, request_id, timestamp)
                WHERE receipt_kind = 'child_receipt';

            DROP TRIGGER IF EXISTS chio_tool_receipts_project_claim_log_entry;
            CREATE TRIGGER chio_tool_receipts_project_claim_log_entry
            AFTER INSERT ON chio_tool_receipts
            BEGIN
                INSERT INTO claim_receipt_log_entries (
                    receipt_id,
                    receipt_kind,
                    source_seq,
                    timestamp,
                    capability_id,
                    session_id,
                    parent_request_id,
                    request_id,
                    subject_key,
                    issuer_key,
                    tool_server,
                    tool_name,
                    raw_json
                ) VALUES (
                    NEW.receipt_id,
                    'tool_receipt',
                    NEW.seq,
                    NEW.timestamp,
                    NEW.capability_id,
                    NULL,
                    NULL,
                    NULL,
                    NEW.subject_key,
                    NEW.issuer_key,
                    NEW.tool_server,
                    NEW.tool_name,
                    NEW.raw_json
                );
            END;

            DROP TRIGGER IF EXISTS chio_child_receipts_project_claim_log_entry;
            CREATE TRIGGER chio_child_receipts_project_claim_log_entry
            AFTER INSERT ON chio_child_receipts
            BEGIN
                INSERT INTO claim_receipt_log_entries (
                    receipt_id,
                    receipt_kind,
                    source_seq,
                    timestamp,
                    capability_id,
                    session_id,
                    parent_request_id,
                    request_id,
                    subject_key,
                    issuer_key,
                    tool_server,
                    tool_name,
                    raw_json
                ) VALUES (
                    NEW.receipt_id,
                    'child_receipt',
                    NEW.seq,
                    NEW.timestamp,
                    NULL,
                    NEW.session_id,
                    NEW.parent_request_id,
                    NEW.request_id,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NEW.raw_json
                );
            END;

            CREATE TABLE IF NOT EXISTS session_anchors (
                anchor_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                auth_context_fingerprint TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                supersedes_anchor_id TEXT REFERENCES session_anchors(anchor_id),
                is_current INTEGER NOT NULL DEFAULT 1,
                source_kind TEXT NOT NULL,
                json_sha256 TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_session_anchors_session
                ON session_anchors(session_id, issued_at DESC);
            CREATE INDEX IF NOT EXISTS idx_session_anchors_supersedes
                ON session_anchors(supersedes_anchor_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_session_anchors_current
                ON session_anchors(session_id)
                WHERE is_current = 1;

            CREATE TABLE IF NOT EXISTS request_lineage (
                session_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                parent_request_id TEXT,
                session_anchor_id TEXT REFERENCES session_anchors(anchor_id),
                recorded_at INTEGER NOT NULL,
                request_fingerprint TEXT,
                source_kind TEXT NOT NULL,
                json_sha256 TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (session_id, request_id)
            );
            CREATE INDEX IF NOT EXISTS idx_request_lineage_parent
                ON request_lineage(session_id, parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_request_lineage_anchor
                ON request_lineage(session_anchor_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_request_lineage_fingerprint
                ON request_lineage(session_id, COALESCE(session_anchor_id, ''), request_fingerprint)
                WHERE request_fingerprint IS NOT NULL;

            CREATE TABLE IF NOT EXISTS receipt_lineage_statements (
                receipt_id TEXT PRIMARY KEY,
                statement_id TEXT,
                request_id TEXT,
                session_id TEXT,
                session_anchor_id TEXT REFERENCES session_anchors(anchor_id),
                chain_id TEXT,
                parent_request_id TEXT,
                parent_receipt_id TEXT,
                evidence_class TEXT,
                evidence_sources_json TEXT,
                verified_session_anchor INTEGER NOT NULL DEFAULT 0,
                verified_parent_request INTEGER NOT NULL DEFAULT 0,
                verified_parent_receipt INTEGER NOT NULL DEFAULT 0,
                replay_protected INTEGER NOT NULL DEFAULT 0,
                recorded_at INTEGER NOT NULL,
                source_kind TEXT NOT NULL,
                json_sha256 TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_request
                ON receipt_lineage_statements(session_id, request_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_receipt_lineage_statement_id
                ON receipt_lineage_statements(statement_id)
                WHERE statement_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_parent_request
                ON receipt_lineage_statements(session_id, parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_parent_receipt
                ON receipt_lineage_statements(parent_receipt_id);
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_anchor
                ON receipt_lineage_statements(session_anchor_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_receipt_lineage_request_anchor
                ON receipt_lineage_statements(session_id, COALESCE(session_anchor_id, ''), request_id)
                WHERE session_id IS NOT NULL
                  AND request_id IS NOT NULL;

            CREATE TABLE IF NOT EXISTS kernel_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_seq INTEGER NOT NULL UNIQUE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                kernel_key TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kernel_checkpoints_batch_end
                ON kernel_checkpoints(batch_end_seq);

            CREATE TABLE IF NOT EXISTS checkpoint_tree_heads (
                checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES kernel_checkpoints(checkpoint_seq) ON DELETE CASCADE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                kernel_key TEXT NOT NULL,
                previous_checkpoint_sha256 TEXT,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_tree_heads_tree_size
                ON checkpoint_tree_heads(tree_size);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_tree_heads_previous
                ON checkpoint_tree_heads(previous_checkpoint_sha256);

            CREATE TABLE IF NOT EXISTS checkpoint_predecessor_witnesses (
                predecessor_checkpoint_seq INTEGER NOT NULL
                    REFERENCES checkpoint_tree_heads(checkpoint_seq) ON DELETE CASCADE,
                witness_checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES checkpoint_tree_heads(checkpoint_seq) ON DELETE CASCADE,
                previous_checkpoint_sha256 TEXT NOT NULL,
                witnessed_at INTEGER NOT NULL,
                witness_statement_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_predecessor_witnesses_predecessor
                ON checkpoint_predecessor_witnesses(predecessor_checkpoint_seq);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_predecessor_witnesses_previous
                ON checkpoint_predecessor_witnesses(previous_checkpoint_sha256);

            CREATE TABLE IF NOT EXISTS checkpoint_publication_metadata (
                checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES kernel_checkpoints(checkpoint_seq) ON DELETE CASCADE,
                publication_schema TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                published_at INTEGER NOT NULL,
                kernel_key TEXT NOT NULL,
                log_tree_size INTEGER NOT NULL,
                entry_start_seq INTEGER NOT NULL,
                entry_end_seq INTEGER NOT NULL,
                previous_checkpoint_sha256 TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_publication_metadata_published_at
                ON checkpoint_publication_metadata(published_at);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_publication_metadata_log_tree_size
                ON checkpoint_publication_metadata(log_tree_size);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_publication_metadata_previous
                ON checkpoint_publication_metadata(previous_checkpoint_sha256);

            CREATE TABLE IF NOT EXISTS checkpoint_publication_trust_anchor_bindings (
                checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES kernel_checkpoints(checkpoint_seq) ON DELETE CASCADE,
                binding_json TEXT NOT NULL
            );

            DROP TRIGGER IF EXISTS kernel_checkpoints_project_tree_head;
            CREATE TRIGGER kernel_checkpoints_project_tree_head
            AFTER INSERT ON kernel_checkpoints
            BEGIN
                INSERT INTO checkpoint_tree_heads (
                    checkpoint_seq,
                    batch_start_seq,
                    batch_end_seq,
                    tree_size,
                    merkle_root,
                    issued_at,
                    kernel_key,
                    previous_checkpoint_sha256,
                    statement_json,
                    signature
                ) VALUES (
                    NEW.checkpoint_seq,
                    NEW.batch_start_seq,
                    NEW.batch_end_seq,
                    NEW.tree_size,
                    NEW.merkle_root,
                    NEW.issued_at,
                    NEW.kernel_key,
                    CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT),
                    NEW.statement_json,
                    NEW.signature
                );

                INSERT INTO checkpoint_predecessor_witnesses (
                    predecessor_checkpoint_seq,
                    witness_checkpoint_seq,
                    previous_checkpoint_sha256,
                    witnessed_at,
                    witness_statement_json
                )
                SELECT
                    NEW.checkpoint_seq - 1,
                    NEW.checkpoint_seq,
                    CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT),
                    NEW.issued_at,
                    NEW.statement_json
                WHERE json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') IS NOT NULL;

                INSERT INTO checkpoint_publication_metadata (
                    checkpoint_seq,
                    publication_schema,
                    merkle_root,
                    published_at,
                    kernel_key,
                    log_tree_size,
                    entry_start_seq,
                    entry_end_seq,
                    previous_checkpoint_sha256
                ) VALUES (
                    NEW.checkpoint_seq,
                    'chio.checkpoint_publication.v1',
                    NEW.merkle_root,
                    NEW.issued_at,
                    NEW.kernel_key,
                    NEW.batch_end_seq,
                    NEW.batch_start_seq,
                    NEW.batch_end_seq,
                    CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT)
                );
            END;

            CREATE TABLE IF NOT EXISTS capability_lineage (
                capability_id        TEXT PRIMARY KEY,
                subject_key          TEXT NOT NULL,
                issuer_key           TEXT NOT NULL,
                issued_at            INTEGER NOT NULL,
                expires_at           INTEGER NOT NULL,
                grants_json          TEXT NOT NULL,
                delegation_depth     INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT REFERENCES capability_lineage(capability_id),
                federated_parent_capability_id TEXT,
                provenance TEXT NOT NULL DEFAULT 'legacy_projection'
                    CHECK (provenance IN ('signed_token', 'synthetic_anchor', 'legacy_projection')),
                signed_capability_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_subject
                ON capability_lineage(subject_key);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_issuer
                ON capability_lineage(issuer_key);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_issued_at
                ON capability_lineage(issued_at);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_parent
                ON capability_lineage(parent_capability_id);

            CREATE TABLE IF NOT EXISTS federated_lineage_bridges (
                local_capability_id TEXT PRIMARY KEY REFERENCES capability_lineage(capability_id) ON DELETE CASCADE,
                parent_capability_id TEXT NOT NULL,
                share_id TEXT REFERENCES federated_evidence_shares(share_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_lineage_bridges_parent
                ON federated_lineage_bridges(parent_capability_id);

            CREATE TABLE IF NOT EXISTS federated_evidence_shares (
                share_id TEXT PRIMARY KEY,
                manifest_hash TEXT NOT NULL,
                imported_at INTEGER NOT NULL,
                exported_at INTEGER NOT NULL,
                issuer TEXT NOT NULL,
                partner TEXT NOT NULL,
                signer_public_key TEXT NOT NULL,
                require_proofs INTEGER NOT NULL DEFAULT 0,
                query_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_federated_evidence_shares_imported_at
                ON federated_evidence_shares(imported_at);

            CREATE TABLE IF NOT EXISTS federated_share_tool_receipts (
                share_id TEXT NOT NULL REFERENCES federated_evidence_shares(share_id) ON DELETE CASCADE,
                seq INTEGER NOT NULL,
                receipt_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (share_id, seq),
                UNIQUE (share_id, receipt_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_share_receipts_capability
                ON federated_share_tool_receipts(capability_id);
            CREATE INDEX IF NOT EXISTS idx_federated_share_receipts_subject
                ON federated_share_tool_receipts(subject_key);

            CREATE TABLE IF NOT EXISTS federated_share_capability_lineage (
                share_id TEXT NOT NULL REFERENCES federated_evidence_shares(share_id) ON DELETE CASCADE,
                capability_id TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                issuer_key TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                grants_json TEXT NOT NULL,
                delegation_depth INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT,
                federated_parent_capability_id TEXT,
                provenance TEXT NOT NULL DEFAULT 'legacy_projection'
                    CHECK (provenance IN ('signed_token', 'synthetic_anchor', 'legacy_projection')),
                signed_capability_json TEXT,
                PRIMARY KEY (share_id, capability_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_share_lineage_capability
                ON federated_share_capability_lineage(capability_id);
            CREATE INDEX IF NOT EXISTS idx_federated_share_lineage_subject
                ON federated_share_capability_lineage(subject_key);

            CREATE TABLE IF NOT EXISTS receipt_retention_watermark (
                archived_through_entry_seq INTEGER NOT NULL,
                archived_through_timestamp INTEGER NOT NULL,
                archive_path               TEXT NOT NULL,
                archive_sha256             TEXT NOT NULL,
                archive_content_sha256     TEXT NOT NULL,
                rotated_at                 INTEGER NOT NULL,
                CHECK (archived_through_entry_seq >= 0),
                CHECK (length(archive_sha256) = 64 AND archive_sha256 NOT GLOB '*[^0-9a-f]*'),
                CHECK (length(archive_content_sha256) = 64 AND archive_content_sha256 NOT GLOB '*[^0-9a-f]*')
            );

            "#,
        )?;
        connection.execute_batch(DISPATCH_INTENT_JOURNAL_DDL)?;
        connection.execute_batch(SETTLEMENT_OBSERVER_OUTBOX_DDL)?;
        validate_settlement_observer_outbox_schema(&connection, false)?;
        connection.execute_batch(crate::IOU_ENVELOPE_MIGRATION)?;
        crate::aggregate_family_root::ensure_aggregate_family_root_schema(&mut connection)?;
        crate::capability_lineage::ensure_causal_lineage_schema(&mut connection)?;
        ensure_capability_lineage_provenance_columns(&connection)?;
        ensure_tool_receipt_attribution_columns(&connection)?;
        super::support::ensure_receipt_lineage_statement_columns(&connection)?;
        super::support::drop_transparency_projection_guards(&connection)?;
        let backfill_result = (|| -> Result<(), ReceiptStoreError> {
            super::support::ensure_receipt_retention_watermark_table(&connection)?;
            super::support::ensure_receipt_retention_tombstones(&connection)?;
            backfill_tool_receipt_attribution_columns(&connection)?;
            super::support::backfill_provenance_lineage_tables(&mut connection)?;
            super::support::backfill_claim_receipt_log_entries(&mut connection)?;
            super::support::backfill_checkpoint_transparency_projections(&mut connection)?;
            Ok(())
        })();
        let guard_result = super::support::ensure_transparency_projection_guards(&connection);
        match (backfill_result, guard_result) {
            (Ok(()), Ok(())) => {}
            (Err(error), Ok(())) => return Err(error),
            (Ok(()), Err(error)) => return Err(error),
            (Err(backfill_error), Err(guard_error)) => {
                return Err(ReceiptStoreError::Canonical(format!(
                    "receipt projection backfill failed ({backfill_error}); restoring immutability guards also failed ({guard_error})"
                )));
            }
        }

        crate::stamp_schema_version(
            &connection,
            RECEIPT_STORE_SCHEMA_KEY,
            RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;

        database_identity_file.validate_live_connection(&connection)?;
        drop(connection);

        let reader_pool = build_receipt_pool(
            &path,
            options.pool.reader_pool_max_size,
            "reader",
            Arc::clone(&database_identity_file),
            options.pool.max_page_count,
        )?;
        let writer_pool = build_receipt_pool(
            &path,
            options.pool.writer_pool_max_size,
            "writer",
            Arc::clone(&database_identity_file),
            options.pool.max_page_count,
        )?;
        database_identity_file.validate_path_binding(&path)?;

        let instance_token = fresh_instance_token();
        let writer_lifetime_lock = acquire_writer_lifetime_lock(&path, &instance_token)?;
        Ok(Self {
            receipt_commit_actor: ReceiptCommitActor::start(
                writer_pool,
                options.incremental_verification,
                Arc::clone(&database_identity_file),
            ),
            pool: reader_pool,
            database_identity,
            database_identity_file,
            max_page_count: options.pool.max_page_count,
            strict_tenant_isolation: std::sync::atomic::AtomicBool::new(true),
            incremental_verification: options.incremental_verification,
            writer_lifetime_lock,
            instance_token,
        })
    }

    pub fn open_with_pool_sizes(
        path: impl AsRef<Path>,
        reader_pool_max_size: u32,
        writer_pool_max_size: u32,
    ) -> Result<Self, ReceiptStoreError> {
        Self::open_with_pool_config(
            path,
            crate::SqlitePoolConfig {
                reader_pool_max_size,
                writer_pool_max_size,
                max_page_count: None,
            },
        )
    }
}
