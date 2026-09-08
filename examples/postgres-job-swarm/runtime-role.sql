-- Role grants matching the existing PostgreSQL store boundary.
DO $role$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chio_jobs_runtime') THEN
                CREATE ROLE chio_jobs_runtime LOGIN PASSWORD '__PASSWORD__'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
            ALTER ROLE chio_jobs_runtime LOGIN PASSWORD '__PASSWORD__'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
            EXECUTE format(
                'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC',
                current_database()
            );
            EXECUTE format(
                'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM chio_jobs_runtime',
                current_database()
            );
        END
        $role$;
        GRANT USAGE ON SCHEMA public TO chio_jobs_runtime;
        GRANT SELECT ON _sqlx_migrations TO chio_jobs_runtime;
        REVOKE ALL ON chio_finding_market_tenants, chio_finding_market_jobs,
            chio_finding_market_principals, chio_finding_market_api_keys,
            chio_finding_market_dpop_nonces, chio_finding_market_dpop_admission_state,
            chio_finding_market_capability_uses,
            chio_finding_market_capability_request_admissions,
            chio_finding_market_security_events, chio_finding_market_aggregate_events,
            chio_finding_market_aggregate_heads,
            chio_finding_market_aggregate_checkpoints,
            chio_finding_market_spend_reservations,
            chio_finding_market_spend_periods,
            chio_finding_market_journal_checkpoints,
            chio_finding_market_journal_checkpoint_members,
            chio_finding_market_archive_manifests,
            chio_finding_market_legal_hold_events,
            chio_finding_market_restore_verifications,
            chio_finding_market_quota_alerts,
            chio_finding_market_gc_receipts,
            chio_finding_market_domain_event_contracts,
            chio_finding_market_domain_projections,
            chio_finding_market_principal_events,
            chio_finding_market_principal_key_overlaps,
            chio_finding_market_authority_state,
            chio_finding_market_replication_events,
            chio_finding_market_principal_replication_events,
            chio_finding_market_replication_checks,
            chio_finding_market_replication_outbox,
            chio_finding_market_principal_replication_outbox,
            chio_finding_market_authority_transitions
            FROM chio_jobs_runtime;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_tenants TO chio_jobs_runtime;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_jobs TO chio_jobs_runtime;
        GRANT SELECT ON chio_finding_market_principals TO chio_jobs_runtime;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_api_keys TO chio_jobs_runtime;
        GRANT SELECT, INSERT, DELETE ON chio_finding_market_dpop_nonces TO chio_jobs_runtime;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_dpop_admission_state TO chio_jobs_runtime;
        GRANT SELECT, INSERT, UPDATE, DELETE ON chio_finding_market_capability_uses TO chio_jobs_runtime;
        GRANT SELECT, INSERT, DELETE ON chio_finding_market_capability_request_admissions TO chio_jobs_runtime;
        GRANT SELECT, INSERT ON chio_finding_market_security_events TO chio_jobs_runtime;
        GRANT SELECT ON chio_finding_market_aggregate_events TO chio_jobs_runtime;
        GRANT SELECT ON chio_finding_market_aggregate_heads TO chio_jobs_runtime;
        GRANT SELECT, INSERT ON chio_finding_market_aggregate_checkpoints TO chio_jobs_runtime;
        GRANT SELECT, INSERT, UPDATE ON chio_finding_market_spend_reservations TO chio_jobs_runtime;
        GRANT SELECT ON chio_finding_market_spend_periods TO chio_jobs_runtime;
        GRANT SELECT ON chio_finding_market_domain_event_contracts,
            chio_finding_market_domain_projections,
            chio_finding_market_principal_events,
            chio_finding_market_principal_key_overlaps,
            chio_finding_market_authority_state
            TO chio_jobs_runtime;
        GRANT EXECUTE ON FUNCTION chio_finding_market_append_domain_event(
            TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, TEXT, TEXT, BYTEA, TEXT, BIGINT
        ) TO chio_jobs_runtime;
        GRANT EXECUTE ON FUNCTION chio_finding_market_apply_principal_event(
            TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, BYTEA, BIGINT
        ) TO chio_jobs_runtime;
        GRANT EXECUTE ON FUNCTION chio_finding_market_claim_jobs(TEXT, TEXT, BIGINT, BIGINT),
            chio_finding_market_renew_job_lease(TEXT, TEXT, TEXT, BIGINT, BIGINT),
            chio_finding_market_complete_job(TEXT, TEXT, TEXT, BIGINT, TEXT, BYTEA),
            chio_finding_market_fail_job(TEXT, TEXT, TEXT, BIGINT, TEXT, BIGINT),
            chio_finding_market_relinquish_job_lease(TEXT, TEXT, TEXT, BIGINT),
            chio_finding_market_exhaust_job(TEXT, TEXT, TEXT, BIGINT, TEXT)
            TO chio_jobs_runtime;
