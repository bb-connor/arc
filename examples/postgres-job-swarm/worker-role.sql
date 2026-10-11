-- Role grants matching the existing PostgreSQL store boundary.
DO $role$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chio_jobs_worker') THEN
                CREATE ROLE chio_jobs_worker LOGIN PASSWORD '__PASSWORD__'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
            ALTER ROLE chio_jobs_worker LOGIN PASSWORD '__PASSWORD__'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
            EXECUTE format(
                'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM chio_jobs_worker',
                current_database()
            );
        END
        $role$;
        GRANT USAGE ON SCHEMA public TO chio_jobs_worker;
        GRANT SELECT ON _sqlx_migrations, chio_finding_market_tenants
            TO chio_jobs_worker;
        GRANT SELECT ON chio_finding_market_jobs TO chio_jobs_worker;
        GRANT EXECUTE ON FUNCTION chio_finding_market_claim_jobs(TEXT, TEXT, BIGINT, BIGINT),
            chio_finding_market_renew_job_lease(TEXT, TEXT, TEXT, BIGINT, BIGINT),
            chio_finding_market_complete_job(TEXT, TEXT, TEXT, BIGINT, TEXT, BYTEA),
            chio_finding_market_fail_job(TEXT, TEXT, TEXT, BIGINT, TEXT, BIGINT),
            chio_finding_market_relinquish_job_lease(TEXT, TEXT, TEXT, BIGINT),
            chio_finding_market_exhaust_job(TEXT, TEXT, TEXT, BIGINT, TEXT)
            TO chio_jobs_worker;
