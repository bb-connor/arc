-- Role grants matching the existing PostgreSQL store boundary.
DO $role$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chio_jobs_migrator') THEN
                CREATE ROLE chio_jobs_migrator LOGIN PASSWORD '__PASSWORD__'
                    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
            ALTER ROLE chio_jobs_migrator LOGIN PASSWORD '__PASSWORD__'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS;
            EXECUTE format(
                'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM chio_jobs_migrator',
                current_database()
            );
        END
        $role$;
        GRANT USAGE, CREATE ON SCHEMA public TO chio_jobs_migrator;
