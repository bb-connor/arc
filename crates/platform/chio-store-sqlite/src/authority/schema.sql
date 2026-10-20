CREATE TABLE IF NOT EXISTS authority_state (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                seed_hex TEXT NOT NULL,
                public_key_hex TEXT NOT NULL,
                generation INTEGER NOT NULL,
                rotated_at INTEGER NOT NULL,
                observed_ms INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS authority_trusted_keys (
                public_key_hex TEXT PRIMARY KEY,
                generation INTEGER NOT NULL,
                activated_at INTEGER NOT NULL,
                lifecycle_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS authority_cluster_fence (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                leader_url TEXT,
                election_term INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                authority_generation INTEGER NOT NULL DEFAULT 0,
                authority_rotated_at INTEGER NOT NULL DEFAULT 0
            );


            CREATE TABLE IF NOT EXISTS authority_budget_anchor_commits (
                commit_sequence INTEGER PRIMARY KEY CHECK (commit_sequence > 0),
                previous_chain_digest TEXT NOT NULL,
                chain_digest TEXT NOT NULL UNIQUE,
                anchor_set_digest TEXT NOT NULL,
                leader_url TEXT NOT NULL CHECK (leader_url <> ''),
                election_term INTEGER NOT NULL CHECK (election_term > 0),
                committed_at INTEGER NOT NULL CHECK (committed_at >= 0),
                signer_public_key TEXT NOT NULL CHECK (signer_public_key <> ''),
                signature TEXT NOT NULL CHECK (signature <> '')
            );

            CREATE TRIGGER IF NOT EXISTS authority_budget_anchor_commits_immutable
            BEFORE UPDATE ON authority_budget_anchor_commits
            BEGIN
                SELECT RAISE(ABORT, 'budget anchor commitment is immutable');
            END;

            CREATE TRIGGER IF NOT EXISTS authority_budget_anchor_commits_no_delete
            BEFORE DELETE ON authority_budget_anchor_commits
            BEGIN
                SELECT RAISE(ABORT, 'budget anchor commitment is immutable');
            END;

CREATE TABLE IF NOT EXISTS authority_replication (
            singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
            anchor_json TEXT NOT NULL,
            head_commitment TEXT NOT NULL,
            chain_json TEXT NOT NULL,
            latest_envelope_json TEXT,
            observed_ms INTEGER NOT NULL CHECK (observed_ms >= 0)
        );
        CREATE TRIGGER IF NOT EXISTS authority_replication_anchor_immutable
        BEFORE UPDATE OF anchor_json ON authority_replication
        BEGIN SELECT RAISE(ABORT, 'authority replication anchor is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS authority_replication_no_delete
        BEFORE DELETE ON authority_replication
        BEGIN SELECT RAISE(ABORT, 'authority replication anchor is immutable'); END;
