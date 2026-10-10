-- Exact predecessor catalog from de84fc306efbb4c8dd6de748d0ad2a8d695fd30e.
-- Source SHA-256: e99b7cfa8cad2b2f04e77992a4a47274faffcd780f3a12c27d254062cf88c5a4

CREATE TABLE IF NOT EXISTS authority_global_commit_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    head_sequence INTEGER NOT NULL CHECK (head_sequence >= 0),
    head_chain_digest TEXT NOT NULL CHECK (
        length(head_chain_digest) = 64
        AND head_chain_digest NOT GLOB '*[^0-9a-f]*'
    )
);

INSERT INTO authority_global_commit_meta (
    singleton, head_sequence, head_chain_digest
) VALUES (
    1, 0,
    '0000000000000000000000000000000000000000000000000000000000000000'
) ON CONFLICT(singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS authority_global_commits (
    commit_sequence INTEGER PRIMARY KEY CHECK (commit_sequence > 0),
    mutation_kind TEXT NOT NULL CHECK (mutation_kind <> ''),
    projection_kind TEXT NOT NULL CHECK (
        projection_kind IN ('baseline', 'admission', 'budget', 'revocation', 'frost', 'payment', 'economic', 'channel_release_publication', 'factor_assignment_authority_set', 'fiscal', 'finding_challenge', 'finding_status', 'runtime_replay_migration', 'governed_approval_replay_migration', 'dpop_replay_migration', 'security_participant_migration', 'security_participant_state', 'security_participant_egress', 'native_dispatch_ledger', 'security_participant_output', 'security_participant_nonce_preflight')
    ),
    projection_key TEXT NOT NULL,
    projection_sequence INTEGER NOT NULL CHECK (projection_sequence >= 0),
    projection_reference_digest TEXT NOT NULL CHECK (
        length(projection_reference_digest) = 64
        AND projection_reference_digest NOT GLOB '*[^0-9a-f]*'
    ),
    authority_projection_digest TEXT NOT NULL CHECK (
        length(authority_projection_digest) = 64
        AND authority_projection_digest NOT GLOB '*[^0-9a-f]*'
    ),
    previous_chain_digest TEXT NOT NULL CHECK (
        length(previous_chain_digest) = 64
        AND previous_chain_digest NOT GLOB '*[^0-9a-f]*'
    ),
    chain_digest TEXT NOT NULL CHECK (
        length(chain_digest) = 64
        AND chain_digest NOT GLOB '*[^0-9a-f]*'
    ),
    store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
    store_lease_id TEXT,
    store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch >= 0),
    CHECK (
        (projection_kind = 'baseline' AND commit_sequence = 1
         AND projection_key = '' AND projection_sequence = 0
         AND store_lease_id IS NULL AND store_owner_epoch = 0)
        OR
        (projection_kind <> 'baseline' AND projection_key <> ''
         AND projection_sequence > 0 AND store_lease_id IS NOT NULL
         AND store_owner_epoch > 0)
    )
);

CREATE INDEX IF NOT EXISTS authority_global_commits_projection
ON authority_global_commits(
    projection_kind, projection_key, projection_sequence
);

CREATE TRIGGER IF NOT EXISTS authority_global_commits_immutable
BEFORE UPDATE ON authority_global_commits
BEGIN
    SELECT RAISE(ABORT, 'global authority commit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS authority_global_commits_no_delete
BEFORE DELETE ON authority_global_commits
BEGIN
    SELECT RAISE(ABORT, 'global authority commit is immutable');
END;
