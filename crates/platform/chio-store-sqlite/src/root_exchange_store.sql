CREATE TABLE root_exchange_events (
    sequence INTEGER PRIMARY KEY CHECK (
        typeof(sequence) = 'integer' AND sequence BETWEEN 1 AND 9007199254740991
    ),
    mutation TEXT NOT NULL CHECK (
        mutation IN ('mint', 'client_assertion', 'erase_openings', 'key_snapshot', 'prune')
    ),
    subject TEXT NOT NULL CHECK (
        typeof(subject) = 'text' AND length(subject) BETWEEN 1 AND 256
        AND octet_length(subject) <= 1024 AND instr(subject, char(0)) = 0
    ),
    digest TEXT NOT NULL CHECK (
        typeof(digest) = 'text' AND length(digest) = 64
        AND instr(digest, char(0)) = 0 AND octet_length(digest) <= 256 AND digest NOT GLOB '*[^0-9a-f]*'
    ),
    occurred_at INTEGER NOT NULL CHECK (
        typeof(occurred_at) = 'integer' AND occurred_at BETWEEN 0 AND 9007199254740991
    )
);

CREATE INDEX root_exchange_events_subject ON root_exchange_events(mutation, subject);

CREATE TRIGGER root_exchange_events_immutable
BEFORE UPDATE ON root_exchange_events
BEGIN
    SELECT RAISE(ABORT, 'root exchange event is immutable');
END;

CREATE TRIGGER root_exchange_events_no_delete
BEFORE DELETE ON root_exchange_events
BEGIN
    SELECT RAISE(ABORT, 'root exchange event is immutable');
END;

-- Every replay binding a mint or client assertion made, recorded with its
-- event so the live table is reconciled against authenticated history.
CREATE TABLE root_exchange_replay_bindings (
    sequence INTEGER PRIMARY KEY REFERENCES root_exchange_events(sequence) CHECK (
        typeof(sequence) = 'integer' AND sequence BETWEEN 1 AND 9007199254740991
    ),
    replay_key_digest TEXT NOT NULL CHECK (
        typeof(replay_key_digest) = 'text' AND length(replay_key_digest) = 64
        AND instr(replay_key_digest, char(0)) = 0 AND octet_length(replay_key_digest) <= 256
        AND replay_key_digest NOT GLOB '*[^0-9a-f]*'
    ),
    namespace TEXT NOT NULL CHECK (
        namespace IN (
            'oauth_id_jag', 'entra_jwt', 'entra_agent_id', 'oidc_jwt', 'oauth_introspection',
            'chio_local_as', 'chio_operator_key', 'operator_static_bearer',
            'chio_local_as_issue', 'client_assertion'
        )
    ),
    bound_at INTEGER NOT NULL CHECK (
        typeof(bound_at) = 'integer' AND bound_at BETWEEN 0 AND 9007199254740991
    ),
    retain_until INTEGER NOT NULL CHECK (
        typeof(retain_until) = 'integer' AND retain_until BETWEEN 0 AND 9007199254740991
    ),
    capability_id TEXT CHECK (
        capability_id IS NULL OR (
            typeof(capability_id) = 'text' AND length(capability_id) BETWEEN 1 AND 256
            AND octet_length(capability_id) <= 1024 AND instr(capability_id, char(0)) = 0
        )
    ),
    CHECK (retain_until > bound_at),
    CHECK ((namespace = 'client_assertion') = (capability_id IS NULL))
) WITHOUT ROWID;

CREATE INDEX root_exchange_replay_bindings_key
    ON root_exchange_replay_bindings(replay_key_digest, sequence);

CREATE TRIGGER root_exchange_replay_bindings_immutable
BEFORE UPDATE ON root_exchange_replay_bindings
BEGIN
    SELECT RAISE(ABORT, 'recorded replay binding is immutable');
END;

CREATE TRIGGER root_exchange_replay_bindings_no_delete
BEFORE DELETE ON root_exchange_replay_bindings
BEGIN
    SELECT RAISE(ABORT, 'recorded replay binding is immutable');
END;

-- Every bearer mapping a mint made, recorded with its event.
CREATE TABLE root_exchange_bearer_bindings (
    sequence INTEGER PRIMARY KEY REFERENCES root_exchange_events(sequence) CHECK (
        typeof(sequence) = 'integer' AND sequence BETWEEN 1 AND 9007199254740991
    ),
    token_digest TEXT NOT NULL CHECK (
        typeof(token_digest) = 'text' AND length(token_digest) = 64
        AND instr(token_digest, char(0)) = 0 AND octet_length(token_digest) <= 256
        AND token_digest NOT GLOB '*[^0-9a-f]*'
    ),
    capability_id TEXT NOT NULL CHECK (
        typeof(capability_id) = 'text' AND length(capability_id) BETWEEN 1 AND 256
        AND octet_length(capability_id) <= 1024 AND instr(capability_id, char(0)) = 0
    ),
    retain_until INTEGER NOT NULL CHECK (
        typeof(retain_until) = 'integer' AND retain_until BETWEEN 0 AND 9007199254740991
    )
) WITHOUT ROWID;

CREATE INDEX root_exchange_bearer_bindings_token
    ON root_exchange_bearer_bindings(token_digest, sequence);

CREATE TRIGGER root_exchange_bearer_bindings_immutable
BEFORE UPDATE ON root_exchange_bearer_bindings
BEGIN
    SELECT RAISE(ABORT, 'recorded bearer mapping is immutable');
END;

CREATE TRIGGER root_exchange_bearer_bindings_no_delete
BEFORE DELETE ON root_exchange_bearer_bindings
BEGIN
    SELECT RAISE(ABORT, 'recorded bearer mapping is immutable');
END;

CREATE TABLE root_exchange_replay (
    replay_key_digest TEXT PRIMARY KEY CHECK (
        typeof(replay_key_digest) = 'text' AND length(replay_key_digest) = 64
        AND instr(replay_key_digest, char(0)) = 0 AND octet_length(replay_key_digest) <= 256
        AND replay_key_digest NOT GLOB '*[^0-9a-f]*'
    ),
    namespace TEXT NOT NULL CHECK (
        namespace IN (
            'oauth_id_jag', 'entra_jwt', 'entra_agent_id', 'oidc_jwt', 'oauth_introspection',
            'chio_local_as', 'chio_operator_key', 'operator_static_bearer',
            'chio_local_as_issue', 'client_assertion'
        )
    ),
    bound_at INTEGER NOT NULL CHECK (
        typeof(bound_at) = 'integer' AND bound_at BETWEEN 0 AND 9007199254740991
    ),
    retain_until INTEGER NOT NULL CHECK (
        typeof(retain_until) = 'integer' AND retain_until BETWEEN 0 AND 9007199254740991
    ),
    capability_id TEXT CHECK (
        capability_id IS NULL OR (
            typeof(capability_id) = 'text' AND length(capability_id) BETWEEN 1 AND 256
            AND octet_length(capability_id) <= 1024 AND instr(capability_id, char(0)) = 0
        )
    ),
    CHECK (retain_until > bound_at),
    CHECK ((namespace = 'client_assertion') = (capability_id IS NULL))
) WITHOUT ROWID;

CREATE INDEX root_exchange_replay_retain ON root_exchange_replay(retain_until);

CREATE TRIGGER root_exchange_replay_immutable
BEFORE UPDATE ON root_exchange_replay
BEGIN
    SELECT RAISE(ABORT, 'replay binding is immutable');
END;

CREATE TABLE root_exchange_roots (
    capability_id TEXT PRIMARY KEY CHECK (
        typeof(capability_id) = 'text' AND length(capability_id) BETWEEN 1 AND 256
        AND octet_length(capability_id) <= 1024 AND instr(capability_id, char(0)) = 0
    ),
    root_policy_rule_id TEXT NOT NULL CHECK (
        typeof(root_policy_rule_id) = 'text' AND length(root_policy_rule_id) BETWEEN 1 AND 256
        AND octet_length(root_policy_rule_id) <= 1024 AND instr(root_policy_rule_id, char(0)) = 0
    ),
    tag_key_id TEXT NOT NULL CHECK (
        typeof(tag_key_id) = 'text' AND length(tag_key_id) = 64
        AND instr(tag_key_id, char(0)) = 0 AND octet_length(tag_key_id) <= 256
        AND tag_key_id NOT GLOB '*[^0-9a-f]*'
    ),
    subject_tag TEXT NOT NULL CHECK (
        typeof(subject_tag) = 'text' AND length(subject_tag) = 64
        AND instr(subject_tag, char(0)) = 0 AND octet_length(subject_tag) <= 256
        AND subject_tag NOT GLOB '*[^0-9a-f]*'
    ),
    tenant_tag TEXT NOT NULL CHECK (
        typeof(tenant_tag) = 'text' AND length(tenant_tag) = 64
        AND instr(tenant_tag, char(0)) = 0 AND octet_length(tenant_tag) <= 256
        AND tenant_tag NOT GLOB '*[^0-9a-f]*'
    ),
    replay_key_digest TEXT NOT NULL CHECK (
        typeof(replay_key_digest) = 'text' AND length(replay_key_digest) = 64
        AND instr(replay_key_digest, char(0)) = 0 AND octet_length(replay_key_digest) <= 256
        AND replay_key_digest NOT GLOB '*[^0-9a-f]*'
    ),
    replay_bound_at INTEGER NOT NULL CHECK (
        typeof(replay_bound_at) = 'integer' AND replay_bound_at BETWEEN 0 AND 9007199254740991
    ),
    client_id TEXT NOT NULL CHECK (
        typeof(client_id) = 'text' AND length(client_id) BETWEEN 1 AND 256
        AND octet_length(client_id) <= 1024 AND instr(client_id, char(0)) = 0
    ),
    artifact_digest TEXT NOT NULL CHECK (
        typeof(artifact_digest) = 'text' AND length(artifact_digest) = 64
        AND instr(artifact_digest, char(0)) = 0 AND octet_length(artifact_digest) <= 256
        AND artifact_digest NOT GLOB '*[^0-9a-f]*'
    ),
    request_digest TEXT NOT NULL CHECK (
        typeof(request_digest) = 'text' AND length(request_digest) = 64
        AND instr(request_digest, char(0)) = 0 AND octet_length(request_digest) <= 256
        AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    expires_at INTEGER NOT NULL CHECK (
        typeof(expires_at) = 'integer' AND expires_at BETWEEN 0 AND 9007199254740991
    ),
    anchor_kind TEXT NOT NULL CHECK (
        anchor_kind IN (
            'oauth_id_jag', 'entra_jwt', 'entra_agent_id', 'oidc_jwt', 'oauth_introspection',
            'chio_local_as', 'chio_operator_key', 'operator_static_bearer'
        )
    ),
    holder TEXT NOT NULL CHECK (holder IN ('edge_session', 'caller')),
    root_policy_digest TEXT NOT NULL CHECK (
        typeof(root_policy_digest) = 'text' AND length(root_policy_digest) = 64
        AND instr(root_policy_digest, char(0)) = 0 AND octet_length(root_policy_digest) <= 256
        AND root_policy_digest NOT GLOB '*[^0-9a-f]*'
    ),
    provider_identity_digest TEXT CHECK (
        provider_identity_digest IS NULL OR (
            typeof(provider_identity_digest) = 'text' AND length(provider_identity_digest) = 64
            AND instr(provider_identity_digest, char(0)) = 0
            AND octet_length(provider_identity_digest) <= 256
            AND provider_identity_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    key_snapshot_digest TEXT CHECK (
        key_snapshot_digest IS NULL OR (
            typeof(key_snapshot_digest) = 'text' AND length(key_snapshot_digest) = 64
            AND instr(key_snapshot_digest, char(0)) = 0 AND octet_length(key_snapshot_digest) <= 256
            AND key_snapshot_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    context_digest TEXT NOT NULL UNIQUE CHECK (
        typeof(context_digest) = 'text' AND length(context_digest) = 64
        AND instr(context_digest, char(0)) = 0 AND octet_length(context_digest) <= 256
        AND context_digest NOT GLOB '*[^0-9a-f]*'
    ),
    delegation_context BLOB NOT NULL CHECK (
        typeof(delegation_context) = 'blob' AND length(delegation_context) BETWEEN 1 AND 65536
    ),
    root_capability BLOB NOT NULL CHECK (
        typeof(root_capability) = 'blob' AND length(root_capability) BETWEEN 1 AND 65536
    ),
    minted_at INTEGER NOT NULL CHECK (
        typeof(minted_at) = 'integer' AND minted_at BETWEEN 0 AND 9007199254740991
    ),
    authorization_projection_digest TEXT NOT NULL CHECK (
        typeof(authorization_projection_digest) = 'text'
        AND length(authorization_projection_digest) = 64
        AND instr(authorization_projection_digest, char(0)) = 0
        AND octet_length(authorization_projection_digest) <= 256
        AND authorization_projection_digest NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (minted_at < expires_at),
    CHECK ((provider_identity_digest IS NULL) = (anchor_kind IN (
        'chio_local_as', 'chio_operator_key', 'operator_static_bearer'
    )))
) WITHOUT ROWID;

CREATE INDEX root_exchange_roots_rule ON root_exchange_roots(root_policy_rule_id);
CREATE INDEX root_exchange_roots_subject ON root_exchange_roots(tag_key_id, subject_tag);
CREATE INDEX root_exchange_roots_tenant ON root_exchange_roots(tag_key_id, tenant_tag);
CREATE INDEX root_exchange_roots_generation ON root_exchange_roots(tag_key_id);
CREATE INDEX root_exchange_roots_replay ON root_exchange_roots(replay_key_digest);
CREATE UNIQUE INDEX root_exchange_roots_replay_binding
    ON root_exchange_roots(replay_key_digest, replay_bound_at);

CREATE TRIGGER root_exchange_roots_immutable
BEFORE UPDATE ON root_exchange_roots
BEGIN
    SELECT RAISE(ABORT, 'anchored root is immutable');
END;

CREATE TRIGGER root_exchange_roots_no_delete
BEFORE DELETE ON root_exchange_roots
BEGIN
    SELECT RAISE(ABORT, 'anchored root is retained');
END;

CREATE TABLE root_exchange_bearer_tokens (
    token_digest TEXT PRIMARY KEY CHECK (
        typeof(token_digest) = 'text' AND length(token_digest) = 64
        AND instr(token_digest, char(0)) = 0 AND octet_length(token_digest) <= 256
        AND token_digest NOT GLOB '*[^0-9a-f]*'
    ),
    capability_id TEXT NOT NULL REFERENCES root_exchange_roots(capability_id),
    retain_until INTEGER NOT NULL CHECK (
        typeof(retain_until) = 'integer' AND retain_until BETWEEN 0 AND 9007199254740991
    )
) WITHOUT ROWID;

CREATE INDEX root_exchange_bearer_tokens_retain ON root_exchange_bearer_tokens(retain_until);
CREATE INDEX root_exchange_bearer_tokens_root ON root_exchange_bearer_tokens(capability_id);

CREATE TRIGGER root_exchange_bearer_tokens_immutable
BEFORE UPDATE ON root_exchange_bearer_tokens
BEGIN
    SELECT RAISE(ABORT, 'bearer token mapping is immutable');
END;

CREATE TABLE root_exchange_key_snapshots (
    snapshot_digest TEXT PRIMARY KEY CHECK (
        typeof(snapshot_digest) = 'text' AND length(snapshot_digest) = 64
        AND instr(snapshot_digest, char(0)) = 0 AND octet_length(snapshot_digest) <= 256
        AND snapshot_digest NOT GLOB '*[^0-9a-f]*'
    ),
    issuer TEXT NOT NULL CHECK (
        typeof(issuer) = 'text' AND length(issuer) BETWEEN 1 AND 2048
        AND octet_length(issuer) <= 8192 AND instr(issuer, char(0)) = 0
    ),
    observed_at INTEGER NOT NULL CHECK (
        typeof(observed_at) = 'integer' AND observed_at BETWEEN 0 AND 9007199254740991
    ),
    snapshot BLOB NOT NULL CHECK (
        typeof(snapshot) = 'blob' AND length(snapshot) BETWEEN 1 AND 262144
    )
) WITHOUT ROWID;

CREATE TRIGGER root_exchange_key_snapshots_immutable
BEFORE UPDATE ON root_exchange_key_snapshots
BEGIN
    SELECT RAISE(ABORT, 'retained key snapshot is immutable');
END;

CREATE TRIGGER root_exchange_key_snapshots_no_delete
BEFORE DELETE ON root_exchange_key_snapshots
BEGIN
    SELECT RAISE(ABORT, 'retained key snapshot is immutable');
END;

CREATE TABLE root_exchange_policies (
    root_policy_digest TEXT PRIMARY KEY CHECK (
        typeof(root_policy_digest) = 'text' AND length(root_policy_digest) = 64
        AND instr(root_policy_digest, char(0)) = 0 AND octet_length(root_policy_digest) <= 256
        AND root_policy_digest NOT GLOB '*[^0-9a-f]*'
    ),
    policy BLOB NOT NULL CHECK (
        typeof(policy) = 'blob' AND length(policy) BETWEEN 1 AND 1048576
    )
) WITHOUT ROWID;

CREATE TRIGGER root_exchange_policies_immutable
BEFORE UPDATE ON root_exchange_policies
BEGIN
    SELECT RAISE(ABORT, 'retained root policy is immutable');
END;

CREATE TRIGGER root_exchange_policies_no_delete
BEFORE DELETE ON root_exchange_policies
BEGIN
    SELECT RAISE(ABORT, 'retained root policy is immutable');
END;

CREATE TABLE root_exchange_provider_identities (
    provider_identity_digest TEXT PRIMARY KEY CHECK (
        typeof(provider_identity_digest) = 'text' AND length(provider_identity_digest) = 64
        AND instr(provider_identity_digest, char(0)) = 0
        AND octet_length(provider_identity_digest) <= 256
        AND provider_identity_digest NOT GLOB '*[^0-9a-f]*'
    ),
    identity BLOB NOT NULL CHECK (
        typeof(identity) = 'blob' AND length(identity) BETWEEN 1 AND 262144
    )
) WITHOUT ROWID;

CREATE TRIGGER root_exchange_provider_identities_immutable
BEFORE UPDATE ON root_exchange_provider_identities
BEGIN
    SELECT RAISE(ABORT, 'retained provider identity is immutable');
END;

CREATE TRIGGER root_exchange_provider_identities_no_delete
BEFORE DELETE ON root_exchange_provider_identities
BEGIN
    SELECT RAISE(ABORT, 'retained provider identity is immutable');
END;

-- Disclosure custody. No foreign key: an erased tombstone outlives its root.
CREATE TABLE root_exchange_openings (
    capability_id TEXT NOT NULL CHECK (
        typeof(capability_id) = 'text' AND length(capability_id) BETWEEN 1 AND 256
        AND octet_length(capability_id) <= 1024 AND instr(capability_id, char(0)) = 0
    ),
    salt_ref TEXT NOT NULL CHECK (
        typeof(salt_ref) = 'text' AND length(salt_ref) BETWEEN 1 AND 128
        AND octet_length(salt_ref) <= 128 AND instr(salt_ref, char(0)) = 0
        AND salt_ref GLOB '[a-z]*' AND salt_ref NOT GLOB '*[^a-z0-9_.]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('present', 'erased')),
    salt BLOB CHECK (
        (state = 'present' AND typeof(salt) = 'blob' AND length(salt) = 32)
        OR (state = 'erased' AND salt IS NULL)
    ),
    state_at INTEGER NOT NULL CHECK (
        typeof(state_at) = 'integer' AND state_at BETWEEN 0 AND 9007199254740991
    ),
    PRIMARY KEY (capability_id, salt_ref)
) WITHOUT ROWID;

CREATE TRIGGER root_exchange_openings_erase_only
BEFORE UPDATE ON root_exchange_openings
WHEN NOT (OLD.state = 'present' AND NEW.state = 'erased'
    AND NEW.capability_id = OLD.capability_id AND NEW.salt_ref = OLD.salt_ref)
BEGIN
    SELECT RAISE(ABORT, 'root opening may only move from present to erased');
END;

CREATE TRIGGER root_exchange_openings_keep_tombstones
BEFORE DELETE ON root_exchange_openings
WHEN OLD.state = 'erased'
BEGIN
    SELECT RAISE(ABORT, 'erased root opening is retained');
END;
