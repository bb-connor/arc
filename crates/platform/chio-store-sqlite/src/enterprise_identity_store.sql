CREATE TABLE enterprise_identities (
    identity_id TEXT NOT NULL PRIMARY KEY CHECK (
        length(identity_id) = 32 AND identity_id NOT GLOB '*[^0-9a-f]*'
    ),
    provider_scope TEXT NOT NULL CHECK (octet_length(provider_scope) <= 4096),
    principal TEXT NOT NULL CHECK (octet_length(principal) <= 4096),
    subject TEXT NOT NULL UNIQUE CHECK (octet_length(subject) <= 256),
    deactivated_at INTEGER,
    UNIQUE (provider_scope, principal)
) STRICT;

CREATE TABLE enterprise_identity_history (
    subject TEXT NOT NULL PRIMARY KEY CHECK (octet_length(subject) <= 256),
    identity_id TEXT NOT NULL CHECK (
        length(identity_id) = 32 AND identity_id NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;
