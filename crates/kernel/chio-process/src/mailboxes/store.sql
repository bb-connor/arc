CREATE TABLE IF NOT EXISTS mailbox_runtime (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    version INTEGER NOT NULL,
    authority TEXT NOT NULL,
    kernel_key TEXT NOT NULL,
    configuration_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mailboxes (
    id TEXT PRIMARY KEY,
    last_sequence INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    acknowledged_through INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged_through BETWEEN 0 AND last_sequence)
);
CREATE TABLE IF NOT EXISTS mailbox_messages (
    channel TEXT NOT NULL REFERENCES mailboxes(id),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    message_key TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload TEXT,
    payload_bytes INTEGER NOT NULL CHECK (payload_bytes >= 0),
    sender TEXT,
    PRIMARY KEY (channel, sequence),
    UNIQUE (channel, message_key)
);
CREATE INDEX IF NOT EXISTS mailbox_pending ON mailbox_messages(channel) WHERE payload IS NOT NULL;
