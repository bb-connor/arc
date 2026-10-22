CREATE TABLE chio_agent_web_replays (
    replay_scope TEXT NOT NULL,
    webhook_id  TEXT NOT NULL,
    consumed_at INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (replay_scope, webhook_id)
);

CREATE INDEX idx_chio_agent_web_replays_expires_at
    ON chio_agent_web_replays(expires_at);

CREATE TABLE chio_agent_web_replay_reservations (
    reservation_id TEXT PRIMARY KEY,
    entries_digest TEXT NOT NULL,
    entry_count    INTEGER NOT NULL CHECK (entry_count > 0),
    expires_at     INTEGER NOT NULL,
    state          TEXT NOT NULL CHECK (
        state IN ('pending', 'filesystem_finalized', 'complete')
    )
);

CREATE INDEX idx_chio_agent_web_replay_reservations_expires_at
    ON chio_agent_web_replay_reservations(expires_at);

CREATE TABLE chio_agent_web_replay_reservation_entries (
    reservation_id TEXT NOT NULL,
    replay_scope   TEXT NOT NULL,
    webhook_id     TEXT NOT NULL,
    expires_at     INTEGER NOT NULL,
    PRIMARY KEY (reservation_id, replay_scope, webhook_id)
);

CREATE INDEX idx_chio_agent_web_replay_reservation_entries_marker
    ON chio_agent_web_replay_reservation_entries(
        replay_scope,
        webhook_id,
        expires_at
    );

CREATE TABLE chio_agent_web_replay_clock (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    wall_clock_high_water INTEGER NOT NULL
);

CREATE TABLE chio_agent_web_replay_limits (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    global_capacity    INTEGER NOT NULL CHECK (global_capacity > 0),
    per_scope_capacity INTEGER NOT NULL CHECK (per_scope_capacity > 0)
);
