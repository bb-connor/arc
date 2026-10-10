use super::*;
use serde::{de::DeserializeOwned, Serialize};

pub(super) struct ReplicationState {
    pub anchor: AuthorityReplicationAnchor,
    pub commitment: String,
    pub chain: Vec<SignedAuthorityTransition>,
    pub latest: Option<SignedAuthoritySnapshot>,
    pub observed_ms: u64,
}

pub(crate) fn ensure_schema(connection: &Connection) -> Result<(), AuthorityStoreError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS authority_replication (
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
        BEGIN SELECT RAISE(ABORT, 'authority replication anchor is immutable'); END;",
    )?;
    Ok(())
}

pub(in crate::authority) fn read_snapshot(
    connection: &Connection,
) -> Result<AuthoritySnapshot, AuthorityStoreError> {
    let (public_key, generation, rotated_at) =
        SqliteCapabilityAuthority::read_public_state_from_connection(connection)?;
    Ok(AuthoritySnapshot {
        public_key_hex: public_key.to_hex(),
        generation,
        rotated_at,
        trusted_keys: SqliteCapabilityAuthority::read_trusted_key_snapshots(connection)?,
    })
}

pub(super) fn read_replication(
    connection: &Connection,
) -> Result<Option<ReplicationState>, AuthorityStoreError> {
    let row = connection
        .query_row(
            "SELECT anchor_json, head_commitment, chain_json, latest_envelope_json, observed_ms
         FROM authority_replication WHERE singleton_id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    row.map(|(anchor, commitment, chain, latest, observed)| {
        Ok(ReplicationState {
            anchor: decode(&anchor)?,
            commitment,
            chain: decode(&chain)?,
            latest: latest.as_deref().map(decode).transpose()?,
            observed_ms: authority_unsigned(observed, "replication clock floor")?,
        })
    })
    .transpose()
}

pub(super) fn require_replication(
    connection: &Connection,
) -> Result<ReplicationState, AuthorityStoreError> {
    read_replication(connection)?
        .ok_or_else(|| refused("authority replication requires an out-of-band pinned anchor"))
}

pub(super) fn insert_anchor(
    connection: &Connection,
    anchor: &AuthorityReplicationAnchor,
    now: UnixMillis,
) -> Result<(), AuthorityStoreError> {
    connection.execute(
        "INSERT INTO authority_replication(singleton_id, anchor_json, head_commitment, chain_json, observed_ms)
         VALUES (1, ?1, ?2, '[]', ?3)",
        params![encode(anchor)?, anchor.commitment()?, authority_sqlite_integer(now.get(), "replication clock floor")?],
    )?;
    Ok(())
}

pub(super) fn write_replication(
    connection: &Connection,
    state: &ReplicationState,
) -> Result<(), AuthorityStoreError> {
    connection.execute(
        "UPDATE authority_replication SET head_commitment = ?1, chain_json = ?2,
         latest_envelope_json = ?3, observed_ms = ?4 WHERE singleton_id = 1",
        params![
            state.commitment,
            encode(&state.chain)?,
            state.latest.as_ref().map(encode).transpose()?,
            authority_sqlite_integer(state.observed_ms, "replication clock floor")?
        ],
    )?;
    Ok(())
}

pub(in crate::authority) fn persist_snapshot(
    connection: &Connection,
    snapshot: &AuthoritySnapshot,
) -> Result<(), AuthorityStoreError> {
    // Only verified state or an explicitly pinned local checkpoint reaches here.
    chio_kernel::authority::replication::validate_state(snapshot)?;
    connection.execute("DELETE FROM authority_trusted_keys", [])?;
    for key in &snapshot.trusted_keys {
        persist_trusted_key(
            connection,
            &key.public_key_hex,
            key.generation,
            key.activated_at,
        )?;
        connection.execute(
            "UPDATE authority_trusted_keys SET lifecycle_json = ?1 WHERE public_key_hex = ?2",
            params![
                key.lifecycle.as_ref().map(encode).transpose()?,
                key.public_key_hex
            ],
        )?;
    }
    connection.execute(
        "UPDATE authority_state SET public_key_hex = ?1, generation = ?2, rotated_at = ?3 WHERE singleton_id = 1",
        params![snapshot.public_key_hex, authority_generation(snapshot.generation)?, authority_sqlite_integer(snapshot.rotated_at, "rotation time")?],
    )?;
    Ok(())
}

pub(super) fn decode<T: DeserializeOwned>(text: &str) -> Result<T, AuthorityStoreError> {
    Ok(chio_core::canonical::UntrustedJsonText::from_wire(
        text.as_bytes(),
        MAX_AUTHORITY_WIRE_BYTES,
    )?
    .decode_signed()?)
}
fn encode<T: Serialize>(value: &T) -> Result<String, AuthorityStoreError> {
    let text = serde_json::to_string(value).map_err(chio_core::error::Error::from)?;
    if text.len() > MAX_AUTHORITY_WIRE_BYTES {
        return Err(refused("authority replication record too large"));
    }
    Ok(text)
}
