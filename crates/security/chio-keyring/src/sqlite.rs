include!("sqlite_parts/part_01.rs");
include!("sqlite_parts/part_02.rs");

fn persist_state(
    connection: &Connection,
    state: &KeyLogState,
    events: &[SignedKeyLogEvent],
    root_hash: Hash,
) -> Result<()> {
    let last = events.last().ok_or(KeyringError::StateInvariant(
        "cannot persist state for an empty event log",
    ))?;
    connection.execute(
        r#"
        INSERT INTO key_state (
            singleton, active_key_id, pending_key_id, pending_event_id, signing_epoch,
            last_sequence, last_event_hash, tree_size, root_hash
        ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(singleton) DO UPDATE SET
            active_key_id = excluded.active_key_id,
            pending_key_id = excluded.pending_key_id,
            pending_event_id = excluded.pending_event_id,
            signing_epoch = excluded.signing_epoch,
            last_sequence = excluded.last_sequence,
            last_event_hash = excluded.last_event_hash,
            tree_size = excluded.tree_size,
            root_hash = excluded.root_hash
        "#,
        params![
            state.active_signing_key()?.key_id.to_string(),
            state
                .pending_rotation_key()
                .map(|record| record.key_id.to_string()),
            state.pending_event_id().map(EventId::as_str),
            to_i64(state.signing_epoch())?,
            to_i64(last.body.sequence)?,
            last.envelope_hash()?.to_string(),
            to_i64(u64::try_from(events.len()).map_err(|_| KeyringError::NumericRange)?)?,
            root_hash.to_string(),
        ],
    )?;
    Ok(())
}
