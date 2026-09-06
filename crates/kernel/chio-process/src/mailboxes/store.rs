use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};

use super::types::{
    claim_generation, sequence, Acknowledge, Claim, Complete, Receive, Send, MAX_LEASE_MS,
    MIN_LEASE_MS,
};
use super::MailboxConfig;
use crate::{digest, ProcessError};

pub(super) struct MailboxStore {
    connection: Connection,
}

impl MailboxStore {
    pub fn open(
        path: &Path,
        authority: &str,
        key: &str,
        config: &[MailboxConfig],
    ) -> Result<Self, ProcessError> {
        let path = crate::store::private_file(path)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(include_str!("store.sql"))?;
        // Files created before sender attestation gain the column; their existing
        // messages remain unattested and are reported with a null sender. Files
        // created before delivery leases gain the claim columns unclaimed.
        let columns = tx
            .prepare("PRAGMA table_info(mailbox_messages)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        if !columns.iter().any(|column| column == "sender") {
            tx.execute_batch("ALTER TABLE mailbox_messages ADD COLUMN sender TEXT")?;
        }
        if !columns.iter().any(|column| column == "claimant") {
            tx.execute_batch(
                "ALTER TABLE mailbox_messages ADD COLUMN claimant TEXT;
                ALTER TABLE mailbox_messages ADD COLUMN claim_generation INTEGER NOT NULL DEFAULT 0 CHECK (claim_generation >= 0);
                ALTER TABLE mailbox_messages ADD COLUMN lease_expires_at INTEGER",
            )?;
        }
        let config_hash = digest(&config)?;
        tx.execute("INSERT OR IGNORE INTO mailbox_runtime(singleton, version, authority, kernel_key, configuration_hash)
            VALUES (1, 1, ?1, ?2, ?3)", params![authority, key, config_hash])?;
        let stored: (u32, String, String, String) = tx.query_row(
            "SELECT version, authority, kernel_key, configuration_hash FROM mailbox_runtime WHERE singleton = 1",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        if stored != (1, authority.to_owned(), key.to_owned(), config_hash) {
            return Err(ProcessError::Configuration(
                "mailboxes belong to another authority, key, configuration or version",
            ));
        }
        for channel in config {
            tx.execute(
                "INSERT OR IGNORE INTO mailboxes(id) VALUES (?1)",
                [&channel.id],
            )?;
        }
        tx.commit()?;
        Ok(Self { connection })
    }

    /// Append or replay one message. `sender` is the kernel-selected process
    /// identity supplied by an attesting host; a stored key belongs to the
    /// sender that committed it.
    pub fn send(
        &mut self,
        channel: &MailboxConfig,
        args: Send,
        sender: Option<&str>,
    ) -> Result<Value, ProcessError> {
        crate::validate_id(&args.message_key)?;
        let payload = chio_core_types::crypto::canonical_json_bytes(&args.payload)?;
        let size = u32::try_from(payload.len())
            .map_err(|_| ProcessError::Invalid("mailbox message exceeds payload limit"))?;
        if size > channel.limits.max_message_bytes {
            return Err(ProcessError::Invalid(
                "mailbox message exceeds payload limit",
            ));
        }
        let payload_hash = chio_core_types::crypto::sha256_hex(&payload);
        let payload = String::from_utf8(payload)
            .map_err(|_| ProcessError::Invalid("invalid mailbox payload"))?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (last, acknowledged): (u32, u32) = tx.query_row(
            "SELECT last_sequence, acknowledged_through FROM mailboxes WHERE id = ?1",
            [&channel.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let existing: Option<(u32, String, Option<String>)> = tx.query_row(
            "SELECT sequence, payload_hash, sender FROM mailbox_messages WHERE channel = ?1 AND message_key = ?2",
            params![channel.id, args.message_key], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        if let Some((number, hash, owner)) = existing {
            if hash != payload_hash || owner.as_deref() != sender {
                return Err(ProcessError::Conflict);
            }
            return Ok(
                json!({"status": if number <= acknowledged { "acknowledged" } else { "sent" },
                "sequence": number.to_string()}),
            );
        }
        if last >= channel.limits.max_messages {
            return Ok(json!({"status": "exhausted"}));
        }
        let (count, bytes): (u32, u32) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0) FROM mailbox_messages WHERE channel = ?1 AND payload IS NOT NULL",
            [&channel.id], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if count >= channel.limits.max_pending_messages
            || bytes.saturating_add(size) > channel.limits.max_pending_bytes
        {
            return Ok(json!({"status": "full"}));
        }
        let next = last
            .checked_add(1)
            .ok_or(ProcessError::Limit("mailbox sequence"))?;
        tx.execute("INSERT INTO mailbox_messages(channel, sequence, message_key, payload_hash, payload, payload_bytes, sender)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", params![channel.id, next, args.message_key, payload_hash, payload, size, sender])?;
        tx.execute(
            "UPDATE mailboxes SET last_sequence = ?1 WHERE id = ?2",
            params![next, channel.id],
        )?;
        tx.commit()?;
        Ok(json!({"status": "sent", "sequence": next.to_string()}))
    }

    pub fn receive(
        &mut self,
        channel: &MailboxConfig,
        args: Receive,
    ) -> Result<Value, ProcessError> {
        let after = sequence(&args.after_sequence)?;
        if args.limit == 0 || args.limit > 16 {
            return Err(ProcessError::Invalid("mailbox receive limit must be 1-16"));
        }
        let tx = self.connection.transaction()?;
        let (last, acknowledged): (u32, u32) = tx.query_row(
            "SELECT last_sequence, acknowledged_through FROM mailboxes WHERE id = ?1",
            [&channel.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if after < acknowledged {
            return Ok(
                json!({"status": "cursor_expired", "acknowledged_through": acknowledged.to_string()}),
            );
        }
        if after > last {
            return Err(ProcessError::Invalid("mailbox cursor exceeds history"));
        }
        let mut statement = tx.prepare("SELECT sequence, payload, sender FROM mailbox_messages
            WHERE channel = ?1 AND sequence > ?2 AND payload IS NOT NULL ORDER BY sequence LIMIT ?3")?;
        let rows = statement.query_map(params![channel.id, after, args.limit], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        let mut messages = Vec::new();
        let mut next = after;
        for row in rows {
            let (number, payload, sender) = row?;
            let payload: Value = serde_json::from_str(&payload)?;
            messages.push(
                json!({"sequence": number.to_string(), "payload": payload, "sender": sender}),
            );
            next = number;
        }
        Ok(json!({"status": "received", "messages": messages, "next_sequence": next.to_string()}))
    }

    pub fn acknowledge(
        &mut self,
        channel: &MailboxConfig,
        args: Acknowledge,
    ) -> Result<Value, ProcessError> {
        let through = sequence(&args.through_sequence)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (last, acknowledged): (u32, u32) = tx.query_row(
            "SELECT last_sequence, acknowledged_through FROM mailboxes WHERE id = ?1",
            [&channel.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if through > last {
            return Err(ProcessError::Invalid(
                "mailbox acknowledgement exceeds history",
            ));
        }
        let through = through.max(acknowledged);
        tx.execute("UPDATE mailbox_messages SET payload = NULL, payload_bytes = 0 WHERE channel = ?1 AND sequence <= ?2 AND payload IS NOT NULL",
            params![channel.id, through])?;
        tx.execute(
            "UPDATE mailboxes SET acknowledged_through = ?1 WHERE id = ?2",
            params![through, channel.id],
        )?;
        tx.commit()?;
        Ok(json!({"status": "acknowledged", "through_sequence": through.to_string()}))
    }

    /// Lease the oldest pending messages no live lease holds to `claimant`.
    /// A message whose lease expired is leased again under a new claim
    /// generation, which fences the earlier claimant's completion. Claims
    /// consume nothing; receives and acknowledgements see the messages as
    /// before.
    pub fn claim(
        &mut self,
        channel: &MailboxConfig,
        args: Claim,
        claimant: &str,
        now_ms: u64,
    ) -> Result<Value, ProcessError> {
        if args.limit == 0 || args.limit > 16 {
            return Err(ProcessError::Invalid("mailbox claim limit must be 1-16"));
        }
        if !(MIN_LEASE_MS..=MAX_LEASE_MS).contains(&args.lease_ms) {
            return Err(ProcessError::Invalid(
                "mailbox lease must be 1000-300000 milliseconds",
            ));
        }
        let clock = || ProcessError::Invalid("mailbox lease exceeds the clock");
        let expires = now_ms.checked_add(args.lease_ms).ok_or_else(clock)?;
        // Lease instants are stored as SQLite integers.
        let now = i64::try_from(now_ms).map_err(|_| clock())?;
        let expires = i64::try_from(expires).map_err(|_| clock())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidates = tx
            .prepare(
                "SELECT sequence, payload, sender, claim_generation FROM mailbox_messages
                WHERE channel = ?1 AND payload IS NOT NULL
                    AND (claimant IS NULL OR lease_expires_at <= ?2)
                ORDER BY sequence LIMIT ?3",
            )?
            .query_map(params![channel.id, now, args.limit], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, u32>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut messages = Vec::with_capacity(candidates.len());
        for (number, payload, sender, generation) in candidates {
            let generation = generation
                .checked_add(1)
                .ok_or(ProcessError::Limit("mailbox claim generation"))?;
            tx.execute(
                "UPDATE mailbox_messages SET claimant = ?1, claim_generation = ?2, lease_expires_at = ?3
                WHERE channel = ?4 AND sequence = ?5",
                params![claimant, generation, expires, channel.id, number],
            )?;
            let payload: Value = serde_json::from_str(&payload)?;
            messages.push(json!({
                "sequence": number.to_string(), "payload": payload, "sender": sender,
                "claim": generation.to_string(), "lease_expires_at_ms": expires,
            }));
        }
        tx.commit()?;
        Ok(json!({"status": "claimed", "messages": messages}))
    }

    /// Consume one message under the claim that holds it. Only the process
    /// that made the current claim completes it; a claim superseded after its
    /// lease expired is refused. Repeating a completion returns the same
    /// result.
    pub fn complete(
        &mut self,
        channel: &MailboxConfig,
        args: Complete,
        claimant: &str,
    ) -> Result<Value, ProcessError> {
        let number = sequence(&args.sequence)?;
        let generation = claim_generation(&args.claim)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<(Option<String>, u32, bool)> = tx
            .query_row(
                "SELECT claimant, claim_generation, payload IS NOT NULL FROM mailbox_messages
                WHERE channel = ?1 AND sequence = ?2",
                params![channel.id, number],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (holder, current, pending) =
            stored.ok_or(ProcessError::Invalid("mailbox completion names no message"))?;
        if generation == 0 || holder.as_deref() != Some(claimant) || current != generation {
            return Err(ProcessError::Conflict);
        }
        if pending {
            tx.execute(
                "UPDATE mailbox_messages SET payload = NULL, payload_bytes = 0
                WHERE channel = ?1 AND sequence = ?2",
                params![channel.id, number],
            )?;
        }
        tx.commit()?;
        Ok(json!({"status": "completed", "sequence": number.to_string()}))
    }
}
