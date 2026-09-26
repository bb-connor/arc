use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};

use super::types::{
    claim_generation, sequence, Acknowledge, Claim, Complete, Receive, Renew, Send, MAX_LEASE_MS,
    MAX_WAIT_MS, MIN_LEASE_MS,
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
        if args.wait_ms > MAX_WAIT_MS {
            return Err(ProcessError::Invalid(
                "mailbox receive wait must be at most 30000 milliseconds",
            ));
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

    /// Extend a live claim from the host clock, never by adding to its existing
    /// deadline. An expired, consumed or superseded claim cannot be revived.
    pub fn renew(
        &mut self,
        channel: &MailboxConfig,
        args: Renew,
        claimant: &str,
        clock_ms: impl FnOnce() -> Result<u64, ProcessError>,
    ) -> Result<Value, ProcessError> {
        if !channel.renewable_leases {
            return Err(ProcessError::Invalid("mailbox lease renewal is disabled"));
        }
        let number = sequence(&args.sequence)?;
        let generation = claim_generation(&args.claim)?;
        if !(MIN_LEASE_MS..=MAX_LEASE_MS).contains(&args.lease_ms) {
            return Err(ProcessError::Invalid(
                "mailbox lease must be 1000-300000 milliseconds",
            ));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Lock contention must not let an already expired claim renew using
        // the time captured before acquiring the write transaction.
        let now_ms = clock_ms()?;
        let clock = || ProcessError::Invalid("mailbox lease exceeds the clock");
        let expires = now_ms.checked_add(args.lease_ms).ok_or_else(clock)?;
        let now = i64::try_from(now_ms).map_err(|_| clock())?;
        let expires = i64::try_from(expires).map_err(|_| clock())?;
        let changed = tx.execute(
            "UPDATE mailbox_messages SET lease_expires_at = MAX(lease_expires_at, ?1)
             WHERE channel = ?2 AND sequence = ?3 AND payload IS NOT NULL
               AND claimant = ?4 AND claim_generation = ?5 AND claim_generation > 0
               AND lease_expires_at > ?6",
            params![expires, channel.id, number, claimant, generation, now],
        )?;
        if changed != 1 {
            return Err(ProcessError::Conflict);
        }
        let retained: i64 = tx.query_row(
            "SELECT lease_expires_at FROM mailbox_messages WHERE channel = ?1 AND sequence = ?2",
            params![channel.id, number],
            |row| row.get(0),
        )?;
        tx.commit()?;
        Ok(json!({"status": "renewed", "sequence": number.to_string(),
            "claim": generation.to_string(), "lease_expires_at_ms": retained}))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewals_preserve_live_ownership_and_expire_without_reviving_work(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let channel = MailboxConfig {
            id: "jobs".into(),
            limits: Default::default(),
            renewable_leases: true,
        };
        let path = directory.path().join("mailboxes.db");
        let open = || MailboxStore::open(&path, "authority", "key", std::slice::from_ref(&channel));
        let mut store = open()?;
        store.send(
            &channel,
            Send {
                message_key: "one".into(),
                payload: json!(1),
            },
            Some("sender"),
        )?;
        let claim = || Claim {
            limit: 1,
            lease_ms: 1000,
        };
        let renew = |lease_ms| Renew {
            sequence: "1".into(),
            claim: "1".into(),
            lease_ms,
        };
        store.claim(&channel, claim(), "a", 10_000)?;
        assert!(matches!(
            store.renew(&channel, renew(1000), "b", || Ok(10_500)),
            Err(ProcessError::Conflict)
        ));
        // The clock is sampled under the write transaction, after contention.
        let renewed = store.renew(&channel, renew(2000), "a", || {
            let competitor = Connection::open(&path)?;
            competitor.busy_timeout(Duration::ZERO)?;
            assert!(competitor.execute_batch("BEGIN IMMEDIATE").is_err());
            Ok(10_500)
        })?;
        assert_eq!(renewed["claim"], "1");
        assert_eq!(renewed["lease_expires_at_ms"], 12_500);
        // Renewals do not accumulate duration, and a shorter request does not
        // shorten the live deadline. Reopening retains that exact deadline.
        assert_eq!(
            store.renew(&channel, renew(1000), "a", || Ok(10_500))?["lease_expires_at_ms"],
            12_500
        );
        drop(store);
        let mut store = open()?;
        assert_eq!(
            store.claim(&channel, claim(), "b", 11_000)?["messages"],
            json!([])
        );
        for lease in [0, 999, 300_001, u64::MAX] {
            assert!(store
                .renew(&channel, renew(lease), "a", || Ok(11_000))
                .is_err());
        }
        for now in [i64::MAX as u64, u64::MAX] {
            assert!(store.renew(&channel, renew(1000), "a", || Ok(now)).is_err());
        }
        assert_eq!(
            store.claim(&channel, claim(), "b", 12_499)?["messages"],
            json!([])
        );
        assert!(matches!(
            store.renew(&channel, renew(1000), "a", || Ok(12_500)),
            Err(ProcessError::Conflict)
        ));
        let next = store.claim(&channel, claim(), "b", 12_500)?;
        assert_eq!(next["messages"][0]["claim"], "2");
        assert!(store
            .renew(&channel, renew(1000), "a", || Ok(12_501))
            .is_err());
        assert!(store
            .complete(
                &channel,
                Complete {
                    sequence: "1".into(),
                    claim: "1".into()
                },
                "a"
            )
            .is_err());
        let current = || Renew {
            sequence: "1".into(),
            claim: "2".into(),
            lease_ms: 1000,
        };
        store.renew(&channel, current(), "b", || Ok(12_501))?;
        store.complete(
            &channel,
            Complete {
                sequence: "1".into(),
                claim: "2".into(),
            },
            "b",
        )?;
        assert!(store
            .renew(&channel, current(), "b", || Ok(12_502))
            .is_err());
        assert_eq!(
            store.claim(&channel, claim(), "a", 20_000)?["messages"],
            json!([])
        );
        let mut disabled = channel.clone();
        disabled.renewable_leases = false;
        assert!(store
            .renew(&disabled, current(), "b", || Ok(12_502))
            .is_err());
        assert!(MailboxStore::open(&path, "authority", "key", &[disabled]).is_err());
        Ok(())
    }

    #[test]
    fn lease_expiry_at_the_exact_deadline_fences_the_previous_holder(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let channel = MailboxConfig {
            id: "jobs".into(),
            limits: Default::default(),
            renewable_leases: false,
        };
        let mut store = MailboxStore::open(
            &directory.path().join("mailboxes.db"),
            "authority",
            "key",
            std::slice::from_ref(&channel),
        )?;
        store.send(
            &channel,
            Send {
                message_key: "one".into(),
                payload: json!({"job": 1}),
            },
            Some("sender"),
        )?;
        let lease = || Claim {
            limit: 1,
            lease_ms: 1000,
        };
        let first = store.claim(&channel, lease(), "worker-a", 10_000)?;
        assert_eq!(first["messages"][0]["claim"], "1");
        let before = store.claim(&channel, lease(), "worker-b", 10_999)?;
        assert_eq!(before["messages"], json!([]));
        let expired = store.claim(&channel, lease(), "worker-b", 11_000)?;
        assert_eq!(expired["messages"][0]["claim"], "2");
        assert!(matches!(
            store.complete(
                &channel,
                Complete {
                    sequence: "1".into(),
                    claim: "1".into()
                },
                "worker-a"
            ),
            Err(ProcessError::Conflict)
        ));
        store.complete(
            &channel,
            Complete {
                sequence: "1".into(),
                claim: "2".into(),
            },
            "worker-b",
        )?;
        assert_eq!(
            store.claim(&channel, lease(), "worker-c", 12_000)?["messages"],
            json!([])
        );
        Ok(())
    }
}
