use std::collections::BTreeSet;
use std::sync::Arc;

use chio_core::canonical::canonical_json_bytes;
use chio_security_types::ports::{AlertDeliveryStatus, PortError, PortResult, SecurityAlert};
use chio_siem::AlertBackend;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::super::{
    load_backend_records, load_status, parked_at_unix_ms, retry_delay, sqlite_time,
    verify_backend_table, AlertOutboxBacklog, AlertOutboxConfig, OutboxRow, BACKEND_DELIVERY_TABLE,
    OUTBOX_TABLE,
};

pub(in super::super) fn ensure_ready(connection: &Connection) -> PortResult<()> {
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| PortError::unavailable())?;
    if quick_check != "ok" {
        return Err(PortError::integrity_failure());
    }
    let exists: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [OUTBOX_TABLE],
            |row| row.get(0),
        )
        .map_err(|_| PortError::unavailable())?;
    if !verify_backend_table(connection)? || exists != 1 {
        return Err(PortError::unavailable());
    }
    Ok(())
}

pub(in super::super) fn backlog(
    connection: &Connection,
    config: AlertOutboxConfig,
) -> PortResult<AlertOutboxBacklog> {
    let max_attempts = i64::from(config.max_attempts);
    let parked_at = sqlite_time(parked_at_unix_ms()?)?;
    let (pending, parked): (i64, i64) = connection
        .query_row(
            &format!(
                "SELECT
                    COALESCE(SUM(CASE WHEN attempts < ?1
                                       AND next_attempt_at_unix_ms <> ?2
                                      THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN attempts >= ?1
                                        OR next_attempt_at_unix_ms = ?2
                                      THEN 1 ELSE 0 END), 0)
                 FROM {OUTBOX_TABLE}
                 WHERE status = 'pending'"
            ),
            params![max_attempts, parked_at],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| PortError::unavailable())?;
    Ok(AlertOutboxBacklog {
        pending: u64::try_from(pending).map_err(|_| PortError::integrity_failure())?,
        parked: u64::try_from(parked).map_err(|_| PortError::integrity_failure())?,
    })
}

pub(in super::super) fn load_confirmed_backends(
    connection: &Connection,
    row: &OutboxRow,
) -> PortResult<BTreeSet<String>> {
    let records = load_backend_records(
        connection,
        row.alert.idempotency_key.as_str(),
        &row.command_hash,
    )?;
    Ok(records
        .into_iter()
        .filter_map(|(backend, record)| record.delivered_at_unix_ms.map(|_| backend))
        .collect())
}

pub(in super::super) fn record_backend_outcome(
    connection: &mut Connection,
    row: &OutboxRow,
    backend: &str,
    accepted: bool,
    now_unix_ms: u64,
) -> PortResult<()> {
    let delivered_at = if accepted {
        Some(sqlite_time(now_unix_ms)?)
    } else {
        None
    };
    let status = if accepted { "delivered" } else { "pending" };
    let idempotency_key = row.alert.idempotency_key.as_str();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| PortError::unavailable())?;
    let row_attempts: Option<i64> = transaction
        .query_row(
            &format!(
                "SELECT attempts FROM {OUTBOX_TABLE}
                 WHERE idempotency_key = ?1 AND command_hash = ?2 AND status = 'pending'"
            ),
            params![idempotency_key, row.command_hash.as_slice()],
            |stored| stored.get(0),
        )
        .optional()
        .map_err(|_| PortError::unavailable())?;
    if row_attempts != Some(i64::from(row.attempts)) {
        return Err(PortError::integrity_failure());
    }
    let records = load_backend_records(&transaction, idempotency_key, &row.command_hash)?;
    let changed = match records.get(backend) {
        None => transaction
            .execute(
                &format!(
                    "INSERT INTO {BACKEND_DELIVERY_TABLE}
                     (idempotency_key, backend_name, command_hash, status, attempts,
                      delivered_at_unix_ms)
                     VALUES (?1, ?2, ?3, ?4, 1, ?5)"
                ),
                params![
                    idempotency_key,
                    backend,
                    row.command_hash.as_slice(),
                    status,
                    delivered_at
                ],
            )
            .map_err(|_| PortError::unavailable())?,
        Some(previous) if previous.delivered_at_unix_ms.is_none() => {
            let attempts = previous
                .attempts
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?;
            transaction
                .execute(
                    &format!(
                        "UPDATE {BACKEND_DELIVERY_TABLE}
                         SET status = ?1, attempts = ?2, delivered_at_unix_ms = ?3
                         WHERE idempotency_key = ?4 AND backend_name = ?5
                           AND command_hash = ?6 AND status = 'pending' AND attempts = ?7"
                    ),
                    params![
                        status,
                        i64::from(attempts),
                        delivered_at,
                        idempotency_key,
                        backend,
                        row.command_hash.as_slice(),
                        i64::from(previous.attempts)
                    ],
                )
                .map_err(|_| PortError::unavailable())?
        }
        Some(_) => return Err(PortError::integrity_failure()),
    };
    if changed != 1 {
        return Err(PortError::integrity_failure());
    }
    transaction.commit().map_err(|_| PortError::unavailable())
}

pub(in super::super) fn load_due(
    connection: &Connection,
    config: AlertOutboxConfig,
    now_unix_ms: u64,
    limit: usize,
) -> PortResult<Vec<OutboxRow>> {
    let now = sqlite_time(now_unix_ms)?;
    let limit = i64::try_from(limit).map_err(|_| PortError::invalid_data())?;
    let attempts = i64::from(config.max_attempts);
    let mut statement = connection
        .prepare(&format!(
            "SELECT command_json, command_hash, attempts
             FROM {OUTBOX_TABLE}
             WHERE status = 'pending'
               AND next_attempt_at_unix_ms <= ?1
               AND attempts < ?2
             ORDER BY next_attempt_at_unix_ms, idempotency_key
             LIMIT ?3"
        ))
        .map_err(|_| PortError::unavailable())?;
    let mut rows = statement
        .query(params![now, attempts, limit])
        .map_err(|_| PortError::unavailable())?;
    let mut due = Vec::new();
    while let Some(row) = rows.next().map_err(|_| PortError::unavailable())? {
        let command_json: Vec<u8> = row.get(0).map_err(|_| PortError::invalid_data())?;
        let command_hash: Vec<u8> = row.get(1).map_err(|_| PortError::invalid_data())?;
        let attempts: i64 = row.get(2).map_err(|_| PortError::invalid_data())?;
        let alert: SecurityAlert =
            chio_core::canonical::UntrustedJsonText::from_wire(&command_json, 64 * 1024 * 1024)
                .and_then(|input| input.decode_signed())
                .map_err(|error| {
                    PortError::with_source(
                        chio_security_types::ports::PortErrorKind::InvalidData,
                        error.code(),
                        error,
                    )
                })?;
        let canonical = canonical_json_bytes(&alert).map_err(|_| PortError::invalid_data())?;
        let actual_hash = chio_core::sha256(&canonical);
        if canonical != command_json || actual_hash.as_bytes().as_slice() != command_hash {
            return Err(PortError::integrity_failure());
        }
        due.push(OutboxRow {
            alert,
            command_hash: actual_hash.as_bytes().to_vec(),
            attempts: u32::try_from(attempts).map_err(|_| PortError::integrity_failure())?,
        });
    }
    Ok(due)
}

pub(in super::super) fn record_failure(
    connection: &Connection,
    config: AlertOutboxConfig,
    row: &OutboxRow,
    now_unix_ms: u64,
) -> PortResult<bool> {
    let attempts = row
        .attempts
        .checked_add(1)
        .ok_or_else(PortError::integrity_failure)?;
    if attempts > config.max_attempts {
        return Err(PortError::integrity_failure());
    }
    let parked = attempts == config.max_attempts;
    let next_attempt_at_unix_ms = if parked {
        parked_at_unix_ms()?
    } else {
        now_unix_ms
            .checked_add(retry_delay(config, attempts))
            .ok_or_else(PortError::integrity_failure)?
    };
    let canonical = canonical_json_bytes(&row.alert).map_err(|_| PortError::invalid_data())?;
    let changed = connection
        .execute(
            &format!(
                "UPDATE {OUTBOX_TABLE}
                 SET attempts = ?1, next_attempt_at_unix_ms = ?2
                 WHERE idempotency_key = ?3 AND command_hash = ?4
                   AND status = 'pending' AND attempts = ?5"
            ),
            params![
                i64::from(attempts),
                sqlite_time(next_attempt_at_unix_ms)?,
                row.alert.idempotency_key.as_str(),
                row.command_hash.as_slice(),
                i64::from(row.attempts)
            ],
        )
        .map_err(|_| PortError::unavailable())?;
    if changed != 1 {
        return Err(PortError::integrity_failure());
    }
    let expected = AlertDeliveryStatus::Pending {
        attempts,
        next_attempt_at_unix_ms,
    };
    if load_status(
        connection,
        row.alert.idempotency_key.as_str(),
        &canonical,
        &row.command_hash,
    )? != Some(expected)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(parked)
}

pub(in super::super) fn record_delivery(
    connection: &mut Connection,
    config: AlertOutboxConfig,
    backends: &[Arc<dyn AlertBackend>],
    row: &OutboxRow,
    now_unix_ms: u64,
) -> PortResult<()> {
    let attempts = row
        .attempts
        .checked_add(1)
        .ok_or_else(PortError::integrity_failure)?;
    if attempts > config.max_attempts {
        return Err(PortError::integrity_failure());
    }
    let canonical = canonical_json_bytes(&row.alert).map_err(|_| PortError::invalid_data())?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| PortError::unavailable())?;
    let records = load_backend_records(
        &transaction,
        row.alert.idempotency_key.as_str(),
        &row.command_hash,
    )?;
    let unconfirmed = backends.iter().any(|backend| {
        records
            .get(backend.name())
            .is_none_or(|record| record.delivered_at_unix_ms.is_none())
    });
    if unconfirmed {
        return Err(PortError::integrity_failure());
    }
    let changed = transaction
        .execute(
            &format!(
                "UPDATE {OUTBOX_TABLE}
                 SET status = 'delivered', attempts = ?1, delivered_at_unix_ms = ?2
                 WHERE idempotency_key = ?3 AND command_hash = ?4
                   AND status = 'pending' AND attempts = ?5"
            ),
            params![
                i64::from(attempts),
                sqlite_time(now_unix_ms)?,
                row.alert.idempotency_key.as_str(),
                row.command_hash.as_slice(),
                i64::from(row.attempts)
            ],
        )
        .map_err(|_| PortError::unavailable())?;
    if changed != 1 {
        return Err(PortError::integrity_failure());
    }
    let expected = AlertDeliveryStatus::Delivered {
        attempts,
        delivered_at_unix_ms: now_unix_ms,
    };
    if load_status(
        &transaction,
        row.alert.idempotency_key.as_str(),
        &canonical,
        &row.command_hash,
    )? != Some(expected)
    {
        return Err(PortError::integrity_failure());
    }
    transaction.commit().map_err(|_| PortError::unavailable())
}
