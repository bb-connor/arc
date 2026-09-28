//! Durable delivery leases for signed finding-pool mutation receipts.

use chio_security_types::clock::{Clock, ClockError, ClockFence, MonotonicInstant};
use std::sync::{Arc, Mutex};

use chio_core::receipt::body::ChioReceipt;
use chio_kernel::finding_pool::FindingPoolLedgerError;
use rusqlite::{params, OptionalExtension};

use super::{invariant, SqliteFindingPoolLedger};

pub(super) struct OutboxLeaseClock {
    pub(super) epoch: u64,
    clock: Arc<dyn Clock>,
    state: Mutex<OutboxLeaseClockState>,
}
#[derive(Default)]
struct OutboxLeaseClockState {
    origin: Option<(u64, MonotonicInstant)>,
    fence: ClockFence,
    high_water_unix_ms: u64,
}
impl OutboxLeaseClock {
    pub(super) fn new(epoch: u64, clock: Arc<dyn Clock>) -> Self {
        Self {
            epoch,
            clock,
            state: Mutex::new(OutboxLeaseClockState::default()),
        }
    }

    /// The epoch sample comes from the qualified ledger caller. Local elapsed
    /// time can advance a lease despite a stalled caller sample, but a broken
    /// clock never becomes a fabricated timestamp. High-water is process-local;
    /// the durable lease epoch fences old workers after restart.
    pub(super) fn nondecreasing_now(
        &self,
        observed_unix_ms: u64,
    ) -> Result<u64, FindingPoolLedgerError> {
        let mut state = self.state.lock().map_err(|_| ClockError::Unavailable)?;
        let reading = state.fence.observe(self.clock.read()?)?;
        let (origin_unix_ms, origin_monotonic) = state
            .origin
            .unwrap_or((observed_unix_ms, reading.monotonic()));
        let elapsed_ms = u64::try_from(
            reading
                .monotonic()
                .duration_since(origin_monotonic)?
                .as_millis(),
        )
        .map_err(|_| ClockError::Overflow)?;
        let monotonic_now = origin_unix_ms
            .checked_add(elapsed_ms)
            .ok_or(ClockError::Overflow)?;
        // Retaining a high-water when a trusted caller repeats an older sample
        // cannot extend an existing lease. Lease expiry is never recalculated.
        let candidate = observed_unix_ms
            .max(monotonic_now)
            .max(state.high_water_unix_ms);
        state.origin = Some((origin_unix_ms, origin_monotonic));
        state.high_water_unix_ms = candidate;
        Ok(candidate)
    }
}

pub(super) fn advance_outbox_lease_epoch(
    connection: &rusqlite::Connection,
) -> Result<u64, FindingPoolLedgerError> {
    let current = connection
        .query_row(
            "SELECT outbox_lease_epoch FROM finding_pool_ledger_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let next = current
        .checked_add(1)
        .filter(|next| *next > 0)
        .ok_or_else(|| invariant("mutation receipt lease epoch overflowed"))?;
    let changed = connection
        .execute(
            "UPDATE finding_pool_ledger_metadata SET outbox_lease_epoch = ?1 \
             WHERE singleton = 1 AND outbox_lease_epoch = ?2",
            params![next, current],
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if changed != 1 {
        return Err(invariant(
            "mutation receipt lease epoch compare-and-set failed",
        ));
    }
    u64::try_from(next).map_err(|_| invariant("mutation receipt lease epoch is negative"))
}

pub(super) fn claim_pending_mutation_receipts(
    ledger: &SqliteFindingPoolLedger,
    claimant_id: &str,
    claimed_at_unix_ms: u64,
    lease_ms: u64,
    limit: usize,
) -> Result<Vec<ChioReceipt>, FindingPoolLedgerError> {
    if claimant_id.is_empty() || claimant_id.len() > 128 || lease_ms == 0 || limit == 0 {
        return Err(FindingPoolLedgerError::Receipt(
            "mutation receipt delivery claim is invalid".to_owned(),
        ));
    }
    let claimed_at_unix_ms = ledger
        .outbox_lease_clock
        .nondecreasing_now(claimed_at_unix_ms)?;
    let claimed_at = i64::try_from(claimed_at_unix_ms).map_err(|_| {
        FindingPoolLedgerError::Receipt("mutation receipt claim time is invalid".to_owned())
    })?;
    let claim_expires = claimed_at_unix_ms
        .checked_add(lease_ms)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(ClockError::Overflow)?;
    let limit = i64::try_from(limit).map_err(|_| {
        FindingPoolLedgerError::Receipt("mutation receipt claim limit is invalid".to_owned())
    })?;
    let mut connection = ledger.connection()?;
    let transaction = ledger.transaction(&mut connection)?;
    let lease_epoch = i64::try_from(ledger.outbox_lease_clock.epoch).map_err(|_| {
        FindingPoolLedgerError::Receipt("mutation receipt lease epoch is invalid".to_owned())
    })?;
    let current_epoch = transaction
        .query_row(
            "SELECT outbox_lease_epoch FROM finding_pool_ledger_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if current_epoch != lease_epoch {
        return Err(FindingPoolLedgerError::Receipt(
            "mutation receipt lease epoch is stale".to_owned(),
        ));
    }
    let mut statement = transaction
        .prepare(
            "SELECT candidate.receipt_id, candidate.signed_receipt_json \
             FROM finding_pool_receipt_outbox AS candidate \
             WHERE candidate.acknowledged_at_unix_ms IS NULL \
               AND (candidate.delivery_claim_epoch IS NULL \
                    OR candidate.delivery_claim_epoch < ?1 \
                    OR (candidate.delivery_claim_epoch = ?1 \
                        AND (candidate.delivery_claim_expires_at_unix_ms IS NULL \
                             OR candidate.delivery_claim_expires_at_unix_ms <= ?2))) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM finding_pool_receipt_outbox AS predecessor \
                   WHERE predecessor.acknowledged_at_unix_ms IS NULL \
                     AND predecessor.delivery_sequence < candidate.delivery_sequence \
                     AND predecessor.delivery_claim_epoch IS NOT NULL \
                     AND (predecessor.delivery_claim_epoch > ?1 \
                          OR (predecessor.delivery_claim_epoch = ?1 \
                              AND predecessor.delivery_claim_expires_at_unix_ms > ?2)) \
               ) \
             ORDER BY candidate.delivery_sequence LIMIT ?3",
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let mut rows = statement
        .query(params![lease_epoch, claimed_at, limit])
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let mut receipts = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
    {
        let receipt_id = row
            .get::<_, String>(0)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let receipt_json = row
            .get::<_, String>(1)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let receipt: ChioReceipt = serde_json::from_str(&receipt_json)
            .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))?;
        if receipt.id != receipt_id {
            return Err(FindingPoolLedgerError::Receipt(
                "stored receipt id does not match its signed body".to_string(),
            ));
        }
        let signature_valid = receipt
            .verify_signature()
            .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))?;
        if !signature_valid {
            return Err(FindingPoolLedgerError::Receipt(
                "stored mutation receipt signature is invalid".to_string(),
            ));
        }
        receipts.push(receipt);
    }
    drop(rows);
    drop(statement);
    for receipt in &receipts {
        let changed = transaction
            .execute(
                "UPDATE finding_pool_receipt_outbox \
                 SET delivery_claim_owner = ?2, delivery_claim_expires_at_unix_ms = ?3, \
                     delivery_claim_epoch = ?4 \
                 WHERE receipt_id = ?1 AND acknowledged_at_unix_ms IS NULL \
                   AND (delivery_claim_epoch IS NULL \
                        OR delivery_claim_epoch < ?4 \
                        OR (delivery_claim_epoch = ?4 \
                            AND (delivery_claim_expires_at_unix_ms IS NULL \
                                 OR delivery_claim_expires_at_unix_ms <= ?5)))",
                params![
                    receipt.id,
                    claimant_id,
                    claim_expires,
                    lease_epoch,
                    claimed_at
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(FindingPoolLedgerError::Receipt(
                "mutation receipt delivery claim lost its compare-and-set".to_owned(),
            ));
        }
    }
    transaction
        .commit()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    Ok(receipts)
}

pub(super) fn acknowledge_mutation_receipt(
    ledger: &SqliteFindingPoolLedger,
    receipt_id: &str,
    claimant_id: &str,
    acknowledged_at_unix_ms: u64,
) -> Result<(), FindingPoolLedgerError> {
    let mut connection = ledger.connection()?;
    let transaction = ledger.transaction(&mut connection)?;
    let changed = transaction
        .execute(
            "UPDATE finding_pool_receipt_outbox \
             SET acknowledged_at_unix_ms = ?2 \
             WHERE receipt_id = ?1 AND acknowledged_at_unix_ms IS NULL \
               AND delivery_claim_owner = ?3",
            params![receipt_id, acknowledged_at_unix_ms.to_string(), claimant_id],
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if changed == 1 {
        transaction.commit()?;
        return Ok(());
    }
    let state = transaction
        .query_row(
            "SELECT acknowledged_at_unix_ms, delivery_claim_owner \
             FROM finding_pool_receipt_outbox WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .optional()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let result = match state {
        Some((Some(_), _)) => Ok(()),
        Some((None, owner)) if owner.as_deref() != Some(claimant_id) => {
            Err(FindingPoolLedgerError::Receipt(
                "cannot acknowledge a mutation receipt claimed by another worker".to_owned(),
            ))
        }
        Some((None, _)) => Err(FindingPoolLedgerError::Receipt(
            "mutation receipt acknowledgment compare-and-set failed".to_owned(),
        )),
        None => Err(FindingPoolLedgerError::Receipt(
            "cannot acknowledge an unknown mutation receipt".to_owned(),
        )),
    };
    if result.is_ok() {
        transaction.commit()?;
    }
    result
}

pub(super) fn has_pending_mutation_receipts(
    ledger: &SqliteFindingPoolLedger,
) -> Result<bool, FindingPoolLedgerError> {
    let connection = ledger.connection()?;
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM finding_pool_receipt_outbox \
             WHERE acknowledged_at_unix_ms IS NULL)",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))
}
