//! Durable reversible-hold payment adapter for a single-operator market.
//!
//! This adapter records local pilot credits, not external currency. Every
//! authorization and terminal action is idempotent and bound to the complete
//! payment request. It is suitable for the single-operator pilot where the
//! operator's venue ledger is the settlement rail.

use chio_security_types::clock::{Clock, SystemClock};
use std::path::Path;
use std::sync::Arc;

use chio_core::sha256_hex;
#[cfg(test)]
use chio_kernel::payment::GovernedPaymentContext;
use chio_kernel::payment::{
    PaymentAdapter, PaymentAuthorization, PaymentAuthorizationState, PaymentAuthorizeRequest,
    PaymentError, PaymentRailMode, PaymentResult, RailSettlementStatus,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

fn configure_pooled_connection(connection: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    connection.execute_batch("PRAGMA busy_timeout = 5000;")
}

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS chio_finding_operator_payments (
    authorization_id TEXT PRIMARY KEY,
    reference TEXT NOT NULL UNIQUE,
    payer TEXT NOT NULL,
    payee TEXT NOT NULL,
    amount_units INTEGER NOT NULL CHECK(amount_units > 0),
    currency TEXT NOT NULL CHECK(typeof(currency) = 'text' AND length(currency) = 3 AND instr(currency, char(0)) = 0 AND octet_length(currency) <= 12),
    governed_intent_id TEXT,
    governed_intent_hash TEXT,
    state TEXT NOT NULL CHECK(state IN ('held', 'captured', 'released', 'refunded')),
    transaction_id TEXT,
    prior_transaction_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS chio_finding_operator_payments_governed_intent
ON chio_finding_operator_payments(governed_intent_id)
WHERE governed_intent_id IS NOT NULL;
"#;
const RAIL_ID: &str = "finding-operator-ledger";
const MAX_TEXT_BYTES: usize = 512;

/// Durable local-credit settlement adapter for the operator pilot.
#[derive(Clone)]
pub struct SqliteFindingOperatorPaymentAdapter {
    clock: crate::store_clock::StoreClock,
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteFindingOperatorPaymentAdapter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        Self::open_with_clock(path, Arc::new(SystemClock))
    }

    /// Open with the time authority shared by the composing service.
    pub fn open_with_clock(path: impl AsRef<Path>, clock: Arc<dyn Clock>) -> Result<Self, String> {
        let path = path.as_ref();
        let manager = SqliteConnectionManager::file(path)
            .with_flags(rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
            .with_init(configure_pooled_connection);
        let pool = crate::pool::sqlite_pool_builder()
            .max_size(8)
            .build(manager)
            .map_err(|error| error.to_string())?;
        let store = Self {
            pool,
            clock: crate::store_clock::StoreClock::new(clock),
        };
        store.validate_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, String> {
        Self::open_in_memory_with_clock(Arc::new(SystemClock))
    }

    pub fn open_in_memory_with_clock(clock: Arc<dyn Clock>) -> Result<Self, String> {
        let manager = SqliteConnectionManager::memory().with_init(configure_pooled_connection);
        let pool = crate::pool::sqlite_pool_builder()
            .max_size(1)
            .build(manager)
            .map_err(|error| error.to_string())?;
        let store = Self {
            pool,
            clock: crate::store_clock::StoreClock::new(clock),
        };
        {
            let mut connection = store.pool.get().map_err(|error| error.to_string())?;
            crate::finding_operator_database::initialize_connection(&mut connection)
                .map_err(|error| error.to_string())?;
        }
        store.validate_schema()?;
        Ok(store)
    }

    fn validate_schema(&self) -> Result<(), String> {
        let mut connection = self.pool.get().map_err(|error| error.to_string())?;
        crate::finding_operator_database::validate_component(&mut connection)
            .map_err(|error| error.to_string())
    }

    fn authorize_durable(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, String> {
        let now = self.now_secs()?;
        validate_request(request)?;
        let authorization_id = authorization_id(request);
        let governed_intent_id = request
            .governed
            .as_ref()
            .map(|value| value.intent_id.as_str());
        let governed_intent_hash = request
            .governed
            .as_ref()
            .map(|value| value.intent_hash.as_str());
        let amount_units = i64::try_from(request.amount_units)
            .map_err(|_| "payment amount exceeds SQLite integer range".to_owned())?;
        let mut conn = self.pool.get().map_err(|error| error.to_string())?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let existing = load_by_reference(&tx, &request.reference)?;
        if let Some(existing) = existing {
            if existing.authorization_id != authorization_id
                || existing.payer != request.payer
                || existing.payee != request.payee
                || existing.amount_units != request.amount_units
                || existing.currency != request.currency
            {
                return Err("payment authorization conflicts with durable state".to_owned());
            }
            if existing.governed_intent_id.as_deref() != governed_intent_id
                || existing.governed_intent_hash.as_deref() != governed_intent_hash
            {
                return Err("payment authorization conflicts with durable state".to_owned());
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(held_authorization(existing.authorization_id, true));
        }
        tx.execute(
            r#"
            INSERT INTO chio_finding_operator_payments
                (authorization_id, reference, payer, payee, amount_units, currency,
                 governed_intent_id, governed_intent_hash, state, transaction_id,
                 prior_transaction_id, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'held', NULL, NULL, ?9, ?9)
            "#,
            params![
                authorization_id,
                request.reference,
                request.payer,
                request.payee,
                amount_units,
                request.currency,
                governed_intent_id,
                governed_intent_hash,
                now,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(held_authorization(authorization_id, false))
    }

    fn settle(
        &self,
        authorization_id: &str,
        action: SettlementAction<'_>,
    ) -> Result<PaymentResult, String> {
        let now = self.now_secs()?;
        validate_text(authorization_id, "authorization_id")?;
        let mut conn = self.pool.get().map_err(|error| error.to_string())?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let record = load_by_authorization(&tx, authorization_id)?
            .ok_or_else(|| "payment authorization was not found".to_owned())?;
        let (target_state, transaction_id, status) = match action {
            SettlementAction::Capture {
                amount_units,
                currency,
                reference,
            } => {
                if amount_units != record.amount_units
                    || currency != record.currency
                    || reference != record.reference
                {
                    return Err("capture does not bind the authorized payment".to_owned());
                }
                (
                    "captured",
                    terminal_id("capture", authorization_id),
                    RailSettlementStatus::Settled,
                )
            }
            SettlementAction::Release { reference } => {
                if reference != record.reference {
                    return Err("release does not bind the authorized payment".to_owned());
                }
                (
                    "released",
                    terminal_id("release", authorization_id),
                    RailSettlementStatus::Released,
                )
            }
            SettlementAction::Refund {
                transaction_id,
                amount_units,
                currency,
                reference,
            } => {
                let binds_capture = (record.state == "captured"
                    && record.transaction_id.as_deref() == Some(transaction_id))
                    || (record.state == "refunded"
                        && record.prior_transaction_id.as_deref() == Some(transaction_id));
                if !binds_capture
                    || amount_units != record.amount_units
                    || currency != record.currency
                    || reference != record.reference
                {
                    return Err("refund does not bind a captured payment".to_owned());
                }
                (
                    "refunded",
                    terminal_id("refund", authorization_id),
                    RailSettlementStatus::Refunded,
                )
            }
        };

        if record.state == target_state {
            if record.transaction_id.as_deref() != Some(transaction_id.as_str()) {
                return Err("payment terminal conflicts with durable state".to_owned());
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(payment_result(transaction_id, status, true));
        }
        let source_allowed = match action {
            SettlementAction::Capture { .. } | SettlementAction::Release { .. } => {
                record.state == "held"
            }
            SettlementAction::Refund { .. } => record.state == "captured",
        };
        if !source_allowed {
            return Err("payment is already in an incompatible terminal state".to_owned());
        }
        let prior_transaction_id = matches!(action, SettlementAction::Refund { .. })
            .then_some(record.transaction_id.as_deref())
            .flatten();
        tx.execute(
            r#"
            UPDATE chio_finding_operator_payments
            SET state = ?2, transaction_id = ?3, updated_at = ?4,
                prior_transaction_id = ?5
            WHERE authorization_id = ?1
            "#,
            params![
                authorization_id,
                target_state,
                transaction_id,
                now,
                prior_transaction_id,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(payment_result(transaction_id, status, false))
    }

    /// Count durable captured or subsequently refunded payments for pilot
    /// conservation checks.
    pub fn capture_count(&self) -> Result<u64, String> {
        let conn = self.pool.get().map_err(|error| error.to_string())?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chio_finding_operator_payments WHERE state IN ('captured', 'refunded')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        u64::try_from(count).map_err(|_| "payment count was negative".to_owned())
    }

    /// Release or refund any durable local-credit payment before an expired
    /// purchase reservation is closed. Replays are exact and terminal.
    pub fn reconcile_expired_reference(
        &self,
        reference: &str,
        payer: &str,
        amount_units: u64,
        currency: &str,
    ) -> Result<(), String> {
        self.now_secs()?;
        validate_reconciliation_binding(payer, amount_units, currency)?;
        validate_text(reference, "reference")?;
        let conn = self.pool.get().map_err(|error| error.to_string())?;
        let Some(record) = load_by_reference(&conn, reference)? else {
            return Ok(());
        };
        drop(conn);
        self.reconcile_record(record, payer, amount_units, currency)
    }

    /// Reconcile the payment bound to one governed cognition-market intent.
    /// A live payment that matches the intent's payer, amount and currency but
    /// carries no governed binding is refused rather than adopted.
    pub fn reconcile_expired_governed_intent(
        &self,
        governed_intent_id: &str,
        payer: &str,
        amount_units: u64,
        currency: &str,
    ) -> Result<(), String> {
        self.now_secs()?;
        validate_reconciliation_binding(payer, amount_units, currency)?;
        validate_text(governed_intent_id, "governed_intent_id")?;
        let mut conn = self.pool.get().map_err(|error| error.to_string())?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let record = load_by_governed_intent_id(&tx, governed_intent_id)?;
        if record.is_none() {
            let amount_units = i64::try_from(amount_units)
                .map_err(|_| "payment amount exceeds SQLite integer range".to_owned())?;
            let unbound_live: i64 = tx
                .query_row(
                    r#"
                    SELECT COUNT(*) FROM chio_finding_operator_payments
                    WHERE governed_intent_id IS NULL
                      AND payer = ?1 AND amount_units = ?2 AND currency = ?3
                      AND state IN ('held', 'captured')
                    "#,
                    params![payer, amount_units, currency],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if unbound_live != 0 {
                return Err(
                    "unbound live payment cannot be bound to the expired governed intent"
                        .to_owned(),
                );
            }
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(());
        }
        tx.commit().map_err(|error| error.to_string())?;
        drop(conn);
        self.reconcile_record(
            record.ok_or_else(|| "governed payment disappeared".to_owned())?,
            payer,
            amount_units,
            currency,
        )
    }

    fn reconcile_record(
        &self,
        record: PaymentRecord,
        payer: &str,
        amount_units: u64,
        currency: &str,
    ) -> Result<(), String> {
        if record.payer != payer
            || record.amount_units != amount_units
            || record.currency != currency
        {
            return Err("expired payment reconciliation conflicts with durable state".to_owned());
        }
        let reference = record.reference.clone();
        match record.state.as_str() {
            "held" => {
                self.settle(
                    &record.authorization_id,
                    SettlementAction::Release {
                        reference: &reference,
                    },
                )?;
            }
            "captured" => {
                let transaction_id = record.transaction_id.as_deref().ok_or_else(|| {
                    "captured payment omitted its durable transaction id".to_owned()
                })?;
                self.settle(
                    &record.authorization_id,
                    SettlementAction::Refund {
                        transaction_id,
                        amount_units,
                        currency,
                        reference: &reference,
                    },
                )?;
            }
            "released" | "refunded" => {}
            _ => return Err("stored payment state is unsupported".to_owned()),
        }
        Ok(())
    }

    /// Count payments refunded by recovery after a prior capture.
    pub fn refund_count(&self) -> Result<u64, String> {
        let conn = self.pool.get().map_err(|error| error.to_string())?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chio_finding_operator_payments WHERE state = 'refunded'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        u64::try_from(count).map_err(|_| "payment count was negative".to_owned())
    }
}

impl PaymentAdapter for SqliteFindingOperatorPaymentAdapter {
    fn egress_allowance_digest(&self) -> &str {
        chio_kernel::payment::EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST
    }

    fn rail_id(&self) -> &'static str {
        RAIL_ID
    }

    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.authorize_durable(request)
            .map_err(PaymentError::RailError)
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.settle(
            authorization_id,
            SettlementAction::Capture {
                amount_units,
                currency,
                reference,
            },
        )
        .map_err(PaymentError::RailError)
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.settle(authorization_id, SettlementAction::Release { reference })
            .map_err(PaymentError::RailError)
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        validate_text(transaction_id, "refund_identifier").map_err(PaymentError::RailError)?;
        let conn = self
            .pool
            .get()
            .map_err(|error| PaymentError::RailError(error.to_string()))?;
        let payment: Option<(String, String)> = conn
            .query_row(
                r#"
                SELECT authorization_id,
                       CASE WHEN state = 'refunded'
                            THEN prior_transaction_id ELSE transaction_id END
                FROM chio_finding_operator_payments
                WHERE authorization_id = ?1 OR transaction_id = ?1 OR prior_transaction_id = ?1
                "#,
                [transaction_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| PaymentError::RailError(error.to_string()))?;
        drop(conn);
        let (authorization_id, captured_transaction_id) = payment
            .ok_or_else(|| PaymentError::RailError("captured payment was not found".to_owned()))?;
        self.settle(
            &authorization_id,
            SettlementAction::Refund {
                transaction_id: &captured_transaction_id,
                amount_units,
                currency,
                reference,
            },
        )
        .map_err(PaymentError::RailError)
    }

    fn replayed_authorization_metadata(
        &self,
        authorization_id: &str,
    ) -> Result<serde_json::Value, PaymentError> {
        Ok(held_authorization(authorization_id.to_owned(), true).metadata)
    }
}

#[derive(Clone, Copy)]
enum SettlementAction<'a> {
    Capture {
        amount_units: u64,
        currency: &'a str,
        reference: &'a str,
    },
    Release {
        reference: &'a str,
    },
    Refund {
        transaction_id: &'a str,
        amount_units: u64,
        currency: &'a str,
        reference: &'a str,
    },
}

struct PaymentRecord {
    authorization_id: String,
    reference: String,
    payer: String,
    payee: String,
    amount_units: u64,
    currency: String,
    governed_intent_id: Option<String>,
    governed_intent_hash: Option<String>,
    state: String,
    transaction_id: Option<String>,
    prior_transaction_id: Option<String>,
}

fn load_by_reference(
    conn: &rusqlite::Connection,
    reference: &str,
) -> Result<Option<PaymentRecord>, String> {
    load_record(conn, "reference", reference)
}

fn load_by_authorization(
    conn: &rusqlite::Connection,
    authorization_id: &str,
) -> Result<Option<PaymentRecord>, String> {
    load_record(conn, "authorization_id", authorization_id)
}

fn load_by_governed_intent_id(
    conn: &rusqlite::Connection,
    governed_intent_id: &str,
) -> Result<Option<PaymentRecord>, String> {
    load_record(conn, "governed_intent_id", governed_intent_id)
}

fn load_record(
    conn: &rusqlite::Connection,
    column: &str,
    value: &str,
) -> Result<Option<PaymentRecord>, String> {
    let sql = format!(
        "SELECT authorization_id, reference, payer, payee, amount_units, currency, governed_intent_id, governed_intent_hash, state, transaction_id, prior_transaction_id FROM chio_finding_operator_payments WHERE {column} = ?1"
    );
    conn.query_row(&sql, [value], |row| {
        let amount_units: i64 = row.get("amount_units")?;
        Ok((
            row.get("authorization_id")?,
            row.get("reference")?,
            row.get("payer")?,
            row.get("payee")?,
            amount_units,
            row.get("currency")?,
            row.get("governed_intent_id")?,
            row.get("governed_intent_hash")?,
            row.get("state")?,
            row.get("transaction_id")?,
            row.get("prior_transaction_id")?,
        ))
    })
    .optional()
    .map_err(|error| error.to_string())?
    .map(
        |(
            authorization_id,
            reference,
            payer,
            payee,
            amount_units,
            currency,
            governed_intent_id,
            governed_intent_hash,
            state,
            transaction_id,
            prior_transaction_id,
        )| {
            Ok(PaymentRecord {
                authorization_id,
                reference,
                payer,
                payee,
                amount_units: u64::try_from(amount_units)
                    .map_err(|_| "stored payment amount was negative".to_owned())?,
                currency,
                governed_intent_id,
                governed_intent_hash,
                state,
                transaction_id,
                prior_transaction_id,
            })
        },
    )
    .transpose()
}

fn validate_request(request: &PaymentAuthorizeRequest) -> Result<(), String> {
    validate_text(&request.reference, "reference")?;
    validate_text(&request.payer, "payer")?;
    validate_text(&request.payee, "payee")?;
    if request.amount_units == 0 || request.amount_units > i64::MAX.unsigned_abs() {
        return Err("payment amount is outside the supported range".to_owned());
    }
    if request.currency.len() != 3
        || !request
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        return Err("payment currency must be three uppercase letters".to_owned());
    }
    if let Some(governed) = request.governed.as_ref() {
        validate_text(&governed.intent_id, "governed_intent_id")?;
        validate_text(&governed.intent_hash, "governed_intent_hash")?;
    }
    Ok(())
}

fn validate_reconciliation_binding(
    payer: &str,
    amount_units: u64,
    currency: &str,
) -> Result<(), String> {
    validate_text(payer, "payer")?;
    if amount_units == 0 || amount_units > i64::MAX.unsigned_abs() {
        return Err("payment amount is outside the supported range".to_owned());
    }
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err("payment currency must be three uppercase letters".to_owned());
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(format!("invalid payment {field}"));
    }
    Ok(())
}

fn authorization_id(request: &PaymentAuthorizeRequest) -> String {
    let preimage = format!(
        "chio.finding.operator-payment.v1\0{}\0{}\0{}\0{}\0{}",
        request.reference, request.payer, request.payee, request.amount_units, request.currency
    );
    format!("hold:{}", sha256_hex(preimage.as_bytes()))
}

fn terminal_id(action: &str, authorization_id: &str) -> String {
    format!(
        "{action}:{}",
        sha256_hex(format!("{action}\0{authorization_id}").as_bytes())
    )
}

fn held_authorization(authorization_id: String, replay: bool) -> PaymentAuthorization {
    PaymentAuthorization {
        authorization_id,
        state: PaymentAuthorizationState::Held,
        metadata: serde_json::json!({
            "rail": RAIL_ID,
            "localCredits": true,
            "replay": replay,
        }),
    }
}

fn payment_result(
    transaction_id: String,
    settlement_status: RailSettlementStatus,
    replay: bool,
) -> PaymentResult {
    PaymentResult {
        transaction_id,
        settlement_status,
        metadata: serde_json::json!({
            "rail": RAIL_ID,
            "localCredits": true,
            "replay": replay,
        }),
    }
}

impl SqliteFindingOperatorPaymentAdapter {
    fn now_secs(&self) -> Result<i64, String> {
        self.clock.now_secs().map_err(|error| error.to_string())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod tests {
    use super::*;

    fn request(reference: &str) -> PaymentAuthorizeRequest {
        PaymentAuthorizeRequest {
            amount_units: 25,
            currency: "USD".to_owned(),
            payer: "buyer-1".to_owned(),
            payee: "seller-1".to_owned(),
            reference: reference.to_owned(),
            governed: None,
            commerce: None,
            x402: None,
            authority_expires_at: None,
            reference_is_durable: false,
        }
    }

    fn governed_request(reference: &str, intent_id: &str) -> PaymentAuthorizeRequest {
        let mut request = request(reference);
        request.governed = Some(GovernedPaymentContext {
            intent_id: intent_id.to_owned(),
            intent_hash: "a".repeat(64),
            purpose: "purchase".to_owned(),
            server_id: "seller-1".to_owned(),
            tool_name: "read_finding".to_owned(),
            approval_token_id: None,
        });
        request
    }

    #[test]
    fn capture_is_restart_safe_and_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.db");
        crate::initialize_finding_operator_database(&path).unwrap();
        let adapter = SqliteFindingOperatorPaymentAdapter::open(&path).unwrap();
        let first = adapter.authorize(&request("purchase-1")).unwrap();
        let captured = adapter
            .capture(&first.authorization_id, 25, "USD", "purchase-1")
            .unwrap();
        drop(adapter);

        let reopened = SqliteFindingOperatorPaymentAdapter::open(&path).unwrap();
        let replayed_auth = reopened.authorize(&request("purchase-1")).unwrap();
        let replayed_capture = reopened
            .capture(&replayed_auth.authorization_id, 25, "USD", "purchase-1")
            .unwrap();
        assert_eq!(captured.transaction_id, replayed_capture.transaction_id);
        assert_eq!(reopened.capture_count().unwrap(), 1);
    }

    #[test]
    fn every_pooled_connection_has_busy_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.db");
        crate::initialize_finding_operator_database(&path).unwrap();
        let adapter = SqliteFindingOperatorPaymentAdapter::open(&path).unwrap();
        let first = adapter.pool.get().unwrap();
        let second = adapter.pool.get().unwrap();

        for connection in [&first, &second] {
            let busy_timeout = connection
                .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                .unwrap();
            assert!(busy_timeout >= 5_000);
        }
    }

    #[test]
    fn durable_replay_metadata_matches_an_authorization_replay() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let first = adapter.authorize(&request("purchase-replay")).unwrap();
        let replay = adapter.authorize(&request("purchase-replay")).unwrap();
        assert_eq!(replay.metadata["replay"], true);
        assert_eq!(
            adapter
                .replayed_authorization_metadata(&first.authorization_id)
                .unwrap(),
            replay.metadata
        );
    }

    #[test]
    fn release_and_capture_are_mutually_exclusive() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let authorization = adapter.authorize(&request("purchase-2")).unwrap();
        let released = adapter
            .release(&authorization.authorization_id, "purchase-2")
            .unwrap();
        assert_eq!(released.settlement_status, RailSettlementStatus::Released);
        assert!(adapter
            .capture(&authorization.authorization_id, 25, "USD", "purchase-2")
            .is_err());
        assert_eq!(adapter.capture_count().unwrap(), 0);
    }

    #[test]
    fn changed_authorization_replay_is_rejected() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        adapter.authorize(&request("purchase-3")).unwrap();
        let mut changed = request("purchase-3");
        changed.amount_units = 26;
        assert!(adapter.authorize(&changed).is_err());
    }

    #[test]
    fn refund_accepts_capture_or_authorization_id_and_replays_exactly() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let authorization = adapter.authorize(&request("purchase-refund")).unwrap();
        let captured = adapter
            .capture(
                &authorization.authorization_id,
                25,
                "USD",
                "purchase-refund",
            )
            .unwrap();
        let refunded = adapter
            .refund(
                &authorization.authorization_id,
                25,
                "USD",
                "purchase-refund",
            )
            .unwrap();
        let replayed = adapter
            .refund(&captured.transaction_id, 25, "USD", "purchase-refund")
            .unwrap();
        let replayed_by_refund = adapter
            .refund(&refunded.transaction_id, 25, "USD", "purchase-refund")
            .unwrap();
        assert_eq!(refunded.transaction_id, replayed.transaction_id);
        assert_eq!(refunded.transaction_id, replayed_by_refund.transaction_id);
        assert_eq!(
            replayed_by_refund.settlement_status,
            RailSettlementStatus::Refunded
        );
    }

    #[test]
    fn refund_rejects_changed_payment_inputs() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let authorization = adapter.authorize(&request("purchase-refund-bind")).unwrap();
        let captured = adapter
            .capture(
                &authorization.authorization_id,
                25,
                "USD",
                "purchase-refund-bind",
            )
            .unwrap();
        assert!(adapter
            .refund(&captured.transaction_id, 26, "USD", "purchase-refund-bind",)
            .is_err());
    }

    #[test]
    fn expired_reconciliation_releases_a_hold_exactly_once() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let authorization = adapter
            .authorize(&request("purchase-expired-hold"))
            .unwrap();
        adapter
            .reconcile_expired_reference("purchase-expired-hold", "buyer-1", 25, "USD")
            .unwrap();
        adapter
            .reconcile_expired_reference("purchase-expired-hold", "buyer-1", 25, "USD")
            .unwrap();
        assert!(adapter
            .capture(
                &authorization.authorization_id,
                25,
                "USD",
                "purchase-expired-hold",
            )
            .is_err());
        assert_eq!(adapter.capture_count().unwrap(), 0);
    }

    #[test]
    fn expired_reconciliation_refunds_a_capture_exactly_once() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let authorization = adapter
            .authorize(&request("purchase-expired-capture"))
            .unwrap();
        adapter
            .capture(
                &authorization.authorization_id,
                25,
                "USD",
                "purchase-expired-capture",
            )
            .unwrap();
        adapter
            .reconcile_expired_reference("purchase-expired-capture", "buyer-1", 25, "USD")
            .unwrap();
        adapter
            .reconcile_expired_reference("purchase-expired-capture", "buyer-1", 25, "USD")
            .unwrap();
        assert_eq!(adapter.capture_count().unwrap(), 1);
        assert_eq!(adapter.refund_count().unwrap(), 1);
    }

    #[test]
    fn expired_governed_intent_selects_the_exact_capture() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let request = governed_request("durable-operation-1", "intent-request-1");
        let authorization = adapter.authorize(&request).unwrap();
        adapter
            .capture(
                &authorization.authorization_id,
                25,
                "USD",
                "durable-operation-1",
            )
            .unwrap();
        adapter
            .reconcile_expired_governed_intent("intent-request-1", "buyer-1", 25, "USD")
            .unwrap();
        assert_eq!(adapter.capture_count().unwrap(), 1);
        assert_eq!(adapter.refund_count().unwrap(), 1);
    }

    #[test]
    fn replay_cannot_attach_a_governed_binding_to_an_unbound_authorization() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let unbound = request("durable-operation-unbound");
        adapter.authorize(&unbound).unwrap();
        let governed = governed_request("durable-operation-unbound", "intent-request-unbound");
        assert!(matches!(
            adapter.authorize(&governed),
            Err(PaymentError::RailError(message))
                if message == "payment authorization conflicts with durable state"
        ));
    }

    #[test]
    fn expired_governed_intent_refuses_an_unbound_live_payment() {
        let adapter = SqliteFindingOperatorPaymentAdapter::open_in_memory().unwrap();
        let unbound = request("durable-operation-unbound-live");
        adapter.authorize(&unbound).unwrap();
        assert_eq!(
            adapter
                .reconcile_expired_governed_intent("intent-request-unbound", "buyer-1", 25, "USD")
                .unwrap_err(),
            "unbound live payment cannot be bound to the expired governed intent"
        );
        assert_eq!(adapter.capture_count().unwrap(), 0);
    }

    #[test]
    fn payment_schema_other_than_current_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.db");
        crate::initialize_finding_operator_database(&path).unwrap();
        drop(SqliteFindingOperatorPaymentAdapter::open(&path).unwrap());
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA ignore_check_constraints = ON;
            UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = 'finding_operator_payment';
            PRAGMA ignore_check_constraints = OFF;").unwrap();
        drop(conn);
        assert_eq!(
            SqliteFindingOperatorPaymentAdapter::open(&path)
                .err()
                .unwrap(),
            "database schema version 0 is not the current schema version 1; refusing to open"
        );
    }

    #[test]
    fn current_stamp_over_a_retired_payment_table_shape_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.db");
        crate::initialize_finding_operator_database(&path).unwrap();
        drop(SqliteFindingOperatorPaymentAdapter::open(&path).unwrap());
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("DROP INDEX chio_finding_operator_payments_governed_intent;")
            .unwrap();
        drop(conn);
        assert_eq!(
            SqliteFindingOperatorPaymentAdapter::open(&path)
                .err()
                .unwrap(),
            "schema catalog differs from its canonical definition"
        );
        let conn = rusqlite::Connection::open(&path).unwrap();
        let restored: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema \
                 WHERE name = 'chio_finding_operator_payments_governed_intent'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(restored, 0, "a refused store is not repaired");
    }
}
