//! Qualified single-host test rail. Integer fixture balances, not real money.
use super::*;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

#[derive(Clone)]
pub struct Bank {
    pub root: PathBuf,
    pub role: u8,
}

fn payment_error(error: impl std::fmt::Display) -> PaymentError {
    PaymentError::RailError(error.to_string())
}

impl Bank {
    pub fn provision(root: &Path) -> Result {
        let db = Connection::open(root.join("bank.db"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL CHECK(balance>=0));
            INSERT INTO accounts VALUES (0,0),(1,1000),(2,100),(3,0);
            CREATE TABLE holds (id TEXT PRIMARY KEY, role INTEGER NOT NULL,
                request TEXT NOT NULL, amount INTEGER NOT NULL, state TEXT NOT NULL,
                charged INTEGER NOT NULL, settlement_reference TEXT);")?;
        Ok(())
    }

    fn open(&self) -> rusqlite::Result<Connection> {
        let db = Connection::open(self.root.join("bank.db"))?;
        db.busy_timeout(Duration::from_secs(15))?;
        db.execute_batch("PRAGMA synchronous=FULL;")?;
        Ok(db)
    }

    fn payer(&self) -> u8 {
        if self.role == 2 {
            1
        } else {
            2
        }
    }

    fn settled_result(id: &str, release: bool) -> PaymentResult {
        PaymentResult {
            transaction_id: id.into(),
            settlement_status: if release {
                RailSettlementStatus::Released
            } else {
                RailSettlementStatus::Settled
            },
            metadata: json!({"localTestRail":true}),
        }
    }

    fn settle(
        &self,
        id: &str,
        charge: u64,
        reference: &str,
        release: bool,
    ) -> Result<PaymentResult> {
        let charge = i64::try_from(charge)?;
        let mut db = self.open()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (role, amount, state, charged, prior_ref): (u8, i64, String, i64, Option<String>) = tx
            .query_row(
                "SELECT role,amount,state,charged,settlement_reference FROM holds WHERE id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
        let expected = if release { "released" } else { "captured" };
        if role != self.role || charge > amount || (release && charge != 0) {
            return Err("rail settlement authority or amount mismatch".into());
        }
        if state != "held" {
            if state != expected || charged != charge || prior_ref.as_deref() != Some(reference) {
                return Err("rail terminal action substitution".into());
            }
            return Ok(Self::settled_result(id, release));
        }
        tx.execute("UPDATE accounts SET balance=balance-? WHERE id=0", [amount])?;
        tx.execute(
            "UPDATE accounts SET balance=balance+? WHERE id=?",
            params![charge, self.role],
        )?;
        tx.execute(
            "UPDATE accounts SET balance=balance+? WHERE id=?",
            params![amount - charge, self.payer()],
        )?;
        tx.execute(
            "UPDATE holds SET state=?,charged=?,settlement_reference=? WHERE id=?",
            params![expected, charge, reference, id],
        )?;
        tx.commit()?;
        Ok(Self::settled_result(id, release))
    }

    pub fn balances(root: &Path) -> Result<Vec<i64>> {
        let db = Connection::open(root.join("bank.db"))?;
        let mut query = db.prepare("SELECT balance FROM accounts ORDER BY id")?;
        let balances = query
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(balances)
    }
}

impl PaymentAdapter for Bank {
    fn rail_id(&self) -> &'static str {
        "three-owner-local-test-rail"
    }
    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> std::result::Result<PaymentAuthorization, PaymentError> {
        let authorize = || -> Result<PaymentAuthorization> {
            if request.currency != "USD" || request.amount_units > 100 {
                return Err("unsupported test rail denomination or amount".into());
            }
            let amount = i64::try_from(request.amount_units)?;
            let encoded = serde_json::to_string(request)?;
            let mut db = self.open()?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let old: Option<(u8, String)> = tx
                .query_row(
                    "SELECT role,request FROM holds WHERE id=?",
                    [&request.reference],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((role, body)) = old {
                if role != self.role || body != encoded {
                    return Err("rail authorization substitution".into());
                }
            } else {
                tx.execute(
                    "UPDATE accounts SET balance=balance-? WHERE id=?",
                    params![amount, self.payer()],
                )?;
                tx.execute("UPDATE accounts SET balance=balance+? WHERE id=0", [amount])?;
                tx.execute(
                    "INSERT INTO holds VALUES (?,?,?,?, 'held',0,NULL)",
                    params![request.reference, self.role, encoded, amount],
                )?;
            }
            tx.commit()?;
            Ok(PaymentAuthorization {
                authorization_id: request.reference.clone(),
                state: PaymentAuthorizationState::Held,
                metadata: json!({"localTestRail":true}),
            })
        };
        authorize().map_err(payment_error)
    }
    fn capture(
        &self,
        id: &str,
        amount: u64,
        currency: &str,
        reference: &str,
    ) -> std::result::Result<PaymentResult, PaymentError> {
        if currency != "USD" {
            return Err(payment_error("wrong currency"));
        }
        self.settle(id, amount, reference, false)
            .map_err(payment_error)
    }
    fn release(
        &self,
        id: &str,
        reference: &str,
    ) -> std::result::Result<PaymentResult, PaymentError> {
        self.settle(id, 0, reference, true).map_err(payment_error)
    }
    fn refund(
        &self,
        _: &str,
        _: u64,
        _: &str,
        _: &str,
    ) -> std::result::Result<PaymentResult, PaymentError> {
        Err(payment_error("test rail denies refund of earned claims"))
    }
    fn settlement_state(
        &self,
        reference: &str,
        id: Option<&str>,
    ) -> std::result::Result<RailSettlementState, PaymentError> {
        let query = || -> Result<RailSettlementState> {
            if id.is_some_and(|id| id != reference) {
                return Err("rail lookup substitution".into());
            }
            let db = self.open()?;
            let row: Option<(u8, String)> = db
                .query_row(
                    "SELECT role,state FROM holds WHERE id=?",
                    [reference],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match row {
                None => Ok(RailSettlementState::NoAuthorization),
                Some((role, _)) if role != self.role => Err("wrong rail owner".into()),
                Some((_, state)) if state == "held" => Ok(RailSettlementState::Held {
                    authorization_id: reference.into(),
                }),
                Some((_, state)) => Ok(RailSettlementState::Settled {
                    authorization_id: reference.into(),
                    result: Self::settled_result(reference, state == "released"),
                }),
            }
        };
        query().map_err(payment_error)
    }
}
