use crate::{
    buyer,
    common::*,
    market::Acceptance,
    provider,
    review::{self, ReviewRequest},
};
use chio_core_types::{capability::token::CapabilityToken, Keypair};
use chio_kernel::{
    dpop::{DpopProof, DpopProofBody, DPOP_SCHEMA},
    ToolServerConnection,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::{fs, io::Read, path::Path};

pub fn request(state: &Path, url: &str, args: Value, sign: bool) -> Result<Value> {
    let work: ReviewRequest = serde_json::from_value(args.clone())?;
    let cap: CapabilityToken = work.acceptance.ask.body.token_offer.clone();
    let identity = key(state)?;
    let proof = if sign {
        Some(DpopProof::sign(
            DpopProofBody {
                schema: DPOP_SCHEMA.into(),
                replay_authority: None,
                capability_id: cap.id.clone(),
                tool_server: SERVER.into(),
                tool_name: "review".into(),
                action_hash: digest(&args)?,
                nonce: Keypair::generate().public_key().to_hex(),
                issued_at: now()?,
                agent_key: identity.public_key(),
            },
            &identity,
        )?)
    } else {
        None
    };
    let client = provider::client_authorized(state, url, &cap, proof.as_ref())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let output = runtime.block_on(client.invoke("review", json!({"data":args}), None))?;
    buyer::verify_receipt(
        &output,
        &work.acceptance.quote.agreement.provider,
        "review",
        &args,
    )?;
    Ok(output)
}

pub fn run(state: &Path, url: &str, crash_after_check: bool) -> Result<Value> {
    let accepted = buyer::run(state, url, false)?;
    let agreement: Agreement = read(state.join("agreement.json"))?;
    let job = accepted["jobs"]
        .as_array()
        .ok_or("missing buyer jobs")?
        .iter()
        .find(|job| job["job"] == agreement.job_id)
        .ok_or("accepted job is absent")?;
    let a: Acceptance = serde_json::from_value(job["acceptance"].clone())?;
    let peers: Peers = read(state.join("peers.json"))?;
    let mut bytes = Vec::new();
    fs::File::open(state.join("input.json"))?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let work = ReviewRequest {
        acceptance: a,
        input: String::from_utf8(bytes)?,
    };
    work.validate(&peers)?;
    work.report()?;
    let job = &work.acceptance.quote.agreement.job_id;
    let mut db = Connection::open(state.join("buyer.sqlite"))?;
    db.execute_batch("PRAGMA busy_timeout=5000;PRAGMA synchronous=FULL;")?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let previous: Option<String> = tx
        .query_row("SELECT request FROM work_jobs WHERE job=?", [job], |r| {
            r.get(0)
        })
        .optional()?;
    if let Some(previous) = previous {
        if digest(&serde_json::from_str::<ReviewRequest>(&previous)?)? != digest(&work)? {
            return Err("work attempt binds a different input".into());
        }
    } else {
        tx.execute(
            "INSERT INTO work_jobs(job,request,state) VALUES(?,?,'prepared')",
            params![job, serde_json::to_string(&work)?],
        )?;
    }
    let (phase, delivery): (String, Option<String>) = tx.query_row(
        "SELECT state,delivery FROM work_jobs WHERE job=?",
        [job],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if phase == "prepared" {
        tx.execute("UPDATE work_jobs SET state='attempted' WHERE job=?", [job])?;
    }
    tx.commit()?;
    if let Some(encoded) = delivery {
        let delivery: Value = serde_json::from_str(&encoded)?;
        let (rejected, _) = review::verify_terminal(&work, &delivery)?;
        return summary(&db, &work, delivery, rejected);
    }
    if phase == "prepared" {
        let output = request(state, url, serde_json::to_value(&work)?, true)?;
        let receipt =
            serde_json::from_value(output["task"]["metadata"]["chio"]["receipt"].clone())?;
        if !review::is_rejection_receipt(&receipt) {
            let report = review::decode(&buyer::payload(output)?)?;
            review::verify_report(&work, &report)?;
        }
    }
    // Recovery asks for a retained deliverable. It never replays the review.
    let output = buyer::request(
        state,
        url,
        "delivery",
        serde_json::to_value(&work.acceptance)?,
    )?;
    let delivery = buyer::payload(output)?;
    let (rejected, receipt_id) = review::verify_terminal(&work, &delivery)?;
    if crash_after_check {
        crash()?;
    }
    commit_terminal(&mut db, job, &delivery, rejected, &receipt_id)?;
    summary(&db, &work, delivery, rejected)
}

fn commit_terminal(
    db: &mut Connection,
    job: &str,
    delivery: &Value,
    rejected: bool,
    receipt_id: &str,
) -> Result<()> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let retained: Option<String> =
        tx.query_row("SELECT delivery FROM work_jobs WHERE job=?", [job], |r| {
            r.get(0)
        })?;
    if let Some(retained) = retained {
        if digest(&serde_json::from_str::<Value>(&retained)?)? != digest(delivery)? {
            return Err("verified terminal conflicts with the retained job outcome".into());
        }
        tx.commit()?;
        return Ok(());
    }
    // The write lock covers the terminal choice and both accounting branches.
    // A different job reusing a receipt id is an error, not an ignored insert.
    let reused: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM expenses WHERE receipt_id=?1 UNION ALL SELECT 1 FROM released_reservations WHERE receipt_id=?1)",
        [receipt_id], |r| r.get(0),
    )?;
    if reused {
        return Err("terminal receipt id was already used by another job".into());
    }
    if rejected {
        tx.execute(
            "INSERT INTO released_reservations(job,receipt_id) VALUES(?,?)",
            params![job, receipt_id],
        )?;
        tx.execute("UPDATE account SET available=available+100 WHERE id=1", [])?;
    } else {
        tx.execute(
            "INSERT INTO expenses(job,amount,receipt_id) VALUES(?,100,?)",
            params![job, receipt_id],
        )?;
    }
    tx.execute(
        "UPDATE work_jobs SET state='verified',delivery=? WHERE job=?",
        params![serde_json::to_string(delivery)?, job],
    )?;
    tx.commit()?;
    Ok(())
}

fn summary(
    db: &Connection,
    work: &ReviewRequest,
    delivery: Value,
    rejected: bool,
) -> Result<Value> {
    let available: i64 =
        db.query_row("SELECT available FROM account WHERE id=1", [], |r| r.get(0))?;
    let spent: i64 = db.query_row("SELECT COALESCE(SUM(amount),0) FROM expenses", [], |r| {
        r.get(0)
    })?;
    let reserved:i64=db.query_row("SELECT COALESCE(SUM(r.amount),0) FROM reservations r LEFT JOIN expenses e ON r.job=e.job LEFT JOIN released_reservations z ON r.job=z.job WHERE e.job IS NULL AND z.job IS NULL",[],|r|r.get(0))?;
    Ok(
        json!({"reviewRejected":rejected,"workExecuted":true,"buyerVerified":true,"localCreditSettled":true,"externalFundsTransferred":false,
        "creditProfile":work.acceptance.quote.agreement.credit_profile,"available":available,"reserved":reserved,"spent":spent,
        "request":work,"delivery":delivery}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflicting_verified_terminals_cannot_change_the_first_accounting_choice() -> Result<()> {
        for rejected in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "chio-terminal-{}",
                Keypair::generate().public_key().to_hex()
            ));
            init(&root)?;
            let result = (|| -> Result<()> {
                let mut db = buyer::open(&root)?;
                db.execute("UPDATE account SET available=900 WHERE id=1", [])?;
                db.execute(
                    "INSERT INTO work_jobs(job,request,state) VALUES('job','{}','attempted')",
                    [],
                )?;
                let first = json!({"terminal":if rejected {"rejected"} else {"accepted"}});
                let second = json!({"terminal":if rejected {"accepted"} else {"rejected"}});
                commit_terminal(&mut db, "job", &first, rejected, "receipt-first")?;
                commit_terminal(&mut db, "job", &first, rejected, "receipt-first")?;
                assert!(
                    commit_terminal(&mut db, "job", &second, !rejected, "receipt-conflict")
                        .is_err()
                );
                let available: i64 =
                    db.query_row("SELECT available FROM account", [], |r| r.get(0))?;
                db.execute(
                    "INSERT INTO work_jobs(job,request,state) VALUES('other-job','{}','attempted')",
                    [],
                )?;
                assert!(
                    commit_terminal(&mut db, "other-job", &second, !rejected, "receipt-first")
                        .is_err()
                );
                let after_conflict: i64 =
                    db.query_row("SELECT available FROM account", [], |r| r.get(0))?;
                assert_eq!(after_conflict, available);
                let expenses: i64 =
                    db.query_row("SELECT COUNT(*) FROM expenses", [], |r| r.get(0))?;
                let releases: i64 =
                    db.query_row("SELECT COUNT(*) FROM released_reservations", [], |r| {
                        r.get(0)
                    })?;
                assert_eq!(
                    (available, expenses, releases),
                    if rejected { (1000, 0, 1) } else { (900, 1, 0) }
                );
                Ok(())
            })();
            fs::remove_dir_all(&root)?;
            result?;
        }
        Ok(())
    }
}
