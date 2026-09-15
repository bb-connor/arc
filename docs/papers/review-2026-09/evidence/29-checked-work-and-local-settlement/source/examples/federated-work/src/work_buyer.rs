use crate::{
    buyer,
    common::*,
    market::Acceptance,
    provider,
    review::{self, Delivery, ReviewRequest},
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
        let delivery: Delivery = serde_json::from_str(&encoded)?;
        review::verify_delivery(&work, &delivery)?;
        return summary(&db, &work, delivery);
    }
    if phase == "prepared" {
        let output = request(state, url, serde_json::to_value(&work)?, true)?;
        let report = review::decode(&buyer::payload(output)?)?;
        review::verify_report(&work, &report)?;
    }
    // Recovery asks for a retained deliverable. It never replays the review.
    let output = buyer::request(
        state,
        url,
        "delivery",
        serde_json::to_value(&work.acceptance)?,
    )?;
    let delivery: Delivery = serde_json::from_value(buyer::payload(output)?)?;
    review::verify_delivery(&work, &delivery)?;
    if crash_after_check {
        crash()?;
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT OR IGNORE INTO expenses(job,amount,receipt_id) VALUES(?,100,?)",
        params![job, delivery.receipt.id],
    )?;
    tx.execute(
        "UPDATE work_jobs SET state='verified',delivery=? WHERE job=?",
        params![serde_json::to_string(&delivery)?, job],
    )?;
    tx.commit()?;
    summary(&db, &work, delivery)
}

fn summary(db: &Connection, work: &ReviewRequest, delivery: Delivery) -> Result<Value> {
    let available: i64 =
        db.query_row("SELECT available FROM account WHERE id=1", [], |r| r.get(0))?;
    let spent: i64 = db.query_row("SELECT COALESCE(SUM(amount),0) FROM expenses", [], |r| {
        r.get(0)
    })?;
    let reserved:i64=db.query_row("SELECT COALESCE(SUM(r.amount),0) FROM reservations r LEFT JOIN expenses e ON r.job=e.job WHERE e.job IS NULL",[],|r|r.get(0))?;
    Ok(
        json!({"workExecuted":true,"buyerVerified":true,"localCreditSettled":true,"externalFundsTransferred":false,
        "creditProfile":work.acceptance.quote.agreement.credit_profile,"available":available,"reserved":reserved,"spent":spent,
        "request":work,"delivery":delivery}),
    )
}
