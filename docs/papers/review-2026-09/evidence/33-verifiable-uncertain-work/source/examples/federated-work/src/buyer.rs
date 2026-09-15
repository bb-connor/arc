use crate::{common::*, market::*, provider};
use chio_core_types::{
    receipt::{body::ChioReceipt, decision::Decision, lineage::SignedExportEnvelope},
    PublicKey,
};
use chio_kernel::ToolServerConnection;
use chio_open_market::bidding::*;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::path::Path;

pub(crate) fn open(state: &Path) -> Result<Connection> {
    let db = Connection::open(state.join("buyer.sqlite"))?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
        CREATE TABLE IF NOT EXISTS account(id INTEGER PRIMARY KEY CHECK(id=1),available INTEGER NOT NULL CHECK(available>=0));
        INSERT OR IGNORE INTO account VALUES(1,1000);
        CREATE TABLE IF NOT EXISTS jobs(job TEXT PRIMARY KEY,quote TEXT NOT NULL,acceptance TEXT,
            state TEXT NOT NULL CHECK(state IN ('quoted','prepared','attempted','accepted')),ack TEXT);
        CREATE TABLE IF NOT EXISTS reservations(job TEXT PRIMARY KEY,amount INTEGER NOT NULL CHECK(amount=100));
        CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY,tool TEXT NOT NULL,args TEXT NOT NULL,response TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS work_jobs(job TEXT PRIMARY KEY,request TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('prepared','attempted','verified')),delivery TEXT);
        CREATE TABLE IF NOT EXISTS released_reservations(job TEXT PRIMARY KEY,receipt_id TEXT NOT NULL UNIQUE);
        CREATE TABLE IF NOT EXISTS expenses(job TEXT PRIMARY KEY,amount INTEGER NOT NULL CHECK(amount=100),receipt_id TEXT NOT NULL UNIQUE);")?;
    Ok(db)
}

pub fn request(state: &Path, url: &str, tool: &str, args: Value) -> Result<Value> {
    let peers: Peers = read(state.join("peers.json"))?;
    let client = provider::client(state, url)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let output = runtime.block_on(client.invoke(tool, json!({"data":args}), None))?;
    verify_receipt(&output, &peers.provider, tool, &args)?;
    open(state)?.execute(
        "INSERT INTO observations(tool,args,response) VALUES(?,?,?)",
        params![
            tool,
            serde_json::to_string(&args)?,
            serde_json::to_string(&output)?
        ],
    )?;
    Ok(output)
}

pub(crate) fn verify_receipt(
    output: &Value,
    provider: &PublicKey,
    tool: &str,
    args: &Value,
) -> Result<()> {
    let receipt: ChioReceipt =
        serde_json::from_value(output["task"]["metadata"]["chio"]["receipt"].clone())?;
    if &receipt.kernel_key != provider
        || !receipt.verify_signature()?
        || receipt.tool_server != SERVER
        || receipt.tool_name != tool
        || !receipt.action.verify_hash()?
        || &receipt.action.parameters != args
    {
        return Err("provider receipt does not verify against this request".into());
    }
    let completed = output["task"]["status"]["state"] == "TASK_STATE_COMPLETED";
    let failed = output["task"]["status"]["state"] == "TASK_STATE_FAILED";
    if (!completed && !failed)
        || receipt.decision.is_none()
        || completed != (receipt.decision == Some(Decision::Allow))
    {
        return Err("task state disagrees with signed kernel decision".into());
    }
    Ok(())
}

pub(crate) fn payload(output: Value) -> Result<Value> {
    let receipt: ChioReceipt =
        serde_json::from_value(output["task"]["metadata"]["chio"]["receipt"].clone())?;
    if output["task"]["status"]["state"] != "TASK_STATE_COMPLETED"
        || receipt.decision != Some(Decision::Allow)
    {
        return Err(format!(
            "provider did not complete the request: {}",
            output["task"]["status"]
        )
        .into());
    }
    output["task"]["artifacts"][0]["parts"][0]
        .get("data")
        .cloned()
        .ok_or_else(|| "missing result data".into())
}

pub fn run(state: &Path, url: &str, crash_before_send: bool) -> Result<Value> {
    let identity = key(state)?;
    let peers: Peers = read(state.join("peers.json"))?;
    let agreement: Agreement = read(state.join("agreement.json"))?;
    if identity.public_key() != peers.buyer {
        return Err("buyer identity differs from configured peer".into());
    }
    validate_agreement(&agreement, &peers)?;
    let mut db = open(state)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let previous: Option<String> = tx
        .query_row(
            "SELECT quote FROM jobs WHERE job=?",
            [&agreement.job_id],
            |r| r.get(0),
        )
        .optional()?;
    let quote = if let Some(previous) = previous {
        let quote: QuoteRequest = serde_json::from_str(&previous)?;
        if digest(&quote.agreement)? != digest(&agreement)? {
            return Err("local job already binds different terms".into());
        }
        quote
    } else {
        let quote = QuoteRequest {
            bid: make_bid(&agreement, &identity)?,
            agreement: agreement.clone(),
        };
        tx.execute(
            "INSERT INTO jobs(job,quote,state) VALUES(?,?,'quoted')",
            params![agreement.job_id, serde_json::to_string(&quote)?],
        )?;
        quote
    };
    tx.commit()?;
    quote.validate(&peers)?;

    let stored: Option<String> = db.query_row(
        "SELECT acceptance FROM jobs WHERE job=?",
        [&agreement.job_id],
        |r| r.get(0),
    )?;
    if stored.is_none() {
        let ask: SignedAskResponse = serde_json::from_value(payload(request(
            state,
            url,
            "quote",
            serde_json::to_value(&quote)?,
        )?)?)?;
        verify_ask(&quote, &ask, &peers.provider)?;
        let time = now()?;
        if time < ask.body.issued_at || time >= ask.body.expires_at {
            return Err("offer is not live for reservation".into());
        }
        // This profile explicitly selects the buyer's local credit promise.
        // The signature is not proof of escrow or of funds outside this journal.
        let reservation = SignedReservationReceipt::sign(
            ReservationReceipt {
                schema: RESERVATION_RECEIPT_SCHEMA.into(),
                receipt_id: format!("hold-{}", digest(&quote.agreement)?),
                agent_id: peers.buyer.to_hex(),
                listing_id: ask.body.listing_id.clone(),
                ask_digest: digest(&ask.body)?,
                reserved_amount: amount(100),
            },
            &identity,
        )?;
        let witness = VerifiedReservationReceipt::from_signed(&reservation, &peers.buyer)?;
        let accepted = accept(&ask, &witness, &identity, time)?;
        let acceptance = Acceptance {
            quote: quote.clone(),
            ask,
            reservation,
            accepted,
        };
        acceptance.verify(&peers)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx.query_row(
            "SELECT acceptance FROM jobs WHERE job=?",
            [&agreement.job_id],
            |r| r.get(0),
        )?;
        if existing.is_none() {
            if tx.execute(
                "UPDATE account SET available=available-100 WHERE id=1 AND available>=100",
                [],
            )? != 1
            {
                return Err("insufficient local credits".into());
            }
            tx.execute(
                "INSERT INTO reservations(job,amount) VALUES(?,100)",
                [&agreement.job_id],
            )?;
            tx.execute(
                "UPDATE jobs SET acceptance=?,state='prepared' WHERE job=?",
                params![serde_json::to_string(&acceptance)?, agreement.job_id],
            )?;
        }
        tx.commit()?;
    }

    // Persist intent before sending. After an uncertain send, only ask the
    // provider to report its retained agreement; never infer absence from a timeout.
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (encoded, phase): (String, String) = tx.query_row(
        "SELECT acceptance,state FROM jobs WHERE job=?",
        [&agreement.job_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let acceptance: Acceptance = serde_json::from_str(&encoded)?;
    acceptance.verify(&peers)?;
    let method = if phase == "prepared" {
        tx.execute(
            "UPDATE jobs SET state='attempted' WHERE job=? AND state='prepared'",
            [&agreement.job_id],
        )?;
        "accept"
    } else {
        "status"
    };
    tx.commit()?;
    if crash_before_send && method == "accept" {
        crash()?;
    }
    let output = request(state, url, method, serde_json::to_value(&acceptance)?)?;
    let ack: SignedExportEnvelope<Acknowledgement> = serde_json::from_value(payload(output)?)?;
    verify_ack(&ack, &acceptance, &peers.provider)?;
    if ack.body.state != "accepted" {
        return Err("acceptance remains uncertain; reservation retained for reconciliation".into());
    }
    db.execute(
        "UPDATE jobs SET state='accepted',ack=? WHERE job=?",
        params![serde_json::to_string(&ack)?, agreement.job_id],
    )?;
    snapshot(state)
}

/// Verify public signed artifacts under separately supplied peer pins.
/// Unsigned balance, isolation and process observations remain harness evidence.
pub fn verify_public(peers: &Peers, public: &Value) -> Result<Value> {
    let jobs = public["buyer"]["jobs"]
        .as_array()
        .ok_or("missing job evidence")?;
    if jobs.len() != 1 {
        return Err("expected exactly one agreement".into());
    }
    let acceptance: Acceptance = serde_json::from_value(jobs[0]["acceptance"].clone())?;
    acceptance.verify(peers)?;
    let ack: SignedExportEnvelope<Acknowledgement> =
        serde_json::from_value(jobs[0]["acknowledgement"].clone())?;
    verify_ack(&ack, &acceptance, &peers.provider)?;
    if ack.body.state != "accepted" {
        return Err("provider has not acknowledged acceptance".into());
    }
    let observations = public["observations"]
        .as_array()
        .ok_or("missing receipt evidence")?;
    if observations.is_empty() {
        return Err("empty receipt evidence".into());
    }
    for observation in observations {
        let method = observation["tool"].as_str().ok_or("missing method")?;
        if !["quote", "accept", "status"].contains(&method) {
            return Err("unsupported transcript method".into());
        }
        let output = &observation["response"];
        verify_receipt(output, &peers.provider, method, &observation["args"])?;
        if output["task"]["status"]["state"] == "TASK_STATE_COMPLETED" {
            let data = payload(output.clone())?;
            if method == "quote" {
                let quote: QuoteRequest = serde_json::from_value(observation["args"].clone())?;
                quote.validate(peers)?;
                verify_ask(&quote, &serde_json::from_value(data)?, &peers.provider)?;
            } else {
                let input: Acceptance = serde_json::from_value(observation["args"].clone())?;
                input.verify(peers)?;
                verify_ack(&serde_json::from_value(data)?, &input, &peers.provider)?;
            }
        }
    }
    Ok(
        json!({"agreementSha256":digest(&acceptance.quote.agreement)?,
        "acceptedBidSha256":digest(&acceptance.accepted)?,"verifiedReceipts":observations.len(),
        "providerAcknowledged":"accepted","workExecuted":false,"settled":false}),
    )
}

fn verify_ack(
    ack: &SignedExportEnvelope<Acknowledgement>,
    acceptance: &Acceptance,
    provider: &PublicKey,
) -> Result<()> {
    let body = &ack.body;
    if &ack.signer_key != provider
        || !ack.verify_signature()?
        || body.schema != ACK_SCHEMA
        || body.job_id != acceptance.quote.agreement.job_id
        || body.agreement_sha256 != digest(&acceptance.quote.agreement)?
        || body.accepted_bid_sha256 != digest(&acceptance.accepted)?
        || body.work_executed
        || body.settled
        || !["quoted", "accepted"].contains(&body.state.as_str())
    {
        return Err("provider acknowledgement differs from the accepted agreement".into());
    }
    Ok(())
}

pub fn snapshot(state: &Path) -> Result<Value> {
    let db = open(state)?;
    let available: i64 =
        db.query_row("SELECT available FROM account WHERE id=1", [], |r| r.get(0))?;
    let (reservations, reserved): (i64, i64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(CASE WHEN e.job IS NULL THEN r.amount ELSE 0 END),0) FROM reservations r LEFT JOIN expenses e ON r.job=e.job",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut stmt = db.prepare("SELECT job,state,acceptance,ack FROM jobs ORDER BY job")?;
    let jobs=stmt.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,Option<String>>(3)?)))?
        .map(|row| -> Result<Value> {
            let (job,phase,acceptance,ack)=row?;
            Ok(json!({"job":job,"state":phase,"acceptance":acceptance.map(|v|serde_json::from_str::<Value>(&v)).transpose()?,
                "acknowledgement":ack.map(|v|serde_json::from_str::<Value>(&v)).transpose()?}))
        }).collect::<Result<Vec<_>>>()?;
    let spent: i64 = db.query_row("SELECT COALESCE(SUM(amount),0) FROM expenses", [], |r| {
        r.get(0)
    })?;
    let profile = if jobs.len() == 1 {
        jobs[0]["acceptance"]["quote"]["agreement"]["creditProfile"].clone()
    } else {
        Value::Null
    };
    Ok(
        json!({"available":available,"reserved":reserved,"reservationCount":reservations,"spent":spent,
        "creditProfile":profile,"jobs":jobs,"workExecuted":spent>0,"settled":spent>0,
        "externalFundsTransferred":false}),
    )
}
