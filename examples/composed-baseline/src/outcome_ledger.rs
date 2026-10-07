//! Independent stateful alternative for the outcome-continuation experiment.
//!
//! A receiver exchanges verified evidence for an opaque handle. Any number of
//! handles may name one logical job, whose single durable budget is consumed at
//! dispatch. The implementation shares only cryptographic/serialization
//! primitives with Chio; it does not call the runtime's rule checker or store.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Job {
    pub receiver_id: String,
    pub workflow_id: String,
    pub step_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalRule {
    pub slot: Job,
    pub predecessor_step_id: String,
    pub verifier_key: PublicKey,
    pub contract_sha256: String,
    pub server_id: String,
    pub tool_name: String,
    pub resource: String,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeBody {
    pub schema: String,
    pub slot: Job,
    pub predecessor_step_id: String,
    pub contract_sha256: String,
    pub artifact_sha256: String,
    pub passed: bool,
    pub verified_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    pub body: OutcomeBody,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Effect {
    pub artifact_sha256: String,
    pub resource: String,
}

pub struct Permit {
    job: Job,
    handle: String,
}

pub struct ReceiverLedger {
    connection: Mutex<Connection>,
}

fn digest(value: &impl Serialize) -> Result<String> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|e| e.to_string())
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn validate_rule(rule: &LocalRule) -> Result<()> {
    if [
        &rule.slot.receiver_id,
        &rule.slot.workflow_id,
        &rule.slot.step_id,
        &rule.predecessor_step_id,
        &rule.server_id,
        &rule.tool_name,
        &rule.resource,
    ]
    .iter()
    .any(|value| value.trim().is_empty())
        || !hex_digest(&rule.contract_sha256)
        || rule.valid_from_unix_ms >= rule.valid_until_unix_ms
    {
        return Err("invalid_local_rule".into());
    }
    Ok(())
}

fn verify(
    rule: &LocalRule,
    evidence: &Evidence,
    effect: &Effect,
    server: &str,
    tool: &str,
    now: u64,
) -> Result<()> {
    validate_rule(rule)?;
    let body = &evidence.body;
    if body.schema != "chio.runtime.artifact-outcome.experimental.v1"
        || !hex_digest(&body.artifact_sha256)
        || !body.passed
        || body.slot != rule.slot
        || body.predecessor_step_id != rule.predecessor_step_id
        || body.contract_sha256 != rule.contract_sha256
        || effect.artifact_sha256 != body.artifact_sha256
        || effect.resource != rule.resource
        || server != rule.server_id
        || tool != rule.tool_name
        || now < rule.valid_from_unix_ms
        || now >= rule.valid_until_unix_ms
        || body.verified_at_unix_ms < rule.valid_from_unix_ms
        || body.verified_at_unix_ms > now
    {
        return Err("outcome_binding_or_policy_denied".into());
    }
    let canonical = canonical_json_bytes(body).map_err(|e| e.to_string())?;
    if !rule
        .verifier_key
        .verify_strict(&canonical, &evidence.signature)
    {
        return Err("outcome_signature_invalid".into());
    }
    Ok(())
}

fn load_rule(connection: &Connection, job: &Job) -> Result<LocalRule> {
    let row: Option<(String,String,i64,String)> = connection.query_row(
        "SELECT rule_json, rule_digest, revoked, state FROM jobs WHERE receiver = ?1 AND workflow = ?2 AND step = ?3",
        params![job.receiver_id,job.workflow_id,job.step_id],
        |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).optional().map_err(|e|e.to_string())?;
    let (raw, hash, revoked, state) = row.ok_or("unknown_job")?;
    if revoked != 0 || state != "waiting" {
        return Err("job_revoked_or_spent".into());
    }
    let rule: LocalRule = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if rule.slot != *job || digest(&rule)? != hash {
        return Err("stored_rule_mismatch".into());
    }
    Ok(rule)
}

impl ReceiverLedger {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path).map_err(|e| e.to_string())?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| e.to_string())?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|e| e.to_string())?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        connection.execute_batch("
            CREATE TABLE IF NOT EXISTS jobs (
                receiver TEXT NOT NULL, workflow TEXT NOT NULL, step TEXT NOT NULL,
                rule_json TEXT NOT NULL, rule_digest TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0,1)),
                state TEXT NOT NULL DEFAULT 'waiting' CHECK (state IN ('waiting','claimed','completed')),
                claimed_handle TEXT, result_json TEXT,
                PRIMARY KEY (receiver,workflow,step)
            );
            CREATE TABLE IF NOT EXISTS authorizations (
                handle TEXT PRIMARY KEY NOT NULL,
                receiver TEXT NOT NULL, workflow TEXT NOT NULL, step TEXT NOT NULL,
                evidence_json TEXT NOT NULL, effect_json TEXT NOT NULL
            );
        ").map_err(|e|e.to_string())?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| "ledger_lock_poisoned".into())
    }

    /// Only a trusted owner provisions jobs. Re-provisioning cannot refill the
    /// logical budget, replace the rule, or remove revocation.
    pub fn provision(&self, rule: &LocalRule) -> Result<()> {
        validate_rule(rule)?;
        let raw = serde_json::to_string(rule).map_err(|e| e.to_string())?;
        let hash = digest(rule)?;
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        tx.execute("INSERT OR IGNORE INTO jobs(receiver,workflow,step,rule_json,rule_digest) VALUES(?1,?2,?3,?4,?5)",
            params![rule.slot.receiver_id,rule.slot.workflow_id,rule.slot.step_id,raw,hash]).map_err(|e|e.to_string())?;
        let existing: String = tx
            .query_row(
                "SELECT rule_digest FROM jobs WHERE receiver=?1 AND workflow=?2 AND step=?3",
                params![
                    rule.slot.receiver_id,
                    rule.slot.workflow_id,
                    rule.slot.step_id
                ],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if existing != hash {
            return Err("job_rule_conflict".into());
        }
        tx.commit().map_err(|e| e.to_string())
    }

    /// A fresh handle is a reference to one authorization, not a fresh job or
    /// budget. Multiple valid candidates may be prepared; only one may dispatch.
    pub fn exchange(
        &self,
        evidence: &Evidence,
        effect: &Effect,
        server: &str,
        tool: &str,
        now: u64,
    ) -> Result<String> {
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let job = &evidence.body.slot;
        let rule = load_rule(&tx, job)?;
        verify(&rule, evidence, effect, server, tool, now)?;
        let handle = sha256_hex(Keypair::generate().public_key().to_hex().as_bytes());
        tx.execute("INSERT INTO authorizations(handle,receiver,workflow,step,evidence_json,effect_json) VALUES(?1,?2,?3,?4,?5,?6)",
            params![handle,job.receiver_id,job.workflow_id,job.step_id,
                serde_json::to_string(evidence).map_err(|e|e.to_string())?,
                serde_json::to_string(effect).map_err(|e|e.to_string())?]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(handle)
    }

    /// Live local state is rechecked at dispatch, not just at handle issuance.
    pub fn claim(
        &self,
        handle: &str,
        effect: &Effect,
        server: &str,
        tool: &str,
        now: u64,
    ) -> Result<Permit> {
        let mut connection = self.lock()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let row: Option<(String,String,String,String,String)>=tx.query_row(
            "SELECT receiver,workflow,step,evidence_json,effect_json FROM authorizations WHERE handle=?1", [handle],
            |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional().map_err(|e|e.to_string())?;
        let (receiver_id, workflow_id, step_id, evidence_json, effect_json) =
            row.ok_or("unknown_handle")?;
        let job = Job {
            receiver_id,
            workflow_id,
            step_id,
        };
        let evidence: Evidence = serde_json::from_str(&evidence_json).map_err(|e| e.to_string())?;
        let granted: Effect = serde_json::from_str(&effect_json).map_err(|e| e.to_string())?;
        if granted != *effect {
            return Err("handle_effect_mismatch".into());
        }
        let rule = load_rule(&tx, &job)?;
        verify(&rule, &evidence, effect, server, tool, now)?;
        let updated=tx.execute("UPDATE jobs SET state='claimed',claimed_handle=?4 WHERE receiver=?1 AND workflow=?2 AND step=?3 AND state='waiting' AND revoked=0",
            params![job.receiver_id,job.workflow_id,job.step_id,handle]).map_err(|e|e.to_string())?;
        if updated != 1 {
            return Err("job_not_available".into());
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(Permit {
            job,
            handle: handle.into(),
        })
    }

    pub fn complete(&self, permit: Permit, result: &Value) -> Result<()> {
        let connection = self.lock()?;
        let updated=connection.execute("UPDATE jobs SET state='completed',result_json=?5 WHERE receiver=?1 AND workflow=?2 AND step=?3 AND state='claimed' AND claimed_handle=?4",
            params![permit.job.receiver_id,permit.job.workflow_id,permit.job.step_id,permit.handle,serde_json::to_string(result).map_err(|e|e.to_string())?]).map_err(|e|e.to_string())?;
        if updated != 1 {
            return Err("completion_conflict".into());
        }
        Ok(())
    }

    pub fn revoke(&self, job: &Job) -> Result<()> {
        let connection = self.lock()?;
        let updated = connection
            .execute(
                "UPDATE jobs SET revoked=1 WHERE receiver=?1 AND workflow=?2 AND step=?3",
                params![job.receiver_id, job.workflow_id, job.step_id],
            )
            .map_err(|e| e.to_string())?;
        if updated != 1 {
            return Err("unknown_job".into());
        }
        Ok(())
    }

    pub fn status(&self, job: &Job) -> Result<(String, Option<Value>)> {
        let connection = self.lock()?;
        let (state, raw): (String, Option<String>) = connection
            .query_row(
                "SELECT state,result_json FROM jobs WHERE receiver=?1 AND workflow=?2 AND step=?3",
                params![job.receiver_id, job.workflow_id, job.step_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| e.to_string())?;
        Ok((
            state,
            raw.map(|raw| serde_json::from_str(&raw).map_err(|e| e.to_string()))
                .transpose()?,
        ))
    }

    /// Read-only audit view of the authorization actually consumed by a job.
    /// This does not reconstruct a Permit, complete a job, or release its budget.
    pub fn claimed_authorization(&self, job: &Job) -> Result<Option<(Evidence, Effect)>> {
        let connection = self.lock()?;
        let row: Option<(String, String)> = connection.query_row(
            "SELECT a.evidence_json,a.effect_json FROM jobs j JOIN authorizations a ON a.handle=j.claimed_handle AND a.receiver=j.receiver AND a.workflow=j.workflow AND a.step=j.step WHERE j.receiver=?1 AND j.workflow=?2 AND j.step=?3 AND j.state IN ('claimed','completed')",
            params![job.receiver_id,job.workflow_id,job.step_id],
            |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional().map_err(|e|e.to_string())?;
        row.map(|(evidence, effect)| {
            Ok((
                serde_json::from_str(&evidence).map_err(|e| e.to_string())?,
                serde_json::from_str(&effect).map_err(|e| e.to_string())?,
            ))
        })
        .transpose()
    }
}
