use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::crypto::{canonical_json_bytes, Keypair};
use chio_kernel::ToolInvocationContext;

use super::*;
use crate::{ChildSubmission, ChildWork};

impl Store {
    pub fn provision_signers(&mut self, keys: &[(String, &Keypair)]) -> Result<(), ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (id, key) in keys {
            let process =
                read_process(&tx, id)?.ok_or_else(|| ProcessError::NotFound(id.clone()))?;
            if key.public_key() != process.capability.subject {
                return Err(ProcessError::Conflict);
            }
            tx.execute(
                "INSERT OR IGNORE INTO process_delegation_keys VALUES(?1,?2)",
                params![id, key.seed_hex()],
            )?;
            let stored: String = tx.query_row(
                "SELECT seed_hex FROM process_delegation_keys WHERE process_id=?1",
                [id],
                |r| r.get(0),
            )?;
            if stored != key.seed_hex() {
                return Err(ProcessError::Conflict);
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn caller(&self, context: &ToolInvocationContext) -> Result<ProcessSnapshot, ProcessError> {
        caller(&self.connection, context)
    }

    pub fn submit_child(
        &mut self,
        submission: ChildSubmission<'_>,
        issue: impl FnOnce(
            &CapabilityToken,
            &Keypair,
            &Keypair,
        ) -> Result<CapabilityToken, ProcessError>,
    ) -> Result<ChildWork, ProcessError> {
        crate::validate_id(submission.template)?;
        if canonical_json_bytes(submission.input)?.len() > 65_536
            || submission.budget_share_bps == 0
            || submission.budget_share_bps > 10_000
        {
            return Err(ProcessError::Invalid(
                "child input or budget share exceeds bounds",
            ));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let parent = caller(&tx, submission.context)?;
        let hash = digest(&(
            &parent.id,
            submission.context.server_id(),
            submission.context.tool_name(),
            submission.template,
            submission.input,
            submission.budget_share_bps,
        ))?;
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT request_hash,process_id FROM process_child_work WHERE request_id=?1",
                [submission.context.request_id()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((stored, id)) = existing {
            if stored != hash {
                return Err(ProcessError::Conflict);
            }
            return work(&tx, &id);
        }
        let sequence: u32 = tx.query_row(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM process_child_work",
            [],
            |r| r.get(0),
        )?;
        if sequence > submission.max_submissions.min(128) {
            return Err(ProcessError::Limit("dynamic submissions"));
        }
        let id = format!("dyn_{sequence}");
        if read_process(&tx, &id)?.is_some() {
            return Err(ProcessError::Conflict);
        }
        let seed: String = tx.query_row(
            "SELECT seed_hex FROM process_delegation_keys WHERE process_id=?1",
            [&parent.id],
            |r| r.get(0),
        )?;
        let signer = Keypair::from_seed_hex(&seed)?;
        if signer.public_key() != parent.capability.subject {
            return Err(ProcessError::Conflict);
        }
        let subject = Keypair::generate();
        let capability = issue(&parent.capability, &signer, &subject)?;
        crate::verify_capability(&capability)?;
        if capability.subject != subject.public_key()
            || capability.budget_share_bps != Some(submission.budget_share_bps)
        {
            return Err(ProcessError::Conflict);
        }
        attach_child(&tx, &parent.id, &id, &capability, crate::validate_child)?;
        tx.execute(
            "INSERT INTO process_delegation_keys VALUES(?1,?2)",
            params![id, subject.seed_hex()],
        )?;
        tx.execute(
            "INSERT INTO process_child_work VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                sequence,
                submission.context.request_id(),
                hash,
                id,
                parent.id,
                submission.template,
                serde_json::to_string(submission.input)?
            ],
        )?;
        let result = work(&tx, &id)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn child_work(&self) -> Result<Vec<ChildWork>, ProcessError> {
        let mut statement = self
            .connection
            .prepare("SELECT process_id FROM process_child_work ORDER BY sequence")?;
        let ids = statement
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter().map(|id| work(&self.connection, id)).collect()
    }

    pub fn worker_waits(&self) -> Result<BTreeMap<String, Vec<String>>, ProcessError> {
        waits(&self.connection)
    }

    pub fn wait_for_children(
        &mut self,
        context: &ToolInvocationContext,
        children: &[String],
        validate: impl FnOnce(&str, &BTreeMap<String, Vec<String>>) -> Result<(), ProcessError>,
    ) -> Result<String, ProcessError> {
        if children.is_empty()
            || children.len() > 128
            || children.iter().collect::<BTreeSet<_>>().len() != children.len()
        {
            return Err(ProcessError::Invalid(
                "wait requires 1-128 unique direct children",
            ));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let parent = caller(&tx, context)?;
        for id in children {
            let child = read_process(&tx, id)?.ok_or_else(|| ProcessError::NotFound(id.clone()))?;
            require_running(&child)?;
            if child.parent_id.as_deref() != Some(parent.id.as_str()) {
                return Err(ProcessError::Invalid("wait target is not a direct child"));
            }
        }
        let mut proposed = waits(&tx)?;
        proposed.insert(parent.id.clone(), children.to_vec());
        validate(&parent.id, &proposed)?;
        tx.execute("INSERT INTO process_worker_waits VALUES(?1,?2) ON CONFLICT(process_id) DO UPDATE SET children=excluded.children",
            params![parent.id, serde_json::to_string(children)?])?;
        tx.commit()?;
        Ok(parent.id)
    }
}

fn caller(
    db: &Connection,
    context: &ToolInvocationContext,
) -> Result<ProcessSnapshot, ProcessError> {
    let mut statement =
        db.prepare("SELECT id FROM processes WHERE json_extract(capability,'$.id')=?1")?;
    let ids = statement
        .query_map([context.capability_id()], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut matched = None;
    for id in ids {
        let process = read_process(db, &id)?.ok_or(ProcessError::Conflict)?;
        if process.capability.subject.to_hex() == context.subject_key()
            && digest(&process.capability)? == context.capability_hash()
        {
            if matched.is_some() {
                return Err(ProcessError::Conflict);
            }
            matched = Some(process);
        }
    }
    let process = matched.ok_or(ProcessError::Unauthenticated)?;
    require_running(&process)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ProcessError::Invalid("clock precedes Unix epoch"))?
        .as_secs();
    if now < process.capability.issued_at || now >= process.capability.expires_at {
        return Err(ProcessError::Unauthenticated);
    }
    Ok(process)
}

fn work(db: &Connection, id: &str) -> Result<ChildWork, ProcessError> {
    let (parent, template, input): (String, String, String) = db.query_row(
        "SELECT parent_id,template,input FROM process_child_work WHERE process_id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    Ok(ChildWork {
        process: id.to_owned(),
        parent,
        template,
        input: serde_json::from_str(&input)?,
    })
}

fn waits(db: &Connection) -> Result<BTreeMap<String, Vec<String>>, ProcessError> {
    let mut statement =
        db.prepare("SELECT process_id,children FROM process_worker_waits ORDER BY process_id")?;
    let mut result = BTreeMap::new();
    for row in statement.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (id, children) = row?;
        result.insert(id, serde_json::from_str(&children)?);
    }
    Ok(result)
}
