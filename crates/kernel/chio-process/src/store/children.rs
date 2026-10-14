use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::crypto::{canonical_json_bytes, Keypair};
use chio_kernel::ToolInvocationContext;

use super::*;
use crate::{ChildSubmission, ChildWork, WorkerWait};

impl Store {
    pub fn with_process_signer<T>(
        &self,
        id: &str,
        sign: impl FnOnce(&CapabilityToken, &Keypair) -> T,
    ) -> Result<T, ProcessError> {
        self.require_running(id)?;
        let process =
            read_process(&self.connection, id)?.ok_or_else(|| ProcessError::NotFound(id.into()))?;
        let seed = zeroize::Zeroizing::new(self.connection.query_row(
            "SELECT seed_hex FROM process_delegation_keys WHERE process_id=?1",
            [id],
            |row| row.get::<_, String>(0),
        )?);
        let signer = Keypair::from_seed_hex(&seed)?;
        if signer.public_key() != process.capability.subject {
            return Err(ProcessError::Conflict);
        }
        Ok(sign(&process.capability, &signer))
    }

    /// Read-only validation of a signer provisioning: every key must belong
    /// to its process's subject, a retained different key refuses, and only
    /// the keys not yet retained are returned for the routed writer.
    pub(crate) fn signers_to_install(
        &mut self,
        keys: &[(String, &Keypair)],
    ) -> Result<Vec<SignerInstall>, ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let mut pending = Vec::new();
        for (id, key) in keys {
            let process =
                read_process(&tx, id)?.ok_or_else(|| ProcessError::NotFound(id.clone()))?;
            if key.public_key() != process.capability.subject {
                return Err(ProcessError::Conflict);
            }
            let stored: Option<String> = tx
                .query_row(
                    "SELECT seed_hex FROM process_delegation_keys WHERE process_id=?1",
                    [id],
                    |r| r.get(0),
                )
                .optional()?;
            match stored {
                Some(stored) if stored == key.seed_hex() => {}
                Some(_) => return Err(ProcessError::Conflict),
                None => pending.push(SignerInstall {
                    process_id: id.clone(),
                    seed: zeroize::Zeroizing::new(key.seed_hex()),
                    subject: key.public_key(),
                }),
            }
        }
        tx.commit()?;
        Ok(pending)
    }

    pub fn caller(&self, context: &ToolInvocationContext) -> Result<ProcessSnapshot, ProcessError> {
        caller(&self.connection, context)
    }

    /// Validate a submission and issue its capability before any write. The
    /// host callback runs here, over one read snapshot; the routed writer
    /// repeats every identity, quota and attachment check inside its own
    /// transaction. Nothing is written here.
    pub(crate) fn plan_child_submission(
        &mut self,
        submission: ChildSubmission<'_>,
        issue: impl FnOnce(
            &CapabilityToken,
            &Keypair,
            &Keypair,
        ) -> Result<CapabilityToken, ProcessError>,
    ) -> Result<ChildPlan, ProcessError> {
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
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let identity = CallerIdentity::of(submission.context);
        let parent = caller_of(&tx, &identity)?;
        let hash = digest(&(
            &parent.id,
            submission.context.server_id(),
            submission.context.tool_name(),
            submission.template,
            submission.input,
            submission.budget_share_bps,
        ))?;
        let request_id = submission.context.request_id().to_owned();
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT request_hash,process_id FROM process_child_work WHERE request_id=?1",
                [&request_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((stored, id)) = existing {
            if stored != hash {
                return Err(ProcessError::Conflict);
            }
            let replay = work(&tx, &id)?;
            tx.commit()?;
            return Ok(ChildPlan::Existing(replay));
        }
        let sequence: u32 = tx.query_row(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM process_child_work",
            [],
            |r| r.get(0),
        )?;
        if sequence > submission.max_submissions.min(128) {
            return Err(ProcessError::Limit("dynamic submissions"));
        }
        let seed: String = tx.query_row(
            "SELECT seed_hex FROM process_delegation_keys WHERE process_id=?1",
            [&parent.id],
            |r| r.get(0),
        )?;
        let seed = zeroize::Zeroizing::new(seed);
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
        let input = serde_json::to_string(submission.input)?;
        tx.commit()?;
        Ok(ChildPlan::Insert(Box::new(ChildInsert {
            identity,
            parent_id: parent.id,
            request_id,
            request_hash: hash,
            capability,
            subject_seed: zeroize::Zeroizing::new(subject.seed_hex()),
            template: submission.template.to_owned(),
            input,
            max_submissions: submission.max_submissions,
        })))
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

    pub fn worker_wait(&self, process_id: &str) -> Result<Option<WorkerWait>, ProcessError> {
        let (children, settled): (Option<String>, bool) = self
            .connection
            .query_row(
                "SELECT w.children,s.process_id IS NOT NULL FROM processes p
             LEFT JOIN process_worker_waits w ON w.process_id=p.id
             LEFT JOIN process_settled_waits s ON s.process_id=p.id WHERE p.id=?1",
                [process_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| ProcessError::NotFound(process_id.to_owned()))?;
        match children {
            Some(children) => Ok(Some(WorkerWait {
                children: serde_json::from_str(&children)?,
                settled,
            })),
            None if settled => Err(ProcessError::Invalid(
                "settled wait has no child dependency record",
            )),
            None => Ok(None),
        }
    }

    pub fn wait_for_children(
        &mut self,
        context: &ToolInvocationContext,
        children: &[String],
        validate: impl FnOnce(&str, &BTreeMap<String, Vec<String>>) -> Result<(), ProcessError>,
    ) -> Result<WaitInsert, ProcessError> {
        self.plan_wait(context, children, false, validate)
    }

    pub fn wait_for_settled_children(
        &mut self,
        context: &ToolInvocationContext,
        children: &[String],
        validate: impl FnOnce(&str, &BTreeMap<String, Vec<String>>) -> Result<(), ProcessError>,
    ) -> Result<WaitInsert, ProcessError> {
        self.plan_wait(context, children, true, validate)
    }

    /// Validate a proposed direct-child wait over one read snapshot and run
    /// the host's graph validation there. The routed writer repeats the
    /// caller and child checks and refuses if any wait record changed since
    /// this snapshot, so a graph the host validated is exactly the graph that
    /// commits. Nothing is written here.
    fn plan_wait(
        &mut self,
        context: &ToolInvocationContext,
        children: &[String],
        settled: bool,
        validate: impl FnOnce(&str, &BTreeMap<String, Vec<String>>) -> Result<(), ProcessError>,
    ) -> Result<WaitInsert, ProcessError> {
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
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let identity = CallerIdentity::of(context);
        let parent = caller_of(&tx, &identity)?;
        check_wait_children(&tx, &parent.id, children)?;
        let observed = waits(&tx)?;
        let mut proposed = observed.clone();
        proposed.insert(parent.id.clone(), children.to_vec());
        validate(&parent.id, &proposed)?;
        tx.commit()?;
        Ok(WaitInsert {
            identity,
            parent_id: parent.id,
            children: children.to_vec(),
            settled,
            observed,
        })
    }
}

/// An owned, validated signer provisioning entry. Only the routed writer
/// persists it.
pub(crate) struct SignerInstall {
    process_id: String,
    seed: zeroize::Zeroizing<String>,
    subject: chio_core_types::crypto::PublicKey,
}

/// The authenticated caller of a native service call, owned so a routed
/// writer can authenticate it again inside its own transaction.
#[derive(Clone)]
pub(crate) struct CallerIdentity {
    capability_id: String,
    subject_key: String,
    capability_hash: String,
}
impl CallerIdentity {
    fn of(context: &ToolInvocationContext) -> Self {
        Self {
            capability_id: context.capability_id().to_owned(),
            subject_key: context.subject_key().to_owned(),
            capability_hash: context.capability_hash().to_owned(),
        }
    }
}

/// A validated dynamic child submission, or the committed work it replays.
pub(crate) enum ChildPlan {
    Existing(ChildWork),
    Insert(Box<ChildInsert>),
}

/// An owned, issued child submission. Only the routed writer persists it.
pub(crate) struct ChildInsert {
    identity: CallerIdentity,
    parent_id: String,
    request_id: String,
    request_hash: String,
    capability: CapabilityToken,
    subject_seed: zeroize::Zeroizing<String>,
    template: String,
    input: String,
    max_submissions: u32,
}

/// A validated wait with the exact graph snapshot the host validated.
pub(crate) struct WaitInsert {
    identity: CallerIdentity,
    parent_id: String,
    children: Vec<String>,
    settled: bool,
    observed: BTreeMap<String, Vec<String>>,
}

/// The complete signer provisioning body inside one writer transaction.
pub(crate) fn provision_signers_call(
    tx: &rusqlite::Transaction<'_>,
    keys: &[SignerInstall],
) -> Result<(), ProcessError> {
    for key in keys {
        let process = read_process(tx, &key.process_id)?
            .ok_or_else(|| ProcessError::NotFound(key.process_id.clone()))?;
        if key.subject != process.capability.subject {
            return Err(ProcessError::Conflict);
        }
        tx.execute(
            "INSERT OR IGNORE INTO process_delegation_keys VALUES(?1,?2)",
            params![key.process_id, key.seed.as_str()],
        )?;
        let stored: String = tx.query_row(
            "SELECT seed_hex FROM process_delegation_keys WHERE process_id=?1",
            [&key.process_id],
            |r| r.get(0),
        )?;
        if stored != key.seed.as_str() {
            return Err(ProcessError::Conflict);
        }
    }
    Ok(())
}

/// The complete child submission body inside one writer transaction: the
/// caller, request replay, the next dynamic sequence and its bound, the
/// existing child-attachment checks, the delegation key and the work row.
pub(crate) fn submit_child_call(
    tx: &rusqlite::Transaction<'_>,
    insert: &ChildInsert,
) -> Result<ChildWork, ProcessError> {
    let parent = caller_of(tx, &insert.identity)?;
    if parent.id != insert.parent_id {
        return Err(ProcessError::Conflict);
    }
    let existing: Option<(String, String)> = tx
        .query_row(
            "SELECT request_hash,process_id FROM process_child_work WHERE request_id=?1",
            [&insert.request_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((stored, id)) = existing {
        if stored != insert.request_hash {
            return Err(ProcessError::Conflict);
        }
        return work(tx, &id);
    }
    let sequence: u32 = tx.query_row(
        "SELECT COALESCE(MAX(sequence),0)+1 FROM process_child_work",
        [],
        |r| r.get(0),
    )?;
    if sequence > insert.max_submissions.min(128) {
        return Err(ProcessError::Limit("dynamic submissions"));
    }
    let id = format!("dyn_{sequence}");
    if read_process(tx, &id)?.is_some() {
        return Err(ProcessError::Conflict);
    }
    attach_child(
        tx,
        &parent.id,
        &id,
        &insert.capability,
        crate::validate_child,
    )?;
    tx.execute(
        "INSERT INTO process_delegation_keys VALUES(?1,?2)",
        params![id, insert.subject_seed.as_str()],
    )?;
    tx.execute(
        "INSERT INTO process_child_work VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            sequence,
            insert.request_id,
            insert.request_hash,
            id,
            parent.id,
            insert.template,
            insert.input
        ],
    )?;
    work(tx, &id)
}

/// The complete wait body inside one writer transaction: the caller, the
/// direct running children, the unchanged validated graph and the wait
/// record with its settled marker.
pub(crate) fn record_wait_call(
    tx: &rusqlite::Transaction<'_>,
    wait: &WaitInsert,
) -> Result<String, ProcessError> {
    let parent = caller_of(tx, &wait.identity)?;
    if parent.id != wait.parent_id {
        return Err(ProcessError::Conflict);
    }
    check_wait_children(tx, &parent.id, &wait.children)?;
    if waits(tx)? != wait.observed {
        return Err(ProcessError::Conflict);
    }
    tx.execute("INSERT INTO process_worker_waits VALUES(?1,?2) ON CONFLICT(process_id) DO UPDATE SET children=excluded.children",
        params![parent.id, serde_json::to_string(&wait.children)?])?;
    if wait.settled {
        tx.execute(
            "INSERT OR IGNORE INTO process_settled_waits VALUES(?1)",
            [&parent.id],
        )?;
    } else {
        tx.execute(
            "DELETE FROM process_settled_waits WHERE process_id=?1",
            [&parent.id],
        )?;
    }
    Ok(parent.id)
}

fn check_wait_children(
    db: &Connection,
    parent: &str,
    children: &[String],
) -> Result<(), ProcessError> {
    for id in children {
        let child = read_process(db, id)?.ok_or_else(|| ProcessError::NotFound(id.clone()))?;
        require_running(&child)?;
        if child.parent_id.as_deref() != Some(parent) {
            return Err(ProcessError::Invalid("wait target is not a direct child"));
        }
    }
    Ok(())
}

fn caller(
    db: &Connection,
    context: &ToolInvocationContext,
) -> Result<ProcessSnapshot, ProcessError> {
    caller_of(db, &CallerIdentity::of(context))
}

fn caller_of(db: &Connection, identity: &CallerIdentity) -> Result<ProcessSnapshot, ProcessError> {
    let mut statement =
        db.prepare("SELECT id FROM processes WHERE json_extract(capability,'$.id')=?1")?;
    let ids = statement
        .query_map([&identity.capability_id], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut matched = None;
    for id in ids {
        let process = read_process(db, &id)?.ok_or(ProcessError::Conflict)?;
        if process.capability.subject.to_hex() == identity.subject_key
            && digest(&process.capability)? == identity.capability_hash
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
