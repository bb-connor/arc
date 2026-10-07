//! A return consumes a constant slot before any child-derived value exists.
use super::*;

impl Store {
    pub(crate) fn confined_return_slot_matches(
        &self,
        child: &str,
        parent: &str,
        boundary: &str,
        digest: &str,
    ) -> Result<bool, ProcessError> {
        self.require_enforced_knowledge()?;
        matches_slot(&self.connection, child, parent, boundary, digest)
    }

    pub(crate) fn reserve_confined_return_slot(
        &mut self,
        child: &str,
        parent: &str,
        boundary: &str,
        digest: &str,
    ) -> Result<(), ProcessError> {
        self.require_enforced_knowledge()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if matches_slot(&tx, child, parent, boundary, digest)? {
            tx.commit()?;
            return Ok(());
        }
        let child_process =
            read_process(&tx, child)?.ok_or_else(|| ProcessError::NotFound(child.to_owned()))?;
        let parent_process =
            read_process(&tx, parent)?.ok_or_else(|| ProcessError::NotFound(parent.to_owned()))?;
        require_running(&child_process)?;
        require_running(&parent_process)?;
        if child_process.parent_id.as_deref() != Some(parent)
            || parent_process.parent_id.is_some()
            || child_process.root_id != parent_process.id
        {
            return Err(ProcessError::Conflict);
        }
        let usage = blobs::usage(&tx, &child_process)?;
        let slots: i64 = tx.query_row(
            "SELECT count(*) FROM process_confined_return_slots WHERE parent_id=?1",
            [parent],
            |row| row.get(0),
        )?;
        if !(0..16).contains(&slots)
            || usage
                .tree_bytes
                .checked_add(8)
                .is_none_or(|bytes| bytes > u64::from(usage.limits.max_bytes))
            || usage.tree_blobs >= u64::from(usage.limits.max_blobs)
        {
            return Err(ProcessError::Limit("immutable process state"));
        }
        tx.execute(
            "INSERT INTO process_confined_return_slots(child_id,parent_id,boundary_id,boundary_digest,generation)
             VALUES(?1,?2,?3,?4,?5)", params![child,parent,boundary,digest,uuid::Uuid::new_v4().to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn matches_slot(
    connection: &Connection,
    child: &str,
    parent: &str,
    boundary: &str,
    digest: &str,
) -> Result<bool, ProcessError> {
    let prior: Option<(String,String,String)> = connection.query_row(
        "SELECT parent_id,boundary_id,boundary_digest FROM process_confined_return_slots WHERE child_id=?1", [child],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional()?;
    match prior {
        None => Ok(false),
        Some((old_parent, old_boundary, old_digest))
            if old_parent == parent && old_boundary == boundary && old_digest == digest =>
        {
            Ok(true)
        }
        Some(_) => Err(ProcessError::Conflict),
    }
}
