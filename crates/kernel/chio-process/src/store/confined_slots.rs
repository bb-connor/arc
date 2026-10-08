//! A return consumes a constant slot before any child-derived value exists.
use super::*;
use chio_kernel::knowledge::VerifiedConfinedReturnCandidate;
use chio_security_types::confinement::IsolationBoundaryV1;

impl Store {
    pub(crate) fn fill_verified_confined_return_slot(
        &mut self,
        verified: VerifiedConfinedReturnCandidate,
        boundary: &IsolationBoundaryV1,
        bytes: &[u8],
    ) -> Result<String, ProcessError> {
        self.require_enforced_knowledge()?;
        verified.consume_for(boundary, bytes)?;
        if self.namespace != boundary.parent.runtime.as_str() {
            return Err(ProcessError::Conflict);
        }
        let digest =
            chio_core_types::crypto::sha256_hex(&chio_core_types::canonical_json_bytes(boundary)?);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !matches_slot(
            &tx,
            boundary.child.as_str(),
            boundary.scope.process_id.as_str(),
            boundary.boundary.as_str(),
            &digest,
        )? {
            return Err(ProcessError::BlobMissing);
        }
        let child = read_process(&tx, boundary.child.as_str())?
            .ok_or_else(|| ProcessError::NotFound(boundary.child.as_str().to_owned()))?;
        let parent = read_process(&tx, boundary.scope.process_id.as_str())?
            .ok_or_else(|| ProcessError::NotFound(boundary.scope.process_id.as_str().to_owned()))?;
        require_running(&child)?;
        require_running(&parent)?;
        if child.parent_id.as_deref() != Some(parent.id.as_str())
            || parent.parent_id.is_some()
            || child.root_id != parent.id
            || chio_core_types::recovery::confined_capability_digest(&child.capability)?
                != boundary.child_capability
            || chio_core_types::recovery::confined_capability_digest(&parent.capability)?
                != boundary.parent_capability
        {
            return Err(ProcessError::Conflict);
        }
        let (generation, prior_hash, prior_bytes): (String, Option<String>, Option<Vec<u8>>) = tx
            .query_row(
            "SELECT generation,sha256,
                    CASE WHEN typeof(data)='blob' AND length(data) IN(4,5) THEN data END
                 FROM process_confined_return_slots WHERE child_id=?1",
            [boundary.child.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let content = chio_core_types::crypto::sha256_hex(bytes);
        match (prior_hash, prior_bytes) {
            (None, None) => {
                let changed = tx.execute(
                    "UPDATE process_confined_return_slots SET sha256=?2,data=?3
                     WHERE child_id=?1 AND sha256 IS NULL AND data IS NULL",
                    params![boundary.child.as_str(), content, bytes],
                )?;
                if changed != 1 {
                    return Err(ProcessError::Conflict);
                }
            }
            (Some(hash), Some(prior)) if hash == content && prior == bytes => (),
            _ => return Err(ProcessError::Conflict),
        }
        tx.commit()?;
        Ok(generation)
    }

    pub(crate) fn read_confined_return_slot(
        &self,
        child: &str,
        boundary: &str,
        content: &str,
        generation: &str,
        retained: bool,
    ) -> Result<Vec<u8>, ProcessError> {
        self.require_enforced_knowledge()?;
        self.process(child)?;
        if !retained {
            self.require_running(child)?;
        }
        let generation = generation
            .strip_prefix("confined:")
            .ok_or(ProcessError::BlobMissing)?;
        let row: Option<Option<Vec<u8>>> = self
            .connection
            .query_row(
                "SELECT CASE WHEN typeof(data)='blob' AND length(data) IN(4,5) THEN data END
                 FROM process_confined_return_slots
                 WHERE child_id=?1 AND boundary_id=?2 AND generation=?3 AND sha256=?4",
                params![child, boundary, generation, content],
                |row| row.get(0),
            )
            .optional()?;
        let bytes = row
            .ok_or(ProcessError::BlobMissing)?
            .ok_or(ProcessError::BlobCorrupt)?;
        if (bytes != b"true" && bytes != b"false")
            || chio_core_types::crypto::sha256_hex(&bytes) != content
        {
            return Err(ProcessError::BlobCorrupt);
        }
        Ok(bytes)
    }
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
