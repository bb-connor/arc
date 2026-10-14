//! Mediated objects have logical identities independent of their content digest.
use super::*;
use crate::MAX_STATE_BLOB_BYTES;
use chio_core_types::crypto::sha256_hex;

struct ObjectIdentity {
    generation: String,
    content: String,
    size: u64,
    retired: bool,
}
impl Store {
    /// Read-only probe of a stage request: the generation of the exact
    /// retained object when this is an idempotent replay, `None` when the
    /// object must be written. A conflicting or corrupt retained object
    /// refuses. Nothing is written here.
    pub(crate) fn staged_object_replay(
        &self,
        process: &str,
        object: &str,
        bytes: &[u8],
    ) -> Result<Option<String>, ProcessError> {
        self.require_enforced_knowledge()?;
        if bytes.len() > MAX_STATE_BLOB_BYTES {
            return Err(ProcessError::Invalid("artifact object is too large"));
        }
        let snapshot = read_process(&self.connection, process)?
            .ok_or_else(|| ProcessError::NotFound(process.to_owned()))?;
        require_running(&snapshot)?;
        replay_generation(&self.connection, process, object, bytes)
    }

    /// Read-only probe of a collection request. Unknown identities and
    /// already retired objects need no write; a retained one is collected by
    /// the routed writer.
    pub(crate) fn object_collection(
        &self,
        process: &str,
        object: &str,
        digest: &str,
        generation: &str,
    ) -> Result<Collection, ProcessError> {
        self.require_enforced_knowledge()?;
        let Some(retained) = object_identity(&self.connection, process, object)? else {
            return Ok(Collection::Absent);
        };
        let generation = generation.strip_prefix("object:").unwrap_or(generation);
        if retained.generation != generation || retained.content != digest {
            return Err(ProcessError::Conflict);
        }
        Ok(if retained.retired {
            Collection::Retired
        } else {
            Collection::Pending
        })
    }

    pub(crate) fn object_generation(
        &self,
        process: &str,
        object: &str,
        digest: &str,
    ) -> Result<Option<String>, ProcessError> {
        self.require_enforced_knowledge()?;
        self.require_running(process)?;
        let Some(retained) = object_identity(&self.connection, process, object)? else {
            return Ok(None);
        };
        if retained.retired || retained.content != digest {
            return Err(ProcessError::BlobMissing);
        }
        Ok(Some(retained.generation))
    }

    pub(crate) fn read_knowledge_object(
        &self,
        process: &str,
        object: &str,
        digest: &str,
        generation: &str,
    ) -> Result<Option<Vec<u8>>, ProcessError> {
        self.require_enforced_knowledge()?;
        self.require_running(process)?;
        self.read_retained_knowledge_object(process, object, digest, generation)
    }

    pub(crate) fn read_retained_knowledge_object(
        &self,
        process: &str,
        object: &str,
        digest: &str,
        generation: &str,
    ) -> Result<Option<Vec<u8>>, ProcessError> {
        self.require_enforced_knowledge()?;
        self.process(process)?;
        if object_identity(&self.connection, process, object)?.is_none() {
            return Ok(None);
        }
        object_bytes(&self.connection, process, object, digest, generation).map(Some)
    }

    pub(crate) fn retained_object_generation(
        &self,
        process: &str,
        object: &str,
        digest: &str,
    ) -> Result<Option<String>, ProcessError> {
        self.require_enforced_knowledge()?;
        self.process(process)?;
        let Some(retained) = object_identity(&self.connection, process, object)? else {
            return Ok(None);
        };
        if retained.retired || retained.content != digest {
            return Err(ProcessError::BlobMissing);
        }
        Ok(Some(retained.generation))
    }
}

/// What a collection request still needs from the journal.
pub(crate) enum Collection {
    Absent,
    Retired,
    Pending,
}

fn replay_generation(
    connection: &Connection,
    process: &str,
    object: &str,
    bytes: &[u8],
) -> Result<Option<String>, ProcessError> {
    let content = sha256_hex(bytes);
    let Some(retained) = object_identity(connection, process, object)? else {
        return Ok(None);
    };
    if retained.retired || retained.content != content || retained.size != bytes.len() as u64 {
        return Err(ProcessError::Conflict);
    }
    if object_bytes(connection, process, object, &content, &retained.generation)? != bytes {
        return Err(ProcessError::BlobCorrupt);
    }
    Ok(Some(retained.generation))
}

/// The complete stage body inside one writer transaction: the enforced
/// level, running identity, idempotent replay, the tree quota and the
/// immutable insert. Executed only by the bank-proven routed writer.
pub(crate) fn stage_knowledge_object_call(
    tx: &Connection,
    process: &str,
    object: &str,
    bytes: &[u8],
) -> Result<String, ProcessError> {
    super::knowledge::require_enforced_level(tx)?;
    if bytes.len() > MAX_STATE_BLOB_BYTES {
        return Err(ProcessError::Invalid("artifact object is too large"));
    }
    let snapshot =
        read_process(tx, process)?.ok_or_else(|| ProcessError::NotFound(process.to_owned()))?;
    require_running(&snapshot)?;
    if let Some(generation) = replay_generation(tx, process, object, bytes)? {
        return Ok(generation);
    }
    let usage = blobs::usage(tx, &snapshot)?;
    if usage
        .tree_bytes
        .checked_add(bytes.len() as u64)
        .is_none_or(|total| total > u64::from(usage.limits.max_bytes))
        || usage.tree_blobs >= u64::from(usage.limits.max_blobs)
    {
        return Err(ProcessError::Limit("immutable process state"));
    }
    let generation = uuid::Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO process_artifact_objects(process_id,object_id,generation,sha256,size_bytes,data)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![process, object, generation, sha256_hex(bytes), bytes.len() as i64, bytes],
    )?;
    Ok(generation)
}

/// The complete collection body inside one writer transaction. Returns
/// whether the identity exists. Executed only by the routed writer.
pub(crate) fn collect_knowledge_object_call(
    tx: &Connection,
    process: &str,
    object: &str,
    digest: &str,
    generation: &str,
) -> Result<bool, ProcessError> {
    super::knowledge::require_enforced_level(tx)?;
    let Some(retained) = object_identity(tx, process, object)? else {
        return Ok(false);
    };
    let generation = generation.strip_prefix("object:").unwrap_or(generation);
    if retained.generation != generation || retained.content != digest {
        return Err(ProcessError::Conflict);
    }
    if !retained.retired {
        tx.execute(
            "UPDATE process_artifact_objects SET data=NULL
             WHERE process_id=?1 AND object_id=?2 AND generation=?3 AND sha256=?4 AND data IS NOT NULL",
            params![process, object, generation, digest],
        )?;
    }
    Ok(true)
}

fn object_identity(
    connection: &Connection,
    process: &str,
    object: &str,
) -> Result<Option<ObjectIdentity>, ProcessError> {
    let row: Option<(String, String, i64, bool)> = connection
        .query_row(
            "SELECT generation,sha256,size_bytes,data IS NULL FROM process_artifact_objects
         WHERE process_id=?1 AND object_id=?2",
            params![process, object],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    row.map(|(generation, content, size, retired)| {
        Ok(ObjectIdentity {
            generation,
            content,
            size: u64::try_from(size).map_err(|_| ProcessError::BlobCorrupt)?,
            retired,
        })
    })
    .transpose()
}

fn object_bytes(
    connection: &Connection,
    process: &str,
    object: &str,
    digest: &str,
    generation: &str,
) -> Result<Vec<u8>, ProcessError> {
    let generation = generation.strip_prefix("object:").unwrap_or(generation);
    let row: Option<(i64, Option<Vec<u8>>)> = connection
        .query_row(
            "SELECT size_bytes,CASE WHEN typeof(data)='blob' AND length(data)<=?5 THEN data END
         FROM process_artifact_objects
         WHERE process_id=?1 AND object_id=?2 AND sha256=?3 AND generation=?4",
            params![
                process,
                object,
                digest,
                generation,
                MAX_STATE_BLOB_BYTES as i64
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (size, bytes) = row.ok_or(ProcessError::BlobMissing)?;
    let size = u64::try_from(size).map_err(|_| ProcessError::BlobCorrupt)?;
    let bytes = bytes.ok_or(ProcessError::BlobMissing)?;
    if bytes.len() as u64 != size || sha256_hex(&bytes) != digest {
        return Err(ProcessError::BlobCorrupt);
    }
    Ok(bytes)
}
