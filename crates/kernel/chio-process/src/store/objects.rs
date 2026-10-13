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
enum StagingPurpose {
    Execution,
    RetainedArchive,
}

impl Store {
    pub(crate) fn stage_knowledge_object(
        &mut self,
        process: &str,
        object: &str,
        bytes: &[u8],
    ) -> Result<String, ProcessError> {
        self.stage_object(process, object, bytes, StagingPurpose::Execution)
    }

    pub(crate) fn stage_retained_archive_object(
        &mut self,
        process: &str,
        object: &str,
        bytes: &[u8],
    ) -> Result<String, ProcessError> {
        self.stage_object(process, object, bytes, StagingPurpose::RetainedArchive)
    }

    fn stage_object(
        &mut self,
        process: &str,
        object: &str,
        bytes: &[u8],
        purpose: StagingPurpose,
    ) -> Result<String, ProcessError> {
        self.require_enforced_knowledge()?;
        if bytes.len() > MAX_STATE_BLOB_BYTES {
            return Err(ProcessError::Invalid("artifact object is too large"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let snapshot = read_process(&tx, process)?
            .ok_or_else(|| ProcessError::NotFound(process.to_owned()))?;
        if matches!(purpose, StagingPurpose::Execution) {
            require_running(&snapshot)?;
        }
        let content = sha256_hex(bytes);
        if let Some(retained) = object_identity(&tx, process, object)? {
            if retained.retired
                || retained.content != content
                || retained.size != bytes.len() as u64
            {
                return Err(ProcessError::Conflict);
            }
            if object_bytes(&tx, process, object, &content, &retained.generation)? != bytes {
                return Err(ProcessError::BlobCorrupt);
            }
            tx.commit()?;
            return Ok(retained.generation);
        }
        let usage = blobs::usage(&tx, &snapshot)?;
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
            params![process,object,generation,content,bytes.len() as i64,bytes],
        )?;
        tx.commit()?;
        Ok(generation)
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

    pub(crate) fn collect_knowledge_object(
        &mut self,
        process: &str,
        object: &str,
        digest: &str,
        generation: &str,
    ) -> Result<bool, ProcessError> {
        self.require_enforced_knowledge()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(retained) = object_identity(&tx, process, object)? else {
            tx.commit()?;
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
                params![process,object,generation,digest],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }
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
