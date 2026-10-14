//! Durable raw-route refusal shared by every open of this journal.
use super::*;
impl Store {
    /// Whether this journal still needs the knowledge activation write. The
    /// retained cohorts are authenticated first; no state is written here.
    pub(crate) fn knowledge_activation_pending(&self) -> Result<bool, ProcessError> {
        super::unused_recovery_reservation::verify_before_open(&self.connection)?;
        super::confined_delivery::verify_before_open(&self.connection)?;
        Ok(matches!(super::feature_level(&self.connection)?, 1..=4))
    }
    pub(crate) fn require_raw_knowledge(&self) -> Result<(), ProcessError> {
        let level = super::feature_level(&self.connection)?;
        super::unused_recovery_reservation::verify_before_open(&self.connection)?;
        super::confined_delivery::verify_before_open(&self.connection)?;
        if !matches!(level, 1 | 2) {
            return Err(ProcessError::Configuration(
                "durable knowledge requires mediated release",
            ));
        }
        Ok(())
    }
    pub(crate) fn require_enforced_knowledge(&self) -> Result<(), ProcessError> {
        // Brokers never follow a replaced journal or hard-link alias. The parent
        // remains host-private; arbitrary writable filesystem backends refuse.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let file = std::fs::symlink_metadata(&self.path)?;
            if !file.is_file()
                || file.nlink() != 1
                || (file.dev(), file.ino()) != self.identity
                || file.permissions().mode() & 0o077 != 0
            {
                return Err(ProcessError::Configuration(
                    "knowledge journal identity changed",
                ));
            }
        }
        #[cfg(not(unix))]
        {
            return Err(ProcessError::Configuration(
                "durable knowledge backend is unsupported",
            ));
        }
        require_enforced_level(&self.connection)
    }
    pub(crate) fn public_process(&self, id: &str) -> Result<ProcessSnapshot, ProcessError> {
        let mut process = self.process(id)?;
        if self.require_raw_knowledge().is_err() {
            process.checkpoint.value = Value::Null;
        }
        Ok(process)
    }
    pub(crate) fn knowledge_storage_usage(
        &self,
        process: &str,
    ) -> Result<crate::ProcessStorage, ProcessError> {
        self.require_enforced_knowledge()?;
        blobs::usage(&self.connection, &self.process(process)?)
    }
    pub(crate) fn knowledge_generation(
        &self,
        process: &str,
        digest: &str,
    ) -> Result<String, ProcessError> {
        self.require_enforced_knowledge()?;
        self.require_running(process)?;
        self.connection.query_row("SELECT knowledge_generation FROM process_state_blobs WHERE process_id=?1 AND sha256=?2",params![process,digest],|row|row.get(0)).optional()?.ok_or(ProcessError::BlobMissing)
    }
    pub(crate) fn read_knowledge_blob(
        &self,
        process: &str,
        digest: &str,
        generation: &str,
    ) -> Result<Vec<u8>, ProcessError> {
        self.require_enforced_knowledge()?;
        self.require_running(process)?;
        self.read_retained_knowledge_blob(process, digest, generation)
    }

    pub(crate) fn read_retained_knowledge_blob(
        &self,
        process: &str,
        digest: &str,
        generation: &str,
    ) -> Result<Vec<u8>, ProcessError> {
        self.require_enforced_knowledge()?;
        self.process(process)?;
        let raw:Option<Option<Vec<u8>>>=self.connection.query_row("SELECT CASE WHEN typeof(data)='blob' AND length(data)<=1048576 THEN data END FROM process_state_blobs WHERE process_id=?1 AND sha256=?2 AND knowledge_generation=?3",params![process,digest,generation],|row|row.get(0)).optional()?;
        let bytes = raw
            .ok_or(ProcessError::BlobMissing)?
            .ok_or(ProcessError::BlobCorrupt)?;
        if chio_core_types::sha256_hex(&bytes) != digest {
            return Err(ProcessError::BlobCorrupt);
        }
        Ok(bytes)
    }
}

/// The complete activation body inside one writer transaction: the retained
/// cohorts are authenticated and a predecessor level is raised to the
/// enforced knowledge level exactly once.
pub(crate) fn enable_knowledge_call(tx: &rusqlite::Transaction<'_>) -> Result<(), ProcessError> {
    super::unused_recovery_reservation::verify_before_open(tx)?;
    super::confined_delivery::verify_before_open(tx)?;
    let level = super::feature_level(tx)?;
    if matches!(level, 1..=4) {
        super::raise_feature_level(tx, level, 5)?;
    }
    Ok(())
}

/// The enforced-knowledge level gate over any connection, including the
/// writer transaction of a routed write.
pub(crate) fn require_enforced_level(connection: &Connection) -> Result<(), ProcessError> {
    let level = super::feature_level(connection)?;
    super::unused_recovery_reservation::verify_before_open(connection)?;
    super::confined_delivery::verify_before_open(connection)?;
    if !matches!(level, 5..=7) {
        return Err(ProcessError::Configuration(
            "durable knowledge is not enforced",
        ));
    }
    Ok(())
}
