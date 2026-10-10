//! Existing-file original provenance without entering the process writer mutex.
use super::*;
use rusqlite::OpenFlags;
use std::path::PathBuf;

pub(crate) struct OriginalProcessSnapshot {
    path: PathBuf,
    namespace: String,
    authority: String,
    kernel_key: String,
    #[cfg(unix)]
    identity: (u64, u64),
}
impl Store {
    pub(crate) fn original_snapshot(
        &self,
        authority: &str,
        kernel_key: &str,
    ) -> OriginalProcessSnapshot {
        OriginalProcessSnapshot {
            path: self.path.clone(),
            namespace: self.namespace.clone(),
            authority: authority.into(),
            kernel_key: kernel_key.into(),
            #[cfg(unix)]
            identity: self.identity,
        }
    }
}
impl OriginalProcessSnapshot {
    pub(super) fn verify_path(&self) -> Result<(), ProcessError> {
        let file = std::fs::symlink_metadata(&self.path)?;
        let parent = self.path.parent().ok_or(ProcessError::Conflict)?;
        let directory = std::fs::symlink_metadata(parent)?;
        if !file.is_file() || !directory.is_dir() || std::fs::canonicalize(&self.path)? != self.path
        {
            return Err(ProcessError::Conflict);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if file.nlink() != 1
                || (file.permissions().mode() | directory.permissions().mode()) & 0o077 != 0
                || (file.dev(), file.ino()) != self.identity
            {
                return Err(ProcessError::Conflict);
            }
        }
        Ok(())
    }
    pub(crate) fn original_call_key(
        &self,
        process: &str,
        request: &ToolCallRequest,
        bindings: &[String; 2],
    ) -> Result<String, ProcessError> {
        self.verify_path()?;
        let mut connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::ZERO)?;
        self.verify_path()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let metadata:(i64,Option<String>,Option<String>,Option<String>)=tx.query_row(
            "SELECT version,CASE WHEN typeof(namespace)='text' AND length(CAST(namespace AS BLOB)) BETWEEN 1 AND 256 THEN namespace END, CASE WHEN typeof(authority)='text' AND length(CAST(authority AS BLOB)) BETWEEN 1 AND 256 THEN authority END, CASE WHEN typeof(kernel_key)='text' AND length(CAST(kernel_key AS BLOB)) BETWEEN 1 AND 32768 THEN kernel_key END FROM process_runtime WHERE singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        )?;
        super::unused_recovery_reservation::verify_before_open(&tx)?;
        super::confined_delivery::verify_before_open(&tx)?;
        if !matches!(metadata.0, 1..=7) {
            return Err(ProcessError::Invalid(
                "unsupported original process journal version",
            ));
        }
        if metadata.1.as_deref() != Some(self.namespace.as_str())
            || metadata.2.as_deref() != Some(self.authority.as_str())
            || metadata.3.as_deref() != Some(self.kernel_key.as_str())
        {
            return Err(ProcessError::Conflict);
        }
        let key = {
            let mut query=tx.prepare("SELECT CASE WHEN typeof(c.operation_key)='text' AND length(CAST(c.operation_key AS BLOB)) BETWEEN 1 AND 256 THEN c.operation_key END,c.attempts,CASE WHEN typeof(p.capability)='text' AND length(CAST(p.capability AS BLOB)) BETWEEN 1 AND 262144 THEN p.capability END FROM processes p JOIN process_calls c ON c.process_id=p.id WHERE p.id=?1 AND c.request_hash IN (?2,?3) LIMIT 2")?;
            let mut rows =
                query.query(params![process, bindings[0].as_str(), bindings[1].as_str()])?;
            let row = rows.next()?.ok_or(ProcessError::Conflict)?;
            let key: Option<String> = row.get(0)?;
            let attempts: i64 = row.get(1)?;
            let capability: Option<String> = row.get(2)?;
            let capability: CapabilityToken = serde_json::from_str(&capability.ok_or(
                ProcessError::Invalid("original capability exceeds its wire bound"),
            )?)?;
            if rows.next()?.is_some()
                || attempts != 1
                || crate::digest(&capability)? != crate::digest(&request.capability)?
                || request.agent_id != capability.subject.to_hex()
            {
                return Err(ProcessError::Conflict);
            }
            key.ok_or(ProcessError::Invalid(
                "original process key exceeds its bound",
            ))?
        };
        self.verify_path()?;
        tx.commit()?;
        self.verify_path()?;
        Ok(key)
    }
}
