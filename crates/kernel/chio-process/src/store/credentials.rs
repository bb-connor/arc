use super::*;

impl Store {
    pub fn issue_worker_credential(
        &mut self,
        process_id: &str,
        hash: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<(), ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let process = read_process(&tx, process_id)?
            .ok_or_else(|| ProcessError::NotFound(process_id.to_owned()))?;
        require_running(&process)?;
        if now < process.capability.issued_at
            || expires_at <= now
            || expires_at > process.capability.expires_at
            || expires_at > i64::MAX as u64
        {
            return Err(ProcessError::Invalid(
                "credential validity must fit its live capability",
            ));
        }
        tx.execute("INSERT INTO worker_credentials(credential_hash, process_id, expires_at) VALUES (?1, ?2, ?3)",
            params![hash, process_id, expires_at as i64])?;
        tx.commit()?;
        Ok(())
    }

    pub fn authenticate_worker(&self, hash: &str, now: u64) -> Result<String, ProcessError> {
        let sql_now = i64::try_from(now).map_err(|_| ProcessError::Unauthenticated)?;
        let id: Option<String> = self.connection.query_row(
            "SELECT process_id FROM worker_credentials WHERE credential_hash = ?1 AND expires_at > ?2",
            params![hash, sql_now], |row| row.get(0),
        ).optional()?;
        let id = id.ok_or(ProcessError::Unauthenticated)?;
        let process = self.process(&id)?;
        if now < process.capability.issued_at || now >= process.capability.expires_at {
            return Err(ProcessError::Unauthenticated);
        }
        Ok(id)
    }

    pub fn revoke_worker_credentials(&mut self, process_id: &str) -> Result<usize, ProcessError> {
        Ok(self.connection.execute(
            "DELETE FROM worker_credentials WHERE process_id = ?1",
            [process_id],
        )?)
    }
}
