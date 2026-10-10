use super::*;

impl SqliteReceiptStore {
    pub(super) fn dispatch_rotate(
        &self,
        config: Box<RetentionConfig>,
        explicit_cutoff: Option<u64>,
    ) -> Result<u64, ReceiptStoreError> {
        let timeout = config.rotation_timeout;
        if timeout.is_zero() {
            return Err(ReceiptStoreError::ReadBoundary(
                "retention rotation timeout must be positive and representable".to_string(),
            ));
        }
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| {
                ReceiptStoreError::ReadBoundary(
                    "retention rotation timeout must be positive and representable".to_string(),
                )
            })?;
        if config.tenant_id.is_some() {
            // Tenant-scoped archival is not expressible as a prefix watermark,
            // so reject here before any partial work runs.
            return Err(ReceiptStoreError::RetentionTenantScopeUnsupported);
        }
        let config = match explicit_cutoff {
            Some(cutoff) => {
                let mut config = config;
                config.retention_days = 0;
                config.explicit_cutoff_unix_secs = Some(cutoff);
                config
            }
            None => config,
        };
        let (response, result) = std::sync::mpsc::sync_channel(1);
        let (completion, timeout_tracker) =
            writer_command_tracker(&self.receipt_commit_actor.health);
        let health = &self.receipt_commit_actor.health;
        self.receipt_commit_actor
            .sender
            .try_send(ReceiptCommitCommand::Rotate {
                config,
                response,
                completion,
            })?;
        match result.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(outcome) => outcome,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                timeout_tracker.note_timeout(RECEIPT_WRITE_TIMEOUT_MARKER);
                Err(ReceiptStoreError::Timeout {
                    operation: "receipt retention rotation".to_string(),
                    timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
                })
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                health.note_writer_unavailable();
                Err(receipt_actor_unavailable_error())
            }
        }
    }
}
