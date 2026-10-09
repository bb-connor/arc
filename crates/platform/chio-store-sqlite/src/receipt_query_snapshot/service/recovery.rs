//! Resource recovery keeps the configured ceiling explicit. Only the owning
//! service can raise it; public queries never allocate an increased quota.
use super::*;

impl ReceiptQuerySnapshots {
    /// Request a larger snapshot page budget without restarting the owner.
    ///
    /// This is an operator API, not an authenticated receipt request option.
    /// The walker applies the increase to its existing projection or next build
    /// and wakes from resource backoff. Quotas never increase automatically.
    /// [`Self::status`] reports the applied, page-rounded quota after publication.
    pub fn increase_quota_bytes(&self, quota_bytes: u64) -> Result<(), ReceiptStoreError> {
        let mut validated = self.inner.config.clone();
        validated.quota_bytes = quota_bytes;
        validated.validate()?;
        self.inner
            .requested_quota_bytes
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                (quota_bytes >= current).then_some(quota_bytes)
            })
            .map_err(|_| {
                ReceiptStoreError::from(ReceiptQuerySnapshotError::Unavailable(
                    "snapshot quota increase cannot lower the current operator budget".into(),
                ))
            })?;
        self.inner.wake();
        Ok(())
    }
}

impl Inner {
    pub(super) fn requested_quota(&self) -> u64 {
        self.requested_quota_bytes.load(Ordering::SeqCst)
    }
}
