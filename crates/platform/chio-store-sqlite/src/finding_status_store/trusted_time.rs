use super::*;

impl SqliteFindingStatusStore {
    /// Advance the rollback-protected trusted-time floor for one status feed.
    ///
    /// The feed floor is already covered by the authenticated finding-status
    /// projection, so reusing its monotonic timestamp keeps clock continuity
    /// across verifier clones and process restarts without creating an
    /// unanchored side table. Equal observations are exact replays. A wall
    /// clock below the retained floor fails closed.
    pub fn observe_trusted_time(
        &self,
        feed_id: &str,
        trusted_now: u64,
    ) -> Result<FindingStatusWriteOutcome, FindingStatusStoreError> {
        self.observe_trusted_time_with_clock(feed_id, || Ok(trusted_now))
            .map(|(outcome, _)| outcome)
    }

    /// Sample and advance trusted time only after acquiring the durable write
    /// transaction. This closes expiry races for callers that must perform a
    /// final freshness check after a potentially blocking feed read.
    pub fn observe_trusted_time_with_clock(
        &self,
        feed_id: &str,
        read_now: impl FnOnce() -> Result<u64, chio_security_types::clock::ClockError>,
    ) -> Result<(FindingStatusWriteOutcome, u64), FindingStatusStoreError> {
        require_identifier(feed_id, "feed_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        ensure_feed_registered_tx(&transaction, feed_id)?;
        let trusted_now = read_now()?;
        require_positive(trusted_now, "trusted_now")?;
        let outcome = advance_trusted_time_floor_tx(&transaction, feed_id, trusted_now)?;
        if outcome == FindingStatusWriteOutcome::ExactReplay {
            transaction.commit().map_err(sqlite_error)?;
        } else {
            self.commit_write(transaction)?;
            self.sync_after_write(&connection)?;
        }
        Ok((outcome, trusted_now))
    }
}
