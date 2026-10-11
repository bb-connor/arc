use super::*;

/// A page and its full operator head from one durable read snapshot.
/// The page may stop before the head when the response size limit is reached.
#[derive(Clone, Debug)]
pub struct KeyLogSyncSnapshot {
    pub response: KeyLogSyncResponse,
    pub head: KeyLogPin,
    pub head_stage: CheckpointStage,
}

impl SqliteKeyLogStore {
    pub fn synchronization_response(&self, base: Option<&KeyLogPin>) -> Result<KeyLogSyncResponse> {
        Ok(self.synchronization_snapshot(base)?.response)
    }

    /// Read the page, signing epoch and stage together. A local connection mutex
    /// does not exclude the operator process writing through another connection.
    pub fn synchronization_snapshot(&self, base: Option<&KeyLogPin>) -> Result<KeyLogSyncSnapshot> {
        let (events, stored_checkpoints, activation_commits, now) = {
            let mut connection = self.connection()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let events = load_events_from(&transaction)?;
            let now = self
                .clock
                .unix_millis()
                .map(chio_security_types::clock::UnixMillis::get)?;
            let checkpoints = load_checkpoints_from(&transaction)?;
            let activation_commits = load_activation_commits_from(&transaction)?;
            transaction.commit()?;
            (events, checkpoints, activation_commits, now)
        };
        // Release the SQLite snapshot before full-history signature verification,
        // replay and page encoding. The loaders still hash captured records.
        let stored = stored_checkpoints
            .last()
            .ok_or(KeyringError::StateInvariant(
                "operator key log is uninitialized",
            ))?;
        let head = KeyLogPin {
            checkpoint_sequence: stored.checkpoint.body.checkpoint_sequence,
            tree_size: stored.checkpoint.body.tree_size,
            checkpoint_hash: stored.checkpoint.checkpoint_hash()?,
            root_hash: stored.checkpoint.body.root_hash,
            signing_epoch: u64::try_from(activation_commits.len())
                .map_err(|_| KeyringError::NumericRange)?,
        };
        let head_stage = stored.stage;
        let checkpoints = stored_checkpoints
            .into_iter()
            .map(|stored| stored.checkpoint)
            .collect::<Vec<_>>();
        let response =
            self.response_from_snapshot(base, &events, &checkpoints, &activation_commits, now)?;
        Ok(KeyLogSyncSnapshot {
            response,
            head,
            head_stage,
        })
    }

    fn response_from_snapshot(
        &self,
        base: Option<&KeyLogPin>,
        events: &[SignedKeyLogEvent],
        checkpoints: &[SignedKeyLogCheckpoint],
        activation_commits: &[SignedKeyActivationCommit],
        now: u64,
    ) -> Result<KeyLogSyncResponse> {
        if events.is_empty() || events.len() != checkpoints.len() {
            return Err(KeyringError::StateInvariant(
                "key log cannot produce a synchronization response",
            ));
        }
        for checkpoint in checkpoints {
            self.policy
                .validate_checkpoint_time(checkpoint.body.issued_at, now)?;
        }
        let history = WitnessedActivationSet::verify_complete(
            events,
            checkpoints,
            activation_commits,
            &self.policy,
        )?;
        KeyLogState::replay(events.iter(), &history, &self.policy)?;

        let (checkpoint_start, event_start, commit_start, base_checkpoint_hash) =
            if let Some(pin) = base {
                let checkpoint_index = usize::try_from(pin.checkpoint_sequence)
                    .map_err(|_| KeyringError::NumericRange)?;
                let checkpoint =
                    checkpoints
                        .get(checkpoint_index)
                        .ok_or(KeyringError::InvalidCheckpoint(
                            "synchronization pin is unknown",
                        ))?;
                let expected_signing_epoch = u64::try_from(
                    activation_commits
                        .iter()
                        .filter(|commit| commit.body.checkpoint_sequence <= pin.checkpoint_sequence)
                        .count(),
                )
                .map_err(|_| KeyringError::NumericRange)?;
                if checkpoint.checkpoint_hash()? != pin.checkpoint_hash
                    || checkpoint.body.tree_size != pin.tree_size
                    || checkpoint.body.root_hash != pin.root_hash
                    || pin.signing_epoch > expected_signing_epoch
                {
                    return Err(KeyringError::InvalidCheckpoint(
                        "synchronization pin does not match durable history",
                    ));
                }
                (
                    checkpoint_index
                        .checked_add(1)
                        .ok_or(KeyringError::NumericRange)?,
                    usize::try_from(pin.tree_size).map_err(|_| KeyringError::NumericRange)?,
                    usize::try_from(pin.signing_epoch).map_err(|_| KeyringError::NumericRange)?,
                    Some(pin.checkpoint_hash),
                )
            } else {
                (0, 0, 0, None)
            };

        let maximum_page_end = crate::sync::synchronization_page_end(event_start, events.len())?;
        if maximum_page_end <= event_start {
            let maximum_commit_end = commit_start
                .checked_add(crate::sync::MAX_SYNC_ITEMS)
                .map_or(activation_commits.len(), |end| {
                    end.min(activation_commits.len())
                });
            let mut commit_end = maximum_commit_end;
            loop {
                if commit_end == commit_start && commit_start < activation_commits.len() {
                    return Err(KeyringError::Canonical(
                        "one key-log activation commit exceeds the 1048576-byte page limit"
                            .to_string(),
                    ));
                }
                let response = KeyLogSyncResponse {
                    base_checkpoint_hash,
                    checkpoints: Vec::new(),
                    event_envelopes: Vec::new(),
                    activation_commits: activation_commits
                        .get(commit_start..commit_end)
                        .ok_or(KeyringError::NumericRange)?
                        .to_vec(),
                    consistency_proof: None,
                };
                if canonical_json_bytes(&response)?.len() <= crate::MAX_CANONICAL_RECORD_BYTES {
                    response.validate_bounds()?;
                    return Ok(response);
                }
                commit_end = commit_start + (commit_end - commit_start) / 2;
            }
        }
        let mut lower = event_start
            .checked_add(1)
            .ok_or(KeyringError::NumericRange)?;
        let mut upper = maximum_page_end;
        let mut response = None;
        while lower <= upper {
            let candidate_end = lower + (upper - lower) / 2;
            let candidate = build_sync_response_page(
                events,
                checkpoints,
                activation_commits,
                SyncPageWindow {
                    checkpoint_start,
                    event_start,
                    commit_start,
                    base_checkpoint_hash,
                    page_end: candidate_end,
                },
            )?;
            if canonical_json_bytes(&candidate)?.len() <= crate::MAX_CANONICAL_RECORD_BYTES {
                response = Some(candidate);
                lower = candidate_end
                    .checked_add(1)
                    .ok_or(KeyringError::NumericRange)?;
            } else {
                upper = candidate_end.saturating_sub(1);
            }
        }
        let response = response.ok_or_else(|| {
            KeyringError::Canonical(
                "one key-log synchronization record exceeds the 1048576-byte page limit"
                    .to_string(),
            )
        })?;
        response.validate_bounds()?;
        Ok(response)
    }
}
