use super::*;

impl RemoteSessionLedger {
    pub(super) fn new(
        clock: RemoteClock,
        lifecycle_policy: SessionLifecyclePolicy,
        tombstone_db_path: Option<PathBuf>,
        resume_hmac_keyring: Option<Arc<RemoteSessionHmacKeyring>>,
    ) -> Result<Self, CliError> {
        let terminal = if let Some(path) = tombstone_db_path.as_deref() {
            let keyring = resume_hmac_keyring.as_deref().ok_or_else(|| {
                CliError::cli_other_error(
                    "durable MCP terminal state requires a dedicated resume HMAC keyring"
                        .to_string(),
                )
            })?;
            load_terminal_session_records(path, keyring, clock.millis()?)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            clock,
            active: Arc::new(Mutex::new(HashMap::new())),
            terminal: Arc::new(Mutex::new(terminal)),
            lifecycle_policy,
            tombstone_db_path,
            resume_hmac_keyring,
        })
    }

    pub(super) async fn insert_active(&self, session: Arc<RemoteSession>) {
        self.active
            .lock()
            .await
            .insert(session.session_id.clone(), session);
    }

    pub(super) async fn remove_active(&self, session_id: &str) -> Option<Arc<RemoteSession>> {
        self.active.lock().await.remove(session_id)
    }

    pub(super) async fn lookup(&self, session_id: &str) -> Option<RemoteSessionEntry> {
        if let Some(session) = self.active.lock().await.get(session_id).cloned() {
            return Some(RemoteSessionEntry::Active(session));
        }

        self.terminal
            .lock()
            .await
            .get(session_id)
            .cloned()
            .map(RemoteSessionEntry::Terminal)
    }

    pub(super) async fn snapshot(
        &self,
    ) -> (
        Vec<RemoteSessionDiagnosticRecord>,
        Vec<RemoteSessionDiagnosticRecord>,
    ) {
        let active = self
            .active
            .lock()
            .await
            .values()
            .map(|session| session.diagnostic_record())
            .collect::<Vec<_>>();
        let terminal = self
            .terminal
            .lock()
            .await
            .values()
            .map(|record| (*record.as_ref()).clone())
            .collect::<Vec<_>>();
        (active, terminal)
    }

    pub(super) async fn mark_deleted(&self, session: &Arc<RemoteSession>) -> Result<(), CliError> {
        self.transition_to_terminal(session, RemoteSessionState::Deleted)
            .await
    }

    pub(super) async fn mark_draining(&self, session: &Arc<RemoteSession>) -> Result<(), CliError> {
        session.begin_draining()
    }

    pub(super) async fn mark_closed(&self, session: &Arc<RemoteSession>) -> Result<(), CliError> {
        self.transition_to_terminal(session, RemoteSessionState::Closed)
            .await
    }

    pub(super) async fn mark_expired(&self, session: &Arc<RemoteSession>) -> Result<(), CliError> {
        self.transition_to_terminal(session, RemoteSessionState::Expired)
            .await
    }

    pub(super) async fn cleanup_due_sessions(&self) -> Result<(), CliError> {
        let now = self.clock.millis()?;
        let sessions = {
            let guard = self.active.lock().await;
            guard.values().cloned().collect::<Vec<_>>()
        };

        for session in sessions {
            let expired = session.deadline_expired()?;
            let snapshot = session.lifecycle_snapshot();
            match snapshot.state {
                RemoteSessionState::Ready if expired => match self.mark_expired(&session).await {
                    Ok(()) => {}
                    Err(error) => {
                        warn!(
                            session_id = %session.session_id,
                            error = %error,
                            "failed to expire MCP session without resumable-state risk"
                        );
                    }
                },
                RemoteSessionState::Ready => {}
                RemoteSessionState::Draining => {
                    if expired {
                        match self.mark_deleted(&session).await {
                            Ok(()) => {}
                            Err(error) => {
                                warn!(
                                    session_id = %session.session_id,
                                    error = %error,
                                    "failed to delete drained MCP session without resumable-state risk"
                                );
                            }
                        }
                    }
                }
                RemoteSessionState::Initializing
                | RemoteSessionState::Deleted
                | RemoteSessionState::Expired => {}
                RemoteSessionState::Closed => {
                    self.active.lock().await.remove(&session.session_id);
                }
            }
        }

        self.purge_old_terminal_records(now).await;
        Ok(())
    }

    pub(super) async fn shutdown_all_active(&self) -> Result<(), CliError> {
        let sessions = {
            let guard = self.active.lock().await;
            guard.values().cloned().collect::<Vec<_>>()
        };
        let mut failures = Vec::new();
        for session in sessions {
            match self.mark_closed(&session).await {
                Ok(()) => {
                    self.active.lock().await.remove(&session.session_id);
                }
                Err(error) => failures.push(format!("{}: {error}", session.session_id)),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(CliError::cli_other_error(format!(
                "failed to terminalize {} MCP session(s): {}",
                failures.len(),
                failures.join("; ")
            )))
        }
    }

    pub(super) async fn transition_to_terminal(
        &self,
        session: &Arc<RemoteSession>,
        state: RemoteSessionState,
    ) -> Result<(), CliError> {
        match state {
            RemoteSessionState::Deleted
            | RemoteSessionState::Expired
            | RemoteSessionState::Closed => {}
            RemoteSessionState::Initializing
            | RemoteSessionState::Ready
            | RemoteSessionState::Draining => {
                return Err(CliError::cli_other_error(format!(
                    "unsupported terminal MCP session state: {}",
                    state.as_str()
                )));
            }
        }
        let _terminalization = session.terminalization.lock().await;
        let mut record = session.diagnostic_record();
        let (terminal_at, durable_tombstone) = {
            // Serialize renewal with expiry adjudication and durable terminal intent.
            let mut lifecycle = session
                .lifecycle
                .lock()
                .map_err(|_| ClockError::Unavailable)?;
            if lifecycle.state.is_terminal() {
                return Ok(());
            }
            let reading = self.clock.read()?;
            if state == RemoteSessionState::Expired {
                if lifecycle.state != RemoteSessionState::Ready {
                    return Ok(());
                }
                match lifecycle
                    .deadline
                    .as_mut()
                    .ok_or(ClockError::InvalidWindow)?
                    .remaining(reading)
                {
                    Ok(_) => return Ok(()),
                    Err(ClockError::Expired) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            let terminal_at = reading.unix_millis().get();
            record.lifecycle = lifecycle.clone();
            record.lifecycle.state = state;
            record.lifecycle.last_seen_at = terminal_at;
            record.lifecycle.drain_deadline_at = None;
            record.terminal_at = terminal_at;
            let durable_tombstone = if let Some(path) = self.tombstone_db_path.as_deref() {
                session.ensure_session_store_owned()?;
                let keyring = self.resume_hmac_keyring.as_deref().ok_or_else(|| {
                    CliError::cli_other_error(format!(
                    "failed to terminalize MCP session {} without a dedicated resume HMAC keyring",
                    session.session_id
                ))
                })?;
                let terminal_epoch = session.next_terminal_persistence_epoch()?;
                let (tombstone, fence) = sign_terminal_session_records(
                    keyring,
                    record.clone(),
                    terminal_epoch,
                    terminal_epoch,
                )?;
                prepare_terminal_session_transition(path, &fence, keyring, terminal_at)?;
                Some((path, keyring, tombstone))
            } else {
                None
            };

            lifecycle.state = state;
            lifecycle.last_seen_at = terminal_at;
            lifecycle.drain_deadline_at = None;
            lifecycle.deadline = None;
            (terminal_at, durable_tombstone)
        };
        self.active.lock().await.remove(&session.session_id);

        // The durable terminal intent and active-row deletion are committed
        // before the owned upstream transport receives its terminal effect.
        // The in-memory session is also made terminal and removed from active
        // lookup before shutdown is attempted. A crash or shutdown error can
        // therefore expose neither durable resume nor live dispatch authority.
        // Shared-owner session shutdown remains a no-op here; the shared native
        // transport is closed once at service shutdown.
        let shutdown_result = session.shutdown_upstream_transport();

        let finalization_result = if let Some((path, keyring, tombstone)) = durable_tombstone {
            let result = session.ensure_session_store_owned().and_then(|()| {
                finalize_terminal_session_transition(path, &tombstone, keyring, terminal_at)
            });
            record = tombstone.record;
            result
        } else {
            Ok(())
        };

        self.terminal
            .lock()
            .await
            .insert(session.session_id.clone(), Arc::new(record));
        match (shutdown_result, finalization_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(shutdown_error), Err(finalization_error)) => {
                Err(CliError::cli_other_error(format!(
                    "MCP session {} upstream shutdown failed: {shutdown_error}; terminal diagnostic finalization also failed: {finalization_error}",
                    session.session_id
                )))
            }
        }
    }

    pub(super) async fn purge_old_terminal_records(&self, now: u64) {
        let retention = self.lifecycle_policy.tombstone_retention_millis;
        let Some(cutoff) = now.checked_sub(retention) else {
            return;
        };
        let mut terminal = self.terminal.lock().await;
        terminal.retain(|_, record| record.terminal_at >= cutoff);
        if let Some(path) = self.tombstone_db_path.as_deref() {
            if let Err(error) = purge_terminal_session_records_before(path, cutoff) {
                warn!(
                    cutoff,
                    error = %error,
                    "failed to purge expired MCP session tombstones"
                );
            }
        }
    }
}
