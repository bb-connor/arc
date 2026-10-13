use super::*;

/// The owning enqueue path returned before a message entered the MCP inbox.
/// No fallible operation follows a successful inbox send on this path.
#[derive(Debug)]
pub(super) struct NotEnqueued(CliError);

impl NotEnqueued {
    pub(super) fn into_error(self) -> CliError {
        self.0
    }
}

impl RemoteSession {
    pub(super) fn new(init: RemoteSessionInit) -> Result<Self, CliError> {
        let reading = init.clock.read()?;
        let now = reading.unix_millis().get();
        let mut lifecycle_snapshot =
            init.lifecycle_snapshot
                .unwrap_or(RemoteSessionLifecycleSnapshot {
                    deadline: None,
                    state: RemoteSessionState::Initializing,
                    created_at: now,
                    last_seen_at: now,
                    idle_expires_at: now,
                    drain_deadline_at: None,
                });
        if lifecycle_snapshot.state == RemoteSessionState::Ready {
            lifecycle_snapshot.drain_deadline_at = None;
            lifecycle_snapshot.deadline = Some(AuthorityDeadline::new(
                UnixMillis::new(lifecycle_snapshot.last_seen_at),
                UnixMillis::new(lifecycle_snapshot.idle_expires_at),
                reading,
            )?);
        }
        let resume_envelope = ResumeEnvelopeRatchet::new(init.lifecycle_policy.resume_envelope_floor);
        Ok(Self {
            clock: init.clock,
            session_id: init.session_id,
            agent_id: init.agent_id,
            capabilities: init.capabilities,
            issued_capabilities: init.issued_capabilities,
            auth_context: init.auth_context,
            auth_mode_fingerprint: init.auth_mode_fingerprint,
            policy_fingerprint: init.policy_fingerprint,
            runtime_contract_fingerprint: init.runtime_contract_fingerprint,
            hosted_isolation: init.hosted_isolation,
            lifecycle_policy: init.lifecycle_policy,
            protocol_version: StdMutex::new(init.protocol_version),
            peer_capabilities: StdMutex::new(init.peer_capabilities),
            initialize_params: StdMutex::new(init.initialize_params),
            lifecycle: StdMutex::new(lifecycle_snapshot),
            terminalization: Mutex::new(()),
            input_tx: init.input_tx,
            event_tx: init.event_tx,
            retained_notification_events: init.retained_notification_events,
            active_request_stream: Arc::new(Mutex::new(())),
            worker_serving_closed: tokio::sync::watch::channel(false).0,
            notification_stream_attached: Arc::new(AtomicBool::new(false)),
            next_event_id: init.next_event_id,
            session_db_path: init.session_db_path,
            approval_redemption: init.approval_redemption,
            session_store_lease: init.session_store_lease,
            resume_hmac_keyring: init.resume_hmac_keyring,
            resume_generation: AtomicU64::new(init.resume_generation),
            resume_envelope,
            subscriptions: StdMutex::new(BTreeMap::new()),
            subscription_deadline: StdMutex::new(SubscriptionDeadline::Unbounded),
            terminal_reason_latch: std::sync::OnceLock::new(),
            upstream_transport: RemoteSessionUpstreamTransport {
                inner: init.upstream_transport,
            },
        })
    }

    pub(super) fn send(&self, message: Value) -> Result<(), CliError> {
        {
            let mut lifecycle = self.lifecycle.lock().map_err(|_| ClockError::Unavailable)?;
            self.check_enqueue_lifecycle(&message, &mut lifecycle)?;
        }
        let message = self.input_tx.account(message)?;
        self.send_accounted(message)
            .map_err(NotEnqueued::into_error)
    }

    pub(super) fn send_accounted(&self, message: AccountedMessage) -> Result<(), NotEnqueued> {
        remote_mcp_approvals::validate_redemption(self, &message).map_err(NotEnqueued)?;
        // Redemption can inspect lifecycle itself. Take the lock afterward and
        // retain it through enqueue, serializing with drain/terminal transitions.
        let mut lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| NotEnqueued(ClockError::Unavailable.into()))?;
        self.check_enqueue_lifecycle(&message, &mut lifecycle)
            .map_err(NotEnqueued)?;
        self.input_tx
            .send(message)
            .map_err(|error| NotEnqueued(error.into()))
    }

    pub(super) fn record_protocol_refusal(
        &self,
        message: AccountedMessage,
        summary: chio_kernel::ProtocolRefusalSummary,
    ) -> Result<chio_mcp_adapter::edge::ingress::ProtocolRefusalAcknowledgement, CliError> {
        let mut lifecycle = self.lifecycle.lock().map_err(|_| ClockError::Unavailable)?;
        if lifecycle.state != RemoteSessionState::Ready {
            return Err(chio_kernel::KernelError::GovernedTransactionDenied(
                "remote MCP session cannot record scoped refusal in its current state".into(),
            )
            .into());
        }
        lifecycle
            .deadline
            .as_mut()
            .ok_or(ClockError::InvalidWindow)?
            .remaining(self.clock.read()?)?;
        self.input_tx
            .record_protocol_refusal(message, summary)
            .map_err(Into::into)
    }

    fn check_enqueue_lifecycle(
        &self,
        message: &Value,
        lifecycle: &mut RemoteSessionLifecycleSnapshot,
    ) -> Result<(), CliError> {
        if *self.worker_serving_closed.borrow() {
            return Err(chio_kernel::KernelError::GovernedTransactionDenied(
                "remote MCP session worker is unavailable".into(),
            )
            .into());
        }
        match lifecycle.state {
            RemoteSessionState::Ready => {
                lifecycle
                    .deadline
                    .as_mut()
                    .ok_or(ClockError::InvalidWindow)?
                    .remaining(self.clock.read()?)?;
            }
            // An ephemeral stateless session never leaves Initializing; the
            // edge opens its kernel session from the request itself.
            RemoteSessionState::Initializing
                if message.get("id").is_some()
                    && (message.get("method").and_then(Value::as_str) == Some("initialize")
                        || chio_mcp_adapter::edge::stateless::requested_protocol_version(message)
                            .is_some()) => {}
            _ => {
                return Err(chio_kernel::KernelError::GovernedTransactionDenied(
                    "remote MCP session does not admit this message in its current state".into(),
                )
                .into())
            }
        }
        Ok(())
    }

    pub(super) fn subscribe(&self) -> broadcast::Receiver<RemoteSessionEvent> {
        self.event_tx.subscribe()
    }

    pub(super) fn next_stream_event_id(&self) -> Result<String, ClockError> {
        let next = crate::clock::next_counter(&self.next_event_id)?;
        Ok(format!("{}-{next}", self.session_id))
    }

    pub(super) fn has_active_notification_stream(&self) -> bool {
        self.notification_stream_attached.load(Ordering::SeqCst)
    }

    pub(super) fn has_active_request_stream(&self) -> bool {
        self.active_request_stream.try_lock().is_err()
    }

    pub(super) fn try_attach_notification_stream(&self) -> bool {
        self.notification_stream_attached
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub(super) fn detach_notification_stream(&self) {
        self.notification_stream_attached
            .store(false, Ordering::SeqCst);
    }

    pub(super) fn replay_notifications_after(
        &self,
        last_event_id: Option<&str>,
    ) -> Result<(u64, Vec<RemoteSessionEvent>), Response> {
        let Some(last_event_id) = last_event_id else {
            let retained = self.retained_notification_events.lock().map_err(|_| {
                plain_http_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to inspect retained session notifications",
                )
            })?;
            return Ok((
                0,
                retained
                    .iter()
                    .map(|event| RemoteSessionEvent {
                        seq: event.seq,
                        event_id: event.event_id.clone(),
                        kind: classify_remote_session_event(&event.message, false),
                        request_generation: None,
                        message: event.message.clone(),
                    })
                    .collect(),
            ));
        };

        let replay_after = parse_session_event_id(last_event_id, &self.session_id)
            .map_err(|message| plain_http_error(StatusCode::CONFLICT, &message))?;
        let retained = self.retained_notification_events.lock().map_err(|_| {
            plain_http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to inspect retained session notifications",
            )
        })?;

        if retained.is_empty() {
            return Err(plain_http_error(
                StatusCode::CONFLICT,
                "notification replay cursor is no longer provable for this session",
            ));
        }

        let oldest = retained.front().map(|event| event.seq).unwrap_or_default();
        let newest = retained.back().map(|event| event.seq).unwrap_or_default();
        if replay_after < oldest.saturating_sub(1) || replay_after > newest {
            return Err(plain_http_error(
                StatusCode::CONFLICT,
                "notification replay cursor is outside the retained session window",
            ));
        }

        let replay = retained
            .iter()
            .filter(|event| event.seq > replay_after)
            .map(|event| RemoteSessionEvent {
                seq: event.seq,
                event_id: event.event_id.clone(),
                // The retained schema is unchanged. Only session-owned messages
                // enter this window; restore their kind from preserved shape.
                kind: classify_remote_session_event(&event.message, false),
                request_generation: None,
                message: event.message.clone(),
            })
            .collect();
        Ok((replay_after, replay))
    }

    pub(super) fn protocol_version(&self) -> Option<String> {
        self.protocol_version
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    pub(super) fn lifecycle_snapshot(&self) -> RemoteSessionLifecycleSnapshot {
        self.lifecycle
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or(RemoteSessionLifecycleSnapshot {
                deadline: None,
                state: RemoteSessionState::Closed,
                created_at: 0,
                last_seen_at: 0,
                idle_expires_at: 0,
                drain_deadline_at: None,
            })
    }

    pub(super) fn resume_record(&self) -> Result<Option<RemoteSessionResumeRecord>, CliError> {
        let lifecycle = self
            .lifecycle
            .lock()
            .map_err(|_| {
                CliError::cli_other_error(format!(
                    "failed to lock lifecycle state for MCP session {}",
                    self.session_id
                ))
            })?
            .clone();
        if lifecycle.state != RemoteSessionState::Ready {
            return Ok(None);
        }
        self.resume_record_for_lifecycle(lifecycle, self.persisted_subscriptions()?)
            .map(Some)
    }

    /// Signs and persists the restored record at the generation its event
    /// seed was derived from, before the session serves.
    pub(super) fn persist_restored_generation(&self) -> Result<(), CliError> {
        let path = self.session_db_path.as_deref().ok_or_else(|| {
            CliError::cli_other_error(format!(
                "restored MCP session {} has no session database",
                self.session_id
            ))
        })?;
        let record = self.resume_record()?.ok_or_else(|| {
            CliError::cli_other_error(format!(
                "restored MCP session {} is not ready",
                self.session_id
            ))
        })?;
        self.persist_record(path, &record, self.clock.millis()?)
    }

    /// Installs the subscriptions a restored record carried. Persisting them is
    /// left to the restored-generation write.
    pub(super) fn restore_subscriptions(
        &self,
        subscriptions: &[PersistedSubscription],
    ) -> Result<(), CliError> {
        let mut current = self
            .subscriptions
            .lock()
            .map_err(|_| ClockError::Unavailable)?;
        *current = subscriptions
            .iter()
            .map(|subscription| {
                let PersistedSubscription::Standard { uri, capability_id } = subscription;
                (uri.clone(), capability_id.clone())
            })
            .collect();
        self.arm_subscription_deadline(&current);
        Ok(())
    }

    /// Arms the deadline at the earliest expiry among the capabilities bound
    /// to `subscriptions`. A capability that is not held, or a clock that
    /// cannot be read, leaves the deadline lapsed.
    fn arm_subscription_deadline(&self, subscriptions: &BTreeMap<String, String>) {
        let earliest = subscriptions
            .values()
            .map(|capability_id| {
                self.issued_capabilities
                    .iter()
                    .find(|capability| &capability.id == capability_id)
                    .map_or(0, |capability| capability.expires_at)
            })
            .min();
        let deadline = match earliest {
            None => SubscriptionDeadline::Unbounded,
            Some(expires_at) => self
                .clock
                .read()
                .and_then(|reading| {
                    let expires_at = expires_at.checked_mul(1_000).ok_or(ClockError::Overflow)?;
                    AuthorityDeadline::new(reading.unix_millis(), UnixMillis::new(expires_at), reading)
                })
                .map_or(SubscriptionDeadline::Lapsed, SubscriptionDeadline::Armed),
        };
        *self
            .subscription_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = deadline;
    }

    /// Whether a subscribed capability's authority window has closed. A clock
    /// that cannot be read or that moved backwards counts as closed.
    pub(super) fn subscription_authority_expired(&self) -> bool {
        let mut deadline = self
            .subscription_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &mut *deadline {
            SubscriptionDeadline::Unbounded => false,
            SubscriptionDeadline::Lapsed => true,
            SubscriptionDeadline::Armed(armed) => self
                .clock
                .read()
                .and_then(|reading| armed.remaining(reading))
                .is_err(),
        }
    }

    /// Latches `subscription_authority_lost`, drops retained resource updates
    /// and wakes every HTTP wait. The next terminal transition uses the reason.
    pub(super) fn latch_subscription_authority_lost(&self) {
        self.terminal_reason_latch
            .get_or_init(|| TerminalReason::SubscriptionAuthorityLost);
        self.retained_notification_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|event| {
                event.message.get("method").and_then(Value::as_str)
                    != Some("notifications/resources/updated")
            });
        self.worker_serving_closed.send_replace(true);
    }

    pub(super) fn latched_terminal_reason(&self) -> Option<TerminalReason> {
        self.terminal_reason_latch.get().copied()
    }

    pub(super) fn persisted_subscriptions(&self) -> Result<Vec<PersistedSubscription>, CliError> {
        let subscriptions = self
            .subscriptions
            .lock()
            .map_err(|_| ClockError::Unavailable)?;
        Ok(standard_subscriptions(&subscriptions))
    }

    /// Applies `change` to the subscription set. A durable session signs and
    /// persists the changed record first, and keeps the old set if that fails.
    fn change_subscriptions(
        &self,
        change: impl FnOnce(&mut BTreeMap<String, String>),
    ) -> Result<(), CliError> {
        let lifecycle = self.lifecycle.lock().map_err(|_| ClockError::Unavailable)?;
        let mut current = self
            .subscriptions
            .lock()
            .map_err(|_| ClockError::Unavailable)?;
        let mut candidate = current.clone();
        change(&mut candidate);
        if candidate == *current {
            return Ok(());
        }
        if let Some(path) = self.session_db_path.as_deref() {
            if lifecycle.state != RemoteSessionState::Ready {
                return Err(CliError::cli_other_error(format!(
                    "MCP session {} persists subscriptions only while ready",
                    self.session_id
                )));
            }
            let record = self
                .resume_record_for_lifecycle(lifecycle.clone(), standard_subscriptions(&candidate))?;
            self.persist_record(path, &record, self.clock.millis()?)?;
        }
        self.arm_subscription_deadline(&candidate);
        *current = candidate;
        Ok(())
    }

    fn resume_record_for_lifecycle(
        &self,
        lifecycle: RemoteSessionLifecycleSnapshot,
        subscriptions: Vec<PersistedSubscription>,
    ) -> Result<RemoteSessionResumeRecord, CliError> {
        let protocol_version = self
            .protocol_version
            .lock()
            .map_err(|_| {
                CliError::cli_other_error(format!(
                    "failed to lock protocol version for MCP session {}",
                    self.session_id
                ))
            })?
            .clone();
        let peer_capabilities = self
            .peer_capabilities
            .lock()
            .map_err(|_| {
                CliError::cli_other_error(format!(
                    "failed to lock peer capabilities for MCP session {}",
                    self.session_id
                ))
            })?
            .clone()
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "ready MCP session {} is missing peer capabilities",
                    self.session_id
                ))
            })?;
        let initialize_params = self
            .initialize_params
            .lock()
            .map_err(|_| {
                CliError::cli_other_error(format!(
                    "failed to lock initialize parameters for MCP session {}",
                    self.session_id
                ))
            })?
            .clone()
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "ready MCP session {} is missing initialize parameters",
                    self.session_id
                ))
            })?;
        self.sign_resume_record(
            lifecycle,
            protocol_version,
            peer_capabilities,
            initialize_params,
            subscriptions,
        )
    }

    fn sign_resume_record(
        &self,
        lifecycle: RemoteSessionLifecycleSnapshot,
        protocol_version: Option<String>,
        peer_capabilities: PeerCapabilities,
        initialize_params: Value,
        subscriptions: Vec<PersistedSubscription>,
    ) -> Result<RemoteSessionResumeRecord, CliError> {
        let keyring = self.resume_hmac_keyring.as_ref().ok_or_else(|| {
            CliError::cli_other_error(format!(
                "ready MCP session {} is missing its resume HMAC keyring",
                self.session_id
            ))
        })?;
        let envelope = self.resume_envelope.select(&subscriptions);
        let resume_generation = crate::clock::next_counter(&self.resume_generation)?;
        let mut record = RemoteSessionResumeRecord {
            session_id: self.session_id.clone(),
            agent_id: self.agent_id.clone(),
            auth_context: self.auth_context.clone(),
            auth_mode_fingerprint: Some(self.auth_mode_fingerprint.clone()),
            policy_fingerprint: Some(self.policy_fingerprint.clone()),
            runtime_contract_fingerprint: self.runtime_contract_fingerprint.clone(),
            hosted_isolation: self.hosted_isolation,
            lifecycle,
            protocol_version,
            peer_capabilities,
            initialize_params,
            issued_capabilities: self.issued_capabilities.clone(),
            subscriptions,
            resume_generation,
            resume_integrity: keyring.empty_tag_for_current(),
        };
        record.resume_integrity.envelope = envelope;
        record.resume_integrity.tag =
            compute_resume_record_integrity_tag(&keyring.current, &record)?;
        Ok(record)
    }

    fn persist_record(
        &self,
        path: &FsPath,
        record: &RemoteSessionResumeRecord,
        now: u64,
    ) -> Result<(), CliError> {
        let keyring = self.resume_hmac_keyring.as_deref().ok_or_else(|| {
            CliError::cli_other_error("resumable MCP session requires a dedicated HMAC keyring")
        })?;
        self.ensure_session_store_owned()?;
        persist_active_session_record(path, record, keyring, now)
    }

    pub(super) fn remove_resumable_record(&self) -> Result<(), CliError> {
        let Some(path) = self.session_db_path.as_deref() else {
            return Ok(());
        };
        self.ensure_session_store_owned()?;
        delete_active_session_record(path, &self.session_id)
    }

    pub(super) fn ensure_session_store_owned(&self) -> Result<(), CliError> {
        match self.session_store_lease.as_deref() {
            Some(lease) => lease.ensure_owned(),
            None if self.session_db_path.is_some() => Err(CliError::cli_other_error(
                "remote MCP session has no retained database ownership lease".to_string(),
            )),
            None => Ok(()),
        }
    }

    pub(super) fn next_terminal_persistence_epoch(&self) -> Result<u64, CliError> {
        Ok(crate::clock::next_counter(&self.resume_generation)?)
    }

    pub(super) fn shutdown_upstream_transport(&self) -> Result<(), CliError> {
        self.upstream_transport.inner.shutdown().map_err(|error| {
            CliError::cli_other_error(format!(
                "MCP session {} terminal receipt persistence failed: {error}",
                self.session_id
            ))
        })
    }

    pub(super) fn mark_ready(
        &self,
        protocol_version: Option<String>,
        initialize_params: Value,
        peer_capabilities: PeerCapabilities,
    ) -> Result<(), CliError> {
        let mut lifecycle = self.lifecycle.lock().map_err(|_| ClockError::Unavailable)?;
        if lifecycle.state != RemoteSessionState::Initializing {
            return Err(CliError::cli_other_error(
                "only an initializing MCP session can become ready",
            ));
        }
        let reading = self.clock.read()?;
        let deadline =
            AuthorityDeadline::for_timeout_ms(reading, self.lifecycle_policy.idle_expiry_millis)?;
        let now = reading.unix_millis();
        let expires = now.checked_add(self.lifecycle_policy.idle_expiry_millis)?;
        // Acquire every metadata lock before changing any state. A failed clock
        // or poisoned lock leaves the initialization available for retry.
        let mut version = self
            .protocol_version
            .lock()
            .map_err(|_| ClockError::Unavailable)?;
        let mut params = self
            .initialize_params
            .lock()
            .map_err(|_| ClockError::Unavailable)?;
        let mut capabilities = self
            .peer_capabilities
            .lock()
            .map_err(|_| ClockError::Unavailable)?;
        let mut proposed = lifecycle.clone();
        proposed.state = RemoteSessionState::Ready;
        proposed.last_seen_at = now.get();
        proposed.idle_expires_at = expires.get();
        proposed.deadline = Some(deadline);
        proposed.drain_deadline_at = None;
        if let Some(path) = self.session_db_path.as_deref() {
            let record = self.sign_resume_record(
                proposed.clone(),
                protocol_version.clone(),
                peer_capabilities.clone(),
                initialize_params.clone(),
                self.persisted_subscriptions()?,
            )?;
            self.persist_record(path, &record, now.get())?;
        }
        *version = protocol_version;
        *params = Some(initialize_params);
        *capabilities = Some(peer_capabilities);
        *lifecycle = proposed;
        Ok(())
    }

    pub(super) fn touch(&self) -> Result<(), CliError> {
        let mut lifecycle = self.lifecycle.lock().map_err(|_| ClockError::Unavailable)?;
        if lifecycle.state != RemoteSessionState::Ready {
            return Ok(());
        }
        let reading = self.clock.read()?;
        let mut proposed = lifecycle.clone();
        proposed
            .deadline
            .as_mut()
            .ok_or(ClockError::InvalidWindow)?
            .remaining(reading)?;
        let now = reading.unix_millis();
        let deadline =
            AuthorityDeadline::for_timeout_ms(reading, self.lifecycle_policy.idle_expiry_millis)?;
        let expires = now.checked_add(self.lifecycle_policy.idle_expiry_millis)?;
        let persist = now.duration_since(UnixMillis::new(lifecycle.last_seen_at))?
            >= SESSION_TOUCH_PERSIST_INTERVAL_MILLIS;
        proposed.last_seen_at = now.get();
        proposed.idle_expires_at = expires.get();
        proposed.deadline = Some(deadline);
        if persist {
            if let Some(path) = self.session_db_path.as_deref() {
                let record = self
                    .resume_record_for_lifecycle(proposed.clone(), self.persisted_subscriptions()?)?;
                self.persist_record(path, &record, now.get())?;
            }
        }
        *lifecycle = proposed;
        Ok(())
    }

    pub(super) fn begin_draining(&self) -> Result<(), CliError> {
        let mut guard = self.lifecycle.lock().map_err(|_| ClockError::Unavailable)?;
        if guard.state != RemoteSessionState::Ready {
            return Ok(());
        }
        let reading = self.clock.read()?;
        let deadline =
            AuthorityDeadline::for_timeout_ms(reading, self.lifecycle_policy.drain_grace_millis)?;
        let expires = reading
            .unix_millis()
            .checked_add(self.lifecycle_policy.drain_grace_millis)?;
        self.remove_resumable_record()?;
        guard.state = RemoteSessionState::Draining;
        guard.last_seen_at = reading.unix_millis().get();
        guard.drain_deadline_at = Some(expires.get());
        guard.deadline = Some(deadline);
        Ok(())
    }

    pub(super) fn deadline_expired(&self) -> Result<bool, CliError> {
        let mut lifecycle = self.lifecycle.lock().map_err(|_| ClockError::Unavailable)?;
        let reading = self.clock.read()?;
        match lifecycle
            .deadline
            .as_mut()
            .map(|deadline| deadline.remaining(reading))
        {
            Some(Err(ClockError::Expired)) => Ok(true),
            Some(Err(error)) => Err(error.into()),
            _ => Ok(false),
        }
    }

    pub(super) fn mark_terminal(&self, state: RemoteSessionState, now: u64) {
        // Terminal intent is already durable. Poison cannot restore dispatch authority.
        let mut guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.state = state;
        guard.last_seen_at = now;
        guard.drain_deadline_at = None;
        guard.deadline = None;
    }

    pub(super) fn auth_context(&self) -> &SessionAuthContext {
        &self.auth_context
    }

    pub(super) fn diagnostic_record(&self) -> RemoteSessionDiagnosticRecord {
        RemoteSessionDiagnosticRecord {
            session_id: self.session_id.clone(),
            auth_context: self.auth_context.clone(),
            capabilities: self.capabilities.clone(),
            lifecycle: self.lifecycle_snapshot(),
            protocol_version: self.protocol_version(),
            ownership: self.ownership_snapshot(),
            terminal_at: self.lifecycle_snapshot().last_seen_at,
            terminal_reason: None,
        }
    }

    pub(super) fn ownership_snapshot(&self) -> RemoteSessionOwnershipSnapshot {
        let notification_stream_attached = self.has_active_notification_stream();
        RemoteSessionOwnershipSnapshot {
            hosted_isolation: self.hosted_isolation,
            hosted_identity_profile: self.hosted_isolation.identity_profile(),
            notification_delivery: if notification_stream_attached {
                RemoteNotificationDelivery::GetSse
            } else {
                RemoteNotificationDelivery::PostResponseFallback
            },
            request_stream_active: self.has_active_request_stream(),
            notification_stream_attached,
            ..RemoteSessionOwnershipSnapshot::default()
        }
    }
}

fn standard_subscriptions(subscriptions: &BTreeMap<String, String>) -> Vec<PersistedSubscription> {
    subscriptions
        .iter()
        .map(|(uri, capability_id)| PersistedSubscription::Standard {
            uri: uri.clone(),
            capability_id: capability_id.clone(),
        })
        .collect()
}

/// Persists the edge's standard resource subscriptions with the session's
/// resume record before the client is answered.
pub(super) struct SubscriptionPersistence(pub(super) Weak<RemoteSession>);

impl SubscriptionPersistence {
    fn change(&self, change: impl FnOnce(&mut BTreeMap<String, String>)) -> Result<(), AdapterError> {
        let session = self.0.upgrade().ok_or_else(|| {
            AdapterError::ConnectionFailed("MCP session ended before its subscription change".into())
        })?;
        session
            .change_subscriptions(change)
            .map_err(|error| AdapterError::ConnectionFailed(error.to_string()))
    }
}

/// When the authority of a session's subscriptions runs out.
#[derive(Debug)]
pub(super) enum SubscriptionDeadline {
    /// The session holds no subscription.
    Unbounded,
    Armed(AuthorityDeadline),
    Lapsed,
}

impl chio_mcp_adapter::edge::ResourceSubscriptionObserver for SubscriptionPersistence {
    fn subscribed(&self, uri: &str, capability_id: &str) -> Result<(), AdapterError> {
        self.change(|subscriptions| {
            subscriptions.insert(uri.to_owned(), capability_id.to_owned());
        })
    }

    fn unsubscribed(&self, uri: &str) -> Result<(), AdapterError> {
        self.change(|subscriptions| {
            subscriptions.remove(uri);
        })
    }

    fn authority_lost(&self, _uri: &str) {
        if let Some(session) = self.0.upgrade() {
            session.latch_subscription_authority_lost();
        }
    }
}
