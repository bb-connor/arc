use super::*;

impl ReceiptCommitWriterHealth {
    fn new(clock: crate::store_clock::StoreClock) -> Self {
        Self {
            clock,
            accepted_total: AtomicU64::new(0),
            committed_total: AtomicU64::new(0),
            failed_total: AtomicU64::new(0),
            saturated_total: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            timed_out_inflight: AtomicU64::new(0),
            timed_out_total: AtomicU64::new(0),
            queue_depth: AtomicU64::new(0),
            last_commit_unix_ms: AtomicU64::new(0),
            first_accept_unix_ms: AtomicU64::new(0),
            backlog_started_unix_ms: AtomicU64::new(0),
            last_error: Mutex::new(None),
            retention_error: Mutex::new(None),
            head_checkpoint_seq: AtomicU64::new(0),
            head_checkpointed_entry_seq: AtomicU64::new(0),
            head_claim_log_count: AtomicU64::new(0),
            head_claim_log_max_seq: AtomicU64::new(0),
            // Fail closed until the actor thread seeds a verified head. The head
            // is seeded asynchronously after construction, so starting open would
            // let a corrupt or still-attaching store pass the pre-dispatch gate
            // and run a tool before the first append could reject. The seed path
            // clears this the moment it succeeds.
            head_poisoned: AtomicBool::new(true),
            seed_settled: Mutex::new(false),
            seed_settled_changed: Condvar::new(),
            critical_write_poisoned: AtomicBool::new(false),
            accounting_poisoned: AtomicBool::new(false),
        }
    }
}

impl ReceiptCommitWriterHealth {
    pub(super) fn set_seed_settled(&self, settled: bool) {
        if let Ok(mut current) = self.seed_settled.lock() {
            *current = settled;
            self.seed_settled_changed.notify_all();
        }
    }

    /// Wait up to `wait` for this run's seed to settle.
    pub(super) fn wait_seed_settled(&self, wait: Duration) -> bool {
        self.seed_settled
            .lock()
            .ok()
            .and_then(|settled| {
                self.seed_settled_changed
                    .wait_timeout_while(settled, wait, |settled| !*settled)
                    .ok()
            })
            .is_some_and(|(settled, _)| *settled)
    }
}

#[cfg(test)]
impl Default for ReceiptCommitWriterHealth {
    fn default() -> Self {
        Self::new(crate::store_clock::StoreClock::new(Arc::new(
            chio_security_types::clock::SystemClock,
        )))
    }
}

#[derive(Clone, Copy)]
enum CommandKind {
    Write,
    Maintenance,
    Control,
}

impl ReceiptCommitCommand {
    fn accounting_kind(&self) -> CommandKind {
        match self {
            Self::Append(_) | Self::AppendWithTimeout { .. } | Self::Write { .. } => {
                CommandKind::Write
            }
            Self::Rotate { .. } | Self::RetentionRepair { .. } => CommandKind::Maintenance,
            _ => CommandKind::Control,
        }
    }
}

impl ReceiptCommitWriterHealth {
    fn accounting_error(&self, counter: &str) -> ReceiptStoreError {
        self.accounting_poisoned.store(true, Ordering::SeqCst);
        let message = format!("receipt writer accounting invariant failed: {counter}");
        if let Ok(mut last_error) = self.last_error.lock() {
            *last_error = Some(message.clone());
        }
        ReceiptStoreError::Conflict(message)
    }

    pub(super) fn add_counter(
        &self,
        counter: &AtomicU64,
        amount: u64,
        name: &str,
    ) -> Result<u64, ReceiptStoreError> {
        counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(amount)
            })
            .map_err(|_| self.accounting_error(name))
    }

    pub(super) fn subtract_counter(&self, counter: &AtomicU64, amount: u64, name: &str) {
        if counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_sub(amount)
            })
            .is_err()
        {
            self.accounting_error(name);
        }
    }
}

/// One command owns each reservation until rejection, completion or unwind.
/// A caller losing its response never releases another command's ownership.
pub(super) struct WriterCommandPermit {
    health: Arc<ReceiptCommitWriterHealth>,
    queued: bool,
    inflight: bool,
    accepted: bool,
}

impl WriterCommandPermit {
    fn reserve(
        health: &Arc<ReceiptCommitWriterHealth>,
        kind: CommandKind,
    ) -> Result<Self, ReceiptStoreError> {
        if health.accounting_poisoned.load(Ordering::SeqCst) {
            return Err(health.accounting_error("admission after accounting failure"));
        }
        let mut permit = Self {
            health: Arc::clone(health),
            queued: false,
            inflight: false,
            accepted: false,
        };
        let reservation = (|| {
            if !matches!(kind, CommandKind::Control) {
                let previous = health.add_counter(&health.inflight, 1, "inflight overflow")?;
                permit.inflight = true;
                health.note_accept(previous)?;
            }
            if matches!(kind, CommandKind::Write) {
                health.add_counter(&health.accepted_total, 1, "accepted total overflow")?;
                permit.accepted = true;
            }
            health.add_counter(&health.queue_depth, 1, "queue depth overflow")?;
            permit.queued = true;
            Ok(())
        })();
        if let Err(error) = reservation {
            permit.cancel();
            return Err(error);
        }
        Ok(permit)
    }

    fn dequeue(&mut self) {
        if std::mem::take(&mut self.queued) {
            self.health
                .subtract_counter(&self.health.queue_depth, 1, "queue depth underflow");
        }
    }

    fn cancel(&mut self) {
        if std::mem::take(&mut self.accepted) {
            self.health.subtract_counter(
                &self.health.accepted_total,
                1,
                "accepted total underflow",
            );
        }
        self.finish(false);
    }

    pub(super) fn finish(&mut self, committed: bool) {
        self.dequeue();
        if std::mem::take(&mut self.accepted) {
            let (counter, name) = if committed {
                (&self.health.committed_total, "committed total overflow")
            } else {
                (&self.health.failed_total, "failed total overflow")
            };
            let _ = self.health.add_counter(counter, 1, name);
            if committed {
                // The commit already happened; this timestamp only feeds health
                // reporting. A clock fault (for example a fenced backward step)
                // keeps the previous value instead of closing the writer.
                match self.health.clock.unix_millis().map(|time| time.get()) {
                    Ok(now) => self.health.last_commit_unix_ms.store(now, Ordering::SeqCst),
                    Err(error) => tracing::warn!(
                        code = error.code(),
                        "receipt writer could not timestamp a committed write"
                    ),
                }
                self.health.clear_timeout_error_if_drained();
            }
        }
        if std::mem::take(&mut self.inflight) {
            self.health
                .subtract_counter(&self.health.inflight, 1, "inflight underflow");
        }
    }
}

impl Drop for WriterCommandPermit {
    fn drop(&mut self) {
        self.finish(false);
    }
}

pub(super) struct QueuedWriterCommand {
    // Drop accounting before a queued command disconnects its response channel.
    permit: WriterCommandPermit,
    command: ReceiptCommitCommand,
}

impl QueuedWriterCommand {
    pub(super) fn dequeue(mut self) -> (ReceiptCommitCommand, WriterCommandPermit) {
        self.permit.dequeue();
        (self.command, self.permit)
    }
}

#[derive(Clone)]
pub(super) struct ReceiptCommitSender {
    sender: mpsc::SyncSender<QueuedWriterCommand>,
    pub(super) health: Arc<ReceiptCommitWriterHealth>,
}

impl ReceiptCommitSender {
    pub(super) fn try_send(&self, command: ReceiptCommitCommand) -> Result<(), ReceiptStoreError> {
        let permit = WriterCommandPermit::reserve(&self.health, command.accounting_kind())?;
        match self
            .sender
            .try_send(QueuedWriterCommand { command, permit })
        {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(mut rejected)) => {
                rejected.permit.cancel();
                self.health.add_counter(
                    &self.health.saturated_total,
                    1,
                    "saturated total overflow",
                )?;
                Err(receipt_actor_saturated_error())
            }
            Err(mpsc::TrySendError::Disconnected(mut rejected)) => {
                rejected.permit.cancel();
                self.health.note_writer_unavailable();
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    #[cfg(test)]
    pub(super) fn send(&self, command: ReceiptCommitCommand) -> Result<(), ReceiptStoreError> {
        let permit = WriterCommandPermit::reserve(&self.health, command.accounting_kind())?;
        self.sender
            .send(QueuedWriterCommand { command, permit })
            .map_err(|mut error| {
                error.0.permit.cancel();
                self.health.note_writer_unavailable();
                receipt_actor_unavailable_error()
            })
    }
}

pub(super) fn receipt_commit_channel_with_clock(
    clock: crate::store_clock::StoreClock,
) -> (ReceiptCommitSender, mpsc::Receiver<QueuedWriterCommand>) {
    let (sender, receiver) = mpsc::sync_channel(RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY);
    (
        ReceiptCommitSender {
            sender,
            health: Arc::new(ReceiptCommitWriterHealth::new(clock)),
        },
        receiver,
    )
}

pub(super) fn checked_claim_count(count: u64, deltas: &[u64]) -> Result<u64, ReceiptStoreError> {
    deltas
        .iter()
        .try_fold(count, |sum, delta| sum.checked_add(*delta))
        .ok_or_else(|| ReceiptStoreError::Conflict("receipt claim count overflow".to_owned()))
}

fn enqueue_for_worker(
    sender: &ReceiptCommitSender,
    worker: &ReceiptCommitWorker,
    command: ReceiptCommitCommand,
) -> Result<(), ReceiptStoreError> {
    sender.try_send(command).map_err(|error| match error {
        ReceiptStoreError::Pool(ref message)
            if message == "sqlite receipt commit actor is unavailable" =>
        {
            worker.writer_dead_error()
        }
        other => other,
    })
}
impl ReceiptCommitActor {
    pub(super) fn enqueue_command(
        &self,
        command: ReceiptCommitCommand,
    ) -> Result<(), ReceiptStoreError> {
        enqueue_for_worker(&self.sender, &self.worker, command)
    }
}
impl WriterHandle {
    pub(super) fn enqueue_command(
        &self,
        command: ReceiptCommitCommand,
    ) -> Result<(), ReceiptStoreError> {
        enqueue_for_worker(&self.sender, &self.worker, command)
    }
}

#[cfg(test)]
pub(super) fn receipt_commit_channel() -> (ReceiptCommitSender, mpsc::Receiver<QueuedWriterCommand>)
{
    receipt_commit_channel_with_clock(crate::store_clock::StoreClock::new(Arc::new(
        chio_security_types::clock::SystemClock,
    )))
}
