use super::*;

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
                health.note_accept(previous);
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
                self.health
                    .last_commit_unix_ms
                    .store(current_unix_ms(), Ordering::SeqCst);
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

pub(super) fn receipt_commit_channel() -> (ReceiptCommitSender, mpsc::Receiver<QueuedWriterCommand>)
{
    let (sender, receiver) = mpsc::sync_channel(RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY);
    (
        ReceiptCommitSender {
            sender,
            health: Arc::new(ReceiptCommitWriterHealth::default()),
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
