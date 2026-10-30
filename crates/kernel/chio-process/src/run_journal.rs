//! Worker lifecycle rules for the process-host run journal. Each rule is a
//! pure function of the persisted record; a journal store applies it inside
//! the transaction that writes the result.

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JournalError {
    #[error("run journal is busy")]
    Busy,
    #[error("run journal persistence failed")]
    Persistence,
    #[error("run journal contains invalid data")]
    Integrity,
    #[error("runner journal does not have the v1 schema")]
    Schema,
    #[error("run plan or authority changed; restore the original configuration")]
    Binding,
    #[error("worker is missing from the run journal")]
    MissingWorker,
    #[error("worker transition does not match its current state")]
    Transition,
    #[error("cancellation does not match pending worker state")]
    Cancellation,
    #[error("worker accounting overflow")]
    Overflow,
    #[error("container transition does not match its durable intent")]
    ContainerIntent,
    #[error("caller has no running worker attempt")]
    NotRunning,
    #[error("worker socket intent does not match the live lease")]
    SocketIntent,
    #[error(
        "worker socket abandoned-intent limit reached; preserve and inspect the runner journal before further runs"
    )]
    SocketHistoryFull,
    #[error("run exceeds {MAX_WORKERS} total workers")]
    WorkerCapacity,
    #[error("run retains {MAX_WORKERS} unresolved container intents; resolve them before further launches")]
    ContainerCapacity,
}

/// Workers one run journal holds, declared and adaptive children together.
/// Container intents and child settlements are bounded by the same count.
pub const MAX_WORKERS: u32 = 128;

/// A journal holding `workers` rows is within the run's worker bound.
pub fn workers_within_capacity(workers: u32) -> Result<(), JournalError> {
    if workers > MAX_WORKERS {
        return Err(JournalError::WorkerCapacity);
    }
    Ok(())
}

/// A container intent may be reserved while fewer than [`MAX_WORKERS`] are
/// unresolved.
pub fn container_intent_admissible(unresolved: u32) -> Result<(), JournalError> {
    if unresolved >= MAX_WORKERS {
        return Err(JournalError::ContainerCapacity);
    }
    Ok(())
}

/// Accounted resource values saturate here so every total stays representable
/// as a signed 64-bit integer in any journal.
pub const MAX_ACCOUNTED: u64 = i64::MAX.unsigned_abs();

/// Abandoned worker socket intents retained before a run refuses to start.
pub const MAX_ABANDONED_SOCKET_INTENTS: u32 = 8;

/// The history slot the live socket intent moves to when it is abandoned.
/// Slot 1 is the live intent and slots 2 to 9 hold abandoned intents.
pub fn next_abandoned_slot(last_slot: u32) -> Result<u32, JournalError> {
    if last_slot > MAX_ABANDONED_SOCKET_INTENTS {
        return Err(JournalError::SocketHistoryFull);
    }
    Ok(last_slot + 1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

/// The live worker socket intent. A missing identity was never committed, so
/// no worker credential was delivered for that stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketLease {
    pub name: String,
    pub directory: Option<FileIdentity>,
    pub socket: Option<FileIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkerState {
    Pending,
    Running,
    Completed,
    Failed,
}

impl WorkerState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

impl TryFrom<&str> for WorkerState {
    type Error = JournalError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(JournalError::Integrity),
        }
    }
}

/// Longest outcome reason a run journal holds.
pub const MAX_OUTCOME_BYTES: usize = 64;

/// Why a worker's last attempt ended. The journal authors every variant but
/// `Observed`, which carries the reason the runner observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerOutcome {
    ProcessCancelled,
    DependencyFailed,
    HostInterrupted,
    WorkerNotExecuted,
    Suspended,
    Observed(ObservedReason),
}

/// A runner-observed reason such as `exit_1` or `container_state_unknown`:
/// 1 to [`MAX_OUTCOME_BYTES`] bytes of `[a-z0-9_-]`, never a journal-authored
/// name. Built only by [`WorkerOutcome::parse`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedReason(String);

const JOURNAL_AUTHORED: [WorkerOutcome; 5] = [
    WorkerOutcome::ProcessCancelled,
    WorkerOutcome::DependencyFailed,
    WorkerOutcome::HostInterrupted,
    WorkerOutcome::WorkerNotExecuted,
    WorkerOutcome::Suspended,
];

impl WorkerOutcome {
    pub fn as_str(&self) -> &str {
        match self {
            Self::ProcessCancelled => "process_cancelled",
            Self::DependencyFailed => "dependency_failed",
            Self::HostInterrupted => "host_interrupted",
            Self::WorkerNotExecuted => "worker_not_executed",
            Self::Suspended => "suspended",
            Self::Observed(reason) => &reason.0,
        }
    }

    /// The outcome `text` names. A journal-authored name is always its
    /// variant, so every outcome has one spelling; text that is not a reason
    /// token is an integrity fault.
    pub fn parse(text: &str) -> Result<Self, JournalError> {
        if let Some(outcome) = JOURNAL_AUTHORED
            .iter()
            .find(|outcome| outcome.as_str() == text)
        {
            return Ok(outcome.clone());
        }
        let token = text
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
        if text.is_empty() || text.len() > MAX_OUTCOME_BYTES || !token {
            return Err(JournalError::Integrity);
        }
        Ok(Self::Observed(ObservedReason(text.to_owned())))
    }
}

impl Serialize for WorkerOutcome {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerRecord {
    pub process: String,
    pub state: WorkerState,
    pub attempts: u32,
    pub suspensions: u32,
    pub outcome: Option<WorkerOutcome>,
    pub peak_resident_bytes: u64,
    pub cpu_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ResourceUsage {
    pub peak_resident_bytes: u64,
    pub cpu_ms: u64,
}

/// How a launch ended, as the runner observed it.
#[derive(Clone, Copy, Debug)]
pub enum Completion<'a> {
    Completed(&'a WorkerOutcome),
    Suspended,
    Failed(&'a WorkerOutcome),
    Terminal(&'a WorkerOutcome),
}

#[derive(Clone, Copy, Debug)]
pub enum WorkerTransition<'a> {
    Start {
        max_attempts: u32,
    },
    CancelPending,
    DependencyFailed,
    Recover {
        max_attempts: u32,
    },
    Unreserve,
    Finish {
        completion: Completion<'a>,
        max_attempts: u32,
        max_suspensions: u32,
        usage: ResourceUsage,
    },
}

impl WorkerRecord {
    pub fn pending(process: String) -> Self {
        Self {
            process,
            state: WorkerState::Pending,
            attempts: 0,
            suspensions: 0,
            outcome: None,
            peak_resident_bytes: 0,
            cpu_ms: 0,
        }
    }

    /// Suspensions never spend the failure budget. `has_container` reports a
    /// durable container intent, which forbids rolling back the reservation.
    pub fn transition(
        &self,
        transition: WorkerTransition<'_>,
        has_container: bool,
    ) -> Result<Self, JournalError> {
        let spent = self
            .attempts
            .checked_sub(self.suspensions)
            .ok_or(JournalError::Integrity)?;
        let mut next = self.clone();
        match transition {
            WorkerTransition::Start { max_attempts } => {
                if self.state != WorkerState::Pending || spent >= max_attempts {
                    return Err(JournalError::Transition);
                }
                next.attempts = self.attempts.checked_add(1).ok_or(JournalError::Overflow)?;
                next.state = WorkerState::Running;
                next.outcome = None;
            }
            WorkerTransition::CancelPending => {
                if self.state != WorkerState::Pending {
                    return Err(JournalError::Cancellation);
                }
                next.state = WorkerState::Failed;
                next.outcome = Some(WorkerOutcome::ProcessCancelled);
            }
            WorkerTransition::DependencyFailed => {
                if self.state != WorkerState::Pending {
                    return Err(JournalError::Transition);
                }
                next.state = WorkerState::Failed;
                next.outcome = Some(WorkerOutcome::DependencyFailed);
            }
            WorkerTransition::Recover { max_attempts } => {
                if self.state == WorkerState::Running {
                    next.state = if spent >= max_attempts {
                        WorkerState::Failed
                    } else {
                        WorkerState::Pending
                    };
                    next.outcome = Some(WorkerOutcome::HostInterrupted);
                }
            }
            WorkerTransition::Unreserve => {
                if self.state != WorkerState::Running || spent == 0 || has_container {
                    return Err(JournalError::Transition);
                }
                next.attempts = self
                    .attempts
                    .checked_sub(1)
                    .ok_or(JournalError::Integrity)?;
                next.state = WorkerState::Pending;
                next.outcome = Some(WorkerOutcome::WorkerNotExecuted);
            }
            WorkerTransition::Finish {
                completion,
                max_attempts,
                max_suspensions,
                usage,
            } => {
                if self.state != WorkerState::Running {
                    return Err(JournalError::Transition);
                }
                let (state, outcome) = match completion {
                    Completion::Completed(outcome) => (WorkerState::Completed, outcome),
                    Completion::Terminal(outcome) => (WorkerState::Failed, outcome),
                    Completion::Failed(outcome) => (
                        if spent >= max_attempts {
                            WorkerState::Failed
                        } else {
                            WorkerState::Pending
                        },
                        outcome,
                    ),
                    Completion::Suspended => {
                        next.suspensions = self
                            .suspensions
                            .checked_add(1)
                            .ok_or(JournalError::Overflow)?;
                        if next.suspensions > self.attempts {
                            return Err(JournalError::Integrity);
                        }
                        (
                            if next.suspensions > max_suspensions {
                                WorkerState::Failed
                            } else {
                                WorkerState::Pending
                            },
                            &WorkerOutcome::Suspended,
                        )
                    }
                };
                next.state = state;
                next.outcome = Some(outcome.clone());
                next.peak_resident_bytes = self
                    .peak_resident_bytes
                    .max(usage.peak_resident_bytes.min(MAX_ACCOUNTED));
                next.cpu_ms = self.cpu_ms.saturating_add(usage.cpu_ms).min(MAX_ACCOUNTED);
            }
        }
        Ok(next)
    }

    /// A container may bind only to the attempt that is running now.
    pub fn bind_container(&self, attempt: u32) -> Result<(), JournalError> {
        if self.state != WorkerState::Running || self.attempts != attempt {
            return Err(JournalError::ContainerIntent);
        }
        Ok(())
    }
}

pub struct WorkerSeed<'a> {
    pub process: &'a str,
    pub max_attempts: u32,
}

/// A durable create-only container intent, written before the engine is
/// contacted. No start request may be sent until `id` is committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerIntent {
    pub owner: String,
    pub engine: String,
    pub id: Option<String>,
    pub create_rejected: bool,
}

/// A failed child whose parent observed it through `settle_children`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildSettlement {
    pub parent: String,
    pub child: String,
    pub request_id: String,
}

/// A child's journal state as reported to its settling parent. A child the
/// runner has not discovered yet is reported as pending with no attempts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChildOutcome {
    pub process: String,
    pub state: WorkerState,
    pub attempts: u32,
    pub outcome: Option<WorkerOutcome>,
}

impl ChildOutcome {
    pub fn undiscovered(process: String) -> Self {
        Self {
            process,
            state: WorkerState::Pending,
            attempts: 0,
            outcome: None,
        }
    }
}

/// Only a running parent may settle. Settlement is recorded once every
/// awaited child is terminal, and only for failed children, since completed
/// children need no handling.
pub fn settle(
    parent: Option<WorkerState>,
    outcomes: &[ChildOutcome],
) -> Result<Option<Vec<&str>>, JournalError> {
    if parent != Some(WorkerState::Running) {
        return Err(JournalError::NotRunning);
    }
    Ok(outcomes
        .iter()
        .all(|outcome| outcome.state.is_terminal())
        .then(|| {
            outcomes
                .iter()
                .filter(|outcome| outcome.state == WorkerState::Failed)
                .map(|outcome| outcome.process.as_str())
                .collect()
        }))
}

#[cfg(test)]
mod tests;
