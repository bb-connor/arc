//! Errors the production response worker returns.

use chio_quarantine::SchedulerError;
use chio_security_types::ports::{ErrorCode, PortError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResponseWorkerTickError {
    #[error("response worker lost an acknowledgement")]
    AckLost,
    #[error("response worker configuration is invalid")]
    InvalidConfig,
    #[error("expired terminal scheduler cleanup remains pending")]
    TerminalSchedulerCleanupPending,
    #[error("declassification receipt outbox failed: {0}")]
    DeclassificationOutbox(PortError),
    #[error("declassification receipt outbox has {0} pending receipts")]
    DeclassificationOutboxPending(u64),
    #[error("declassification receipt outbox made no progress with {0} receipts pending")]
    DeclassificationOutboxNoProgress(u64),
    #[error(
        "declassification receipt outbox exceeded the bounded drain with {0} receipts pending"
    )]
    DeclassificationOutboxDrainLimit(u64),
    #[error(
        "declassification receipt startup reconciliation made no progress with {0} consumptions stranded"
    )]
    DeclassificationReconciliationNoProgress(u64),
    #[error(
        "declassification receipt startup reconciliation exceeded its bound with {0} consumptions stranded"
    )]
    DeclassificationReconciliationLimit(u64),
    #[error("production security runtime has {0} live publication leases")]
    RuntimeLeasesActive(u64),
    #[error("production security runtime has {0} live dispatch outcome recorder leases")]
    DispatchRecorderLeasesActive(u64),
    #[error("production active-defense host has {0} live event consumer leases")]
    ConsumerLeasesActive(u64),
    #[error("production security runtime admission is closed")]
    RuntimeAdmissionClosed,
    #[error("response worker port failed: {0}")]
    Port(#[from] PortError),
    #[error("response worker background loop is already running")]
    WorkerAlreadyRunning,
    #[error("response worker task-ready handshake failed")]
    WorkerTaskReadyHandshake,
    #[error("response worker arm handshake failed")]
    WorkerArmHandshake,
    #[error("response worker publication gate failed")]
    WorkerPublicationGate,
    #[error("response worker publication has not been observed")]
    WorkerPublicationPending,
    #[error("response worker initial tick failed: {0}")]
    WorkerInitialTick(String),
    #[error("response worker runtime failed: {0}")]
    WorkerRuntime(String),
    #[error("response worker join reaper failed: {0}")]
    WorkerReaper(String),
    #[error("response worker join registry is at capacity")]
    WorkerReaperCapacity,
    #[error(
        "response worker progress stalled after start {started_sequence:?} and completion {completed_sequence:?}"
    )]
    WorkerProgressStalled {
        started_sequence: Option<u64>,
        completed_sequence: Option<u64>,
    },
    #[error("active-defense services already have an owner")]
    ServicesAlreadyPublished,
    #[error("active-defense service ownership does not match the installed instance")]
    ServicesOwnershipMismatch,
    #[error("response scheduler failed: {0}")]
    Scheduler(#[from] SchedulerError),
    #[error("response worker crashed: {0}")]
    WorkerCrash(ErrorCode),
    #[error("response worker is stopped")]
    WorkerStopped,
}
