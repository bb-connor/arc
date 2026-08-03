//! `ChioKernel` construction and configuration surface.
//!
//! Holds the kernel constructor, session/store accessors, and the
//! `set_*` / `with_*` / `register_*` configuration setters, including
//! federation, emergency-stop, DPoP, and execution-nonce wiring.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use chio_log_redact::redacted;
use dashmap::DashMap;

use super::*;

fn receipt_evaluation_map_key(request_id: &str) -> String {
    current_receipt_evaluation_scope_key().map_or_else(
        || format!("request:{request_id}"),
        |evaluation_id| format!("evaluation:{evaluation_id}"),
    )
}

/// Fail-closed kernel build error. Lets deadline config be validated at
/// construction time without making the infallible `ChioKernel::new` fallible.
#[derive(Debug, thiserror::Error)]
pub enum KernelBuildError {
    #[error("invalid hot-path deadline config: {0}")]
    InvalidDeadlineConfig(String),
    #[error(
        "settlement observer requires a durable settlement retry store: call \
         set_settlement_retry_store before set_settlement_observer, so every retryable or \
         permanent settlement outcome lands a settle_attempts or settle_dead_letters row \
         instead of a warn-only log"
    )]
    MissingSettlementRetryStore,
    #[error("settlement observer is already installed")]
    SettlementObserverAlreadyInstalled,
    #[error("settlement observer requires a crash-durable settlement retry store")]
    SettlementRetryStoreNotDurable,
    #[error("settlement hook must be idempotent by receipt id")]
    SettlementHookNotIdempotent,
    #[error("receipt store does not support the durable settlement-observer outbox contract")]
    SettlementObserverOutboxUnsupported,
    #[error("settlement observer durable storage topology is invalid: {0}")]
    SettlementObserverStorageTopology(String),
    #[error("settlement-observer outbox recovery failed: {0}")]
    SettlementObserverRecovery(String),
    #[error("credit-facility bind trust configuration is invalid: {0}")]
    InvalidCreditFacilityBindTrust(String),
}

include!("construction.part1.inc");
include!("construction.part2.inc");
