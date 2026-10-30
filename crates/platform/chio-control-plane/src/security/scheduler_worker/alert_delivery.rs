//! Delivery of paged security alerts, driven by the response worker.

use std::convert::Infallible;
use std::panic::AssertUnwindSafe;

use futures_util::FutureExt;

use super::{Arc, Clock, Duration, MissedTickBehavior, Mutex, PortError};
use crate::security::adapters::{AlertDispatchReport, SecurityAlertOutbox};
use chio_security_types::ports::{PortResult, SecurityAlertOutboxBacklog};

/// Outbox rows one delivery pass may dispatch.
pub(in crate::security) const SECURITY_ALERT_ROWS_PER_PASS: usize = 16;

/// Health of security alert delivery, as of the last completed pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecurityAlertDeliveryHealth {
    /// Delivery passes completed, including failed ones.
    pub passes: u64,
    /// Alerts confirmed by every configured backend.
    pub delivered: u64,
    /// Alert attempts that at least one backend did not confirm.
    pub failed_attempts: u64,
    /// Alerts awaiting delivery or retry.
    pub pending: u64,
    /// Alerts that exhausted their delivery attempts and stay parked until an
    /// operator resolves them.
    pub parked: u64,
    /// Outbox, store, integrity or clock failure of the last pass.
    pub last_error: Option<String>,
}

/// Dispatches due rows of the security paging outbox in bounded passes on the
/// worker's thread, between response ticks. A pass never runs inside a tick,
/// so a slow or unavailable SIEM backend cannot delay expiry or rollback.
pub(in crate::security) struct SecurityAlertDelivery {
    outbox: Arc<SecurityAlertOutbox>,
    clock: Arc<dyn Clock>,
    health: Mutex<SecurityAlertDeliveryHealth>,
}

impl SecurityAlertDelivery {
    #[must_use]
    pub(in crate::security) fn new(
        outbox: Arc<SecurityAlertOutbox>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            outbox,
            clock,
            health: Mutex::new(SecurityAlertDeliveryHealth::default()),
        }
    }

    #[must_use]
    pub(in crate::security) fn health(&self) -> SecurityAlertDeliveryHealth {
        self.health.lock().map_or_else(
            |_| SecurityAlertDeliveryHealth {
                last_error: Some("security alert delivery health lock is unavailable".to_string()),
                ..SecurityAlertDeliveryHealth::default()
            },
            |health| health.clone(),
        )
    }

    /// Durable backlog of the outbox, read on every call.
    pub(in crate::security) fn backlog(&self) -> PortResult<SecurityAlertOutboxBacklog> {
        self.outbox.backlog()
    }

    /// Runs one pass per cadence until the future is dropped. Missed cadences
    /// are skipped and passes never overlap.
    pub(in crate::security) async fn run(&self, cadence: Duration) -> Infallible {
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + cadence, cadence);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            self.deliver_once().await;
        }
    }

    /// Dispatches at most [`SECURITY_ALERT_ROWS_PER_PASS`] due rows and
    /// records the outcome. A pass with nothing pending reads no clock.
    pub(in crate::security) async fn deliver_once(&self) {
        let outcome = AssertUnwindSafe(self.delivery_outcome())
            .catch_unwind()
            .await;
        if let Ok(mut health) = self.health.lock() {
            health.passes = health.passes.saturating_add(1);
            match outcome {
                Ok(Ok((report, backlog))) => {
                    health.delivered = health.delivered.saturating_add(count(report.delivered));
                    health.failed_attempts =
                        health.failed_attempts.saturating_add(count(report.failed));
                    health.pending = backlog.pending;
                    health.parked = backlog.parked;
                    health.last_error = None;
                }
                Ok(Err(error)) => health.last_error = Some(error.to_string()),
                Err(_) => health.last_error = Some("security alert delivery panicked".to_owned()),
            }
        }
    }

    async fn delivery_outcome(
        &self,
    ) -> PortResult<(AlertDispatchReport, SecurityAlertOutboxBacklog)> {
        match self.outbox.delivery_backlog().await {
            Ok(backlog) if backlog.pending == 0 => Ok((AlertDispatchReport::default(), backlog)),
            Ok(_) => match self.dispatch_due().await {
                Ok(report) => self
                    .outbox
                    .delivery_backlog()
                    .await
                    .map(|backlog| (report, backlog)),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        }
    }

    async fn dispatch_due(&self) -> PortResult<AlertDispatchReport> {
        let now_unix_ms = self
            .clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)
            .map_err(PortError::from)?;
        self.outbox
            .deliver_due(now_unix_ms, SECURITY_ALERT_ROWS_PER_PASS)
            .await
    }
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[path = "tests/alert_delivery_passes_are_bounded_and_report_parked_alerts.rs"]
mod alert_delivery_passes_are_bounded_and_report_parked_alerts;
