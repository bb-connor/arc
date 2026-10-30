use std::panic::resume_unwind;
use std::sync::Arc;

use chio_security_types::ports::{
    AlertBackendOutcome, DueSecurityAlert, PortError, PortResult, SecurityAlertOutboxBacklog,
    SecurityAlertOutboxStore,
};

use super::{
    backend_alert, increment, retry_delay, validate_backends, AlertDispatchReport,
    SecurityAlertOutbox,
};

#[cfg(test)]
mod tests;

impl SecurityAlertOutbox {
    /// Dispatches up to `limit` due rows to their unconfirmed backends. A row
    /// whose failed attempt reaches `max_attempts` is parked in the same write,
    /// and a due row already at `max_attempts` is parked without a dispatch.
    ///
    /// Storage runs in the current Tokio runtime's blocking pool. Backend
    /// failures leave rows pending under backoff; `Err` means the outbox failed.
    /// Delivery is at least once: cancellation can occur after remote acceptance
    /// but before its local confirmation. Backends must honor the dedup key.
    pub async fn deliver_due(
        &self,
        now_unix_ms: u64,
        limit: usize,
    ) -> PortResult<AlertDispatchReport> {
        if limit == 0 {
            return Err(PortError::invalid_data());
        }
        validate_backends(&self.backends)?;
        let guard = Arc::clone(&self.delivery_lock).lock_owned().await;
        let config = self.config;
        let (due, mut guard) = self
            .with_store(guard, move |store| {
                store.ensure_ready()?;
                store.load_due(now_unix_ms, limit)
            })
            .await?;
        let backend_names: Arc<Vec<String>> = Arc::new(
            self.backends
                .iter()
                .map(|backend| backend.name().to_owned())
                .collect(),
        );
        let mut report = AlertDispatchReport::default();
        for row in due {
            if row.attempts >= config.max_attempts {
                let attempts = row.attempts;
                guard = self.park(guard, row, attempts).await?;
                increment(&mut report.parked)?;
                continue;
            }
            let row = Arc::new(row);
            increment(&mut report.attempted)?;
            let alert = backend_alert(&row.alert)?;
            let stored = Arc::clone(&row);
            let (confirmed, returned_guard) = self
                .with_store(guard, move |store| store.confirmed_backends(&stored))
                .await?;
            guard = returned_guard;
            let mut delivery_failed = false;
            for backend in &self.backends {
                if confirmed.contains(backend.name()) {
                    continue;
                }
                increment(&mut report.backend_dispatches)?;
                let outcome = match backend.dispatch(&alert).await {
                    Ok(_) => AlertBackendOutcome::Confirmed,
                    Err(_) => AlertBackendOutcome::Refused,
                };
                let name = backend.name().to_owned();
                let stored = Arc::clone(&row);
                let ((), returned_guard) = self
                    .with_store(guard, move |store| {
                        store.record_backend_outcome(&stored, &name, outcome, now_unix_ms)
                    })
                    .await?;
                guard = returned_guard;
                if outcome == AlertBackendOutcome::Refused {
                    delivery_failed = true;
                    increment(&mut report.backend_failures)?;
                }
            }
            let attempts = row
                .attempts
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?;
            if delivery_failed && attempts >= config.max_attempts {
                guard = self
                    .park(guard, Arc::unwrap_or_clone(row), attempts)
                    .await?;
                increment(&mut report.failed)?;
                increment(&mut report.parked)?;
            } else if delivery_failed {
                let next_attempt_at_unix_ms = now_unix_ms
                    .checked_add(retry_delay(config, attempts))
                    .ok_or_else(PortError::integrity_failure)?;
                let ((), returned_guard) = self
                    .with_store(guard, move |store| {
                        store.record_failure(&row, next_attempt_at_unix_ms)
                    })
                    .await?;
                guard = returned_guard;
                increment(&mut report.failed)?;
            } else {
                let names = Arc::clone(&backend_names);
                let ((), returned_guard) = self
                    .with_store(guard, move |store| {
                        let names: Vec<&str> = names.iter().map(String::as_str).collect();
                        store.record_delivery(&row, &names, now_unix_ms)
                    })
                    .await?;
                guard = returned_guard;
                increment(&mut report.delivered)?;
            }
        }
        Ok(report)
    }

    async fn park<G: Send + 'static>(
        &self,
        guard: G,
        row: DueSecurityAlert,
        attempts: u32,
    ) -> PortResult<G> {
        self.with_store(guard, move |store| store.record_parked(&row, attempts))
            .await
            .map(|((), guard)| guard)
    }

    pub(in crate::security) async fn delivery_backlog(
        &self,
    ) -> PortResult<SecurityAlertOutboxBacklog> {
        self.with_store((), |store| store.backlog())
            .await
            .map(|(backlog, ())| backlog)
    }

    /// Custody moves into the blocking operation and returns only after it
    /// finishes. Cancelling the await cannot release delivery serialization
    /// while a confirmation is still committing.
    async fn with_store<T, G>(
        &self,
        custody: G,
        operation: impl FnOnce(&dyn SecurityAlertOutboxStore) -> PortResult<T> + Send + 'static,
    ) -> PortResult<(T, G)>
    where
        T: Send + 'static,
        G: Send + 'static,
    {
        let store = Arc::clone(&self.store);
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| PortError::unavailable())?;
        let task =
            runtime.spawn_blocking(move || operation(store.as_ref()).map(|value| (value, custody)));
        match task.await {
            Ok(result) => result,
            Err(error) if error.is_panic() => resume_unwind(error.into_panic()),
            Err(_) => Err(PortError::unavailable()),
        }
    }
}
