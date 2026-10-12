use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::Arc;

use chio_security_types::ports::{PortError, PortResult};
use rusqlite::Connection;

use super::{
    backend_alert, increment, validate_backends, AlertDispatchReport, AlertOutboxBacklog,
    SqliteSiemOutbox,
};

pub(super) mod store;

#[cfg(test)]
mod tests;

impl SqliteSiemOutbox {
    /// Dispatches up to `limit` due rows to their unconfirmed backends.
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
            .with_store(guard, move |connection| {
                store::ensure_ready(connection)?;
                store::load_due(connection, config, now_unix_ms, limit)
            })
            .await?;
        let mut report = AlertDispatchReport::default();
        for row in due {
            let row = Arc::new(row);
            increment(&mut report.attempted)?;
            let alert = backend_alert(&row.alert)?;
            let stored = Arc::clone(&row);
            let (confirmed, returned_guard) = self
                .with_store(guard, move |connection| {
                    store::load_confirmed_backends(connection, &stored)
                })
                .await?;
            guard = returned_guard;
            let mut delivery_failed = false;
            for backend in &self.backends {
                if confirmed.contains(backend.name()) {
                    continue;
                }
                increment(&mut report.backend_dispatches)?;
                let accepted = backend.dispatch(&alert).await.is_ok();
                let name = backend.name().to_owned();
                let stored = Arc::clone(&row);
                let ((), returned_guard) = self
                    .with_store(guard, move |connection| {
                        store::record_backend_outcome(
                            connection,
                            &stored,
                            &name,
                            accepted,
                            now_unix_ms,
                        )
                    })
                    .await?;
                guard = returned_guard;
                if !accepted {
                    delivery_failed = true;
                    increment(&mut report.backend_failures)?;
                }
            }
            if delivery_failed {
                let (parked, returned_guard) = self
                    .with_store(guard, move |connection| {
                        store::record_failure(connection, config, &row, now_unix_ms)
                    })
                    .await?;
                guard = returned_guard;
                if parked {
                    increment(&mut report.parked)?;
                }
                increment(&mut report.failed)?;
            } else {
                let backends = self.backends.clone();
                let ((), returned_guard) = self
                    .with_store(guard, move |connection| {
                        store::record_delivery(connection, config, &backends, &row, now_unix_ms)
                    })
                    .await?;
                guard = returned_guard;
                increment(&mut report.delivered)?;
            }
        }
        Ok(report)
    }

    pub(in crate::security) async fn delivery_backlog(&self) -> PortResult<AlertOutboxBacklog> {
        let config = self.config;
        self.with_store((), move |connection| store::backlog(connection, config))
            .await
            .map(|(backlog, ())| backlog)
    }

    /// Custody moves into the blocking operation and returns only after it
    /// finishes. Cancelling the await cannot release delivery serialization
    /// while a confirmation is still committing. The worker drops its runtime
    /// before reporting thread completion, draining any started store operation.
    async fn with_store<T, G>(
        &self,
        custody: G,
        operation: impl FnOnce(&mut Connection) -> PortResult<T> + Send + 'static,
    ) -> PortResult<(T, G)>
    where
        T: Send + 'static,
        G: Send + 'static,
    {
        let connection = Arc::clone(&self.connection);
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| PortError::unavailable())?;
        let task = runtime.spawn_blocking(move || {
            let mut connection = connection.lock().map_err(|_| PortError::unavailable())?;
            // Transaction destructors roll back inside this unwind boundary.
            // Drop the mutex guard normally before resuming a panic, so a later
            // pass can recover without ignoring a poisoned connection lock.
            let result = catch_unwind(AssertUnwindSafe(|| operation(&mut connection)));
            drop(connection);
            match result {
                Ok(result) => result.map(|value| (value, custody)),
                Err(payload) => resume_unwind(payload),
            }
        });
        match task.await {
            Ok(result) => result,
            Err(error) if error.is_panic() => resume_unwind(error.into_panic()),
            Err(_) => Err(PortError::unavailable()),
        }
    }
}
