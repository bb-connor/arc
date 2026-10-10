use super::*;

/// Bounded poll loop: re-verify the directory and either swap in a successor, alarm +
/// deny-all on expiry, or keep last-good. Wakes at most every `interval`, but also
/// exactly at the running directory's expiry deadline (see [`next_reload_delay`]) so an
/// expired directory fails closed promptly instead of admitting until the next fixed
/// poll. A dedicated task feeds shared state (the admission gate and the alive flag)
/// and is joined on shutdown.
pub(crate) async fn run_directory_reloader(
    gate: DirectoryGate,
    config: DirectoryReloadConfig,
    now_fn: Arc<dyn Fn() -> std::io::Result<u64> + Send + Sync>,
    alive: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut state = ReloadState::from_gate(&gate);
    loop {
        let result = (|| -> std::io::Result<Duration> {
            let now = now_fn()?;
            directory_reload_step(&gate, &config, now, &mut state, &alive);
            Ok(next_reload_delay(
                config.interval,
                now_fn()?,
                gate.current_expires_at_unix_ms(),
            ))
        })();
        let delay = match result {
            Ok(delay) => delay,
            Err(_) => {
                gate.swap(Arc::new(
                    chio_federation_transport_iroh::identity::VerifiedDirectory::empty_deny_all(),
                ));
                alive.store(false, std::sync::atomic::Ordering::SeqCst);
                tracing::error!("transport directory clock unavailable; admission disabled");
                config.interval
            }
        };
        tokio::time::sleep(delay).await;
    }
}
