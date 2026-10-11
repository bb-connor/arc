use super::*;

static METRICS_TEST_LOCK: Mutex<()> = Mutex::new(());

pub(super) fn metrics_test_guard() -> std::sync::MutexGuard<'static, ()> {
    match METRICS_TEST_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
