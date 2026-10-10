use super::*;
use std::sync::{atomic::AtomicBool, mpsc, Mutex, Weak};

fn reading(elapsed: u64) -> ClockReading {
    use chio_security_types::clock::{MonotonicInstant, UnixMillis};
    ClockReading::new(
        UnixMillis::new(1_700_000_000_000 + elapsed),
        MonotonicInstant::from_nanos(elapsed * 1_000_000),
    )
}

fn adapter(clock: Arc<dyn Clock>) -> Arc<A2aAdapter> {
    let server = FakeA2aServer::spawn_jsonrpc_push_notification_capability_only().unwrap();
    let adapter = A2aAdapter::discover(
        test_adapter_config(server.base_url(), Keypair::generate().public_key().to_hex())
            .with_clock(clock),
    )
    .unwrap();
    server.join();
    Arc::new(adapter)
}

struct InterleavedClock {
    armed: AtomicBool,
    reads: AtomicU64,
    adapter: Mutex<Weak<A2aAdapter>>,
    sampled: mpsc::SyncSender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl Clock for InterleavedClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        if !self.armed.load(Ordering::SeqCst) {
            return Ok(reading(0));
        }
        let index = self.reads.fetch_add(1, Ordering::SeqCst);
        let sampled = reading(index + 1);
        if index == 0 {
            let adapter = self.adapter.lock().unwrap().upgrade().unwrap();
            // Model preemption after sampling. Another lookup can overtake this
            // observation only when the sample has no cache lock protecting it.
            let can_overtake = adapter.token_cache.try_lock().is_ok();
            self.sampled.send(()).unwrap();
            if can_overtake {
                self.resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
        }
        Ok(sampled)
    }
}

#[test]
fn review_regression_concurrent_cache_hits_do_not_invent_clock_regression() {
    let (sampled_tx, sampled_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let clock = Arc::new(InterleavedClock {
        armed: AtomicBool::new(false),
        reads: AtomicU64::new(0),
        adapter: Mutex::new(Weak::new()),
        sampled: sampled_tx,
        resume: Mutex::new(resume_rx),
    });
    let adapter = adapter(clock.clone());
    *clock.adapter.lock().unwrap() = Arc::downgrade(&adapter);
    adapter
        .store_cached_bearer_token("key".into(), "secret".into(), Some(60), reading(0))
        .unwrap();
    clock.armed.store(true, Ordering::SeqCst);
    let first_adapter = adapter.clone();
    let first = thread::spawn(move || first_adapter.lookup_cached_bearer_token("key"));
    sampled_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let second = adapter.lookup_cached_bearer_token("key");
    resume_tx.send(()).unwrap();
    let first = first.join().unwrap();
    assert_eq!(second.unwrap().as_deref(), Some("secret"));
    assert_eq!(first.unwrap().as_deref(), Some("secret"));
}

struct FinalObservationClock(ClockReading);
impl Clock for FinalObservationClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        Ok(self.0)
    }
}

#[test]
fn review_regression_final_token_observation_rejects_advertised_expiry() {
    for ttl in [1, 31, 0] {
        let adapter = adapter(Arc::new(FinalObservationClock(reading(ttl * 1000))));
        // Acquiring or validating earlier cannot admit a token that has expired
        // at this final observation, whether or not the skew permits caching.
        assert!(matches!(
            adapter.store_cached_bearer_token("key".into(), "secret".into(), Some(ttl), reading(0)),
            Err(AdapterError::Clock(ClockError::Expired))
        ));
        assert!(adapter.token_cache.lock().unwrap().is_empty());
    }
}
