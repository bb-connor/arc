//! loom model of the receipt commit actor's command-channel accounting.
//!
//! loom cannot execute SQLite, so this models the protocol invariant the
//! real actor relies on: a pre-send inflight increment is owned by a
//! per-command release-once lease, held for the command's full execution, and
//! bounded-queue rejection releases only that command's count. Inflight count
//! and backlog-anchor transitions share one lock, so a rejected first
//! reservation cannot mask accepted work behind it.
//! The lease protocol is command-agnostic: the same modeled `Command` covers
//! Append, Flush, Write, Rotate, RetentionRepair, ReseedHead, and InstallSigner.
//! Run: RUSTFLAGS="--cfg chio_store_sqlite_loom" cargo test -p chio-store-sqlite --test loom_receipt_writer --release
#![cfg_attr(not(any(loom, chio_store_sqlite_loom)), allow(dead_code))]

#[cfg(any(loom, chio_store_sqlite_loom))]
mod model {
    use loom::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use loom::sync::{Arc, Mutex};
    use loom::thread;
    use std::collections::VecDeque;

    const QUEUE_CAPACITY: usize = 2;

    #[derive(Clone)]
    struct InflightReleaseHandle {
        state: Arc<InflightState>,
    }

    struct InflightState {
        inflight: Arc<AtomicU64>,
        backlog_started: Arc<AtomicU64>,
        transition: Arc<Mutex<()>>,
        released: AtomicBool,
    }

    impl InflightReleaseHandle {
        fn release(&self) {
            if !self.state.released.swap(true, Ordering::SeqCst) {
                let _transition = match self.state.transition.lock() {
                    Ok(transition) => transition,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let current = self.state.inflight.load(Ordering::SeqCst);
                let next = current.saturating_sub(1);
                self.state.inflight.store(next, Ordering::SeqCst);
                if next == 0 {
                    self.state.backlog_started.store(0, Ordering::SeqCst);
                }
            }
        }
    }

    struct InflightLease {
        release_handle: Option<InflightReleaseHandle>,
    }

    impl InflightLease {
        fn acquire(
            inflight: &Arc<AtomicU64>,
            backlog_started: &Arc<AtomicU64>,
            transition: &Arc<Mutex<()>>,
        ) -> (Self, InflightReleaseHandle, u64) {
            let release_handle = InflightReleaseHandle {
                state: Arc::new(InflightState {
                    inflight: Arc::clone(inflight),
                    backlog_started: Arc::clone(backlog_started),
                    transition: Arc::clone(transition),
                    released: AtomicBool::new(false),
                }),
            };
            let lease = Self {
                release_handle: Some(release_handle.clone()),
            };
            let _transition = match transition.lock() {
                Ok(transition) => transition,
                Err(poisoned) => poisoned.into_inner(),
            };
            let previous_inflight = inflight.load(Ordering::SeqCst);
            if previous_inflight == 0 {
                backlog_started.store(1, Ordering::SeqCst);
            }
            inflight.store(previous_inflight.saturating_add(1), Ordering::SeqCst);
            (lease, release_handle, previous_inflight)
        }

        fn release(mut self) {
            if let Some(release_handle) = self.release_handle.take() {
                release_handle.release();
            }
        }
    }

    impl Drop for InflightLease {
        fn drop(&mut self) {
            if let Some(release_handle) = self.release_handle.take() {
                release_handle.release();
            }
        }
    }

    struct Command {
        job: u64,
        inflight: InflightLease,
    }

    struct Channel {
        queue: Mutex<VecDeque<Command>>,
        inflight: Arc<AtomicU64>,
        backlog_started: Arc<AtomicU64>,
        transition: Arc<Mutex<()>>,
    }

    impl Channel {
        fn new() -> Self {
            Self {
                queue: Mutex::new(VecDeque::new()),
                inflight: Arc::new(AtomicU64::new(0)),
                backlog_started: Arc::new(AtomicU64::new(0)),
                transition: Arc::new(Mutex::new(())),
            }
        }

        fn try_send(&self, job: u64) -> Option<InflightReleaseHandle> {
            let (inflight, release_handle, _previous_inflight) =
                InflightLease::acquire(&self.inflight, &self.backlog_started, &self.transition);
            match self.queue.lock() {
                Ok(mut queue) if queue.len() < QUEUE_CAPACITY => {
                    queue.push_back(Command { job, inflight });
                    Some(release_handle)
                }
                Ok(_) | Err(_) => {
                    // The caller and rejected command both see the same release
                    // handle. Either release may run first; the command-scoped
                    // bit guarantees one decrement.
                    release_handle.release();
                    None
                }
            }
        }

        fn drain(&self) -> u64 {
            let mut drained = 0;
            loop {
                let job = match self.queue.lock() {
                    Ok(mut queue) => queue.pop_front(),
                    Err(_) => None,
                };
                let Some(command) = job else { break };
                let _job = command.job;
                // The actor retains the lease through work completion, then
                // releases immediately before response fanout.
                command.inflight.release();
                drained += 1;
            }
            drained
        }
    }

    // Thin wrapper over the single-consumer drain loop. The accounting is
    // command-agnostic, so one drain helper covers all producer shapes.
    fn drain_all(channel: &Channel) -> u64 {
        channel.drain()
    }

    #[test]
    fn inflight_accounting_never_leaks_across_append_write_flush() {
        loom::model(|| {
            let channel = Arc::new(Channel::new());

            let producer_a = {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.try_send(1)) // Append-shaped
            };
            let producer_b = {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.try_send(2)) // Write-shaped
            };
            let consumer = {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.drain()) // actor loop
            };

            let sent_a = producer_a.join().ok().flatten();
            let sent_b = producer_b.join().ok().flatten();
            let _ = consumer.join();
            // Final drain (actor keeps running until channel close).
            channel.drain();

            let accepted = u64::from(sent_a.is_some()) + u64::from(sent_b.is_some());
            let _ = accepted;
            assert_eq!(
                channel.inflight.load(Ordering::SeqCst),
                0,
                "inflight must be zero after every accepted job is drained"
            );
            assert_eq!(channel.backlog_started.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn inflight_accounting_never_leaks_across_intent_consume_flush() {
        loom::model(|| {
            let channel = Arc::new(Channel::new());
            // The dispatch-intent journal adds two producer shapes to the one
            // channel: a metadata-only intent insert (Write-shaped) and the
            // consuming receipt append (Append-shaped). The accounting is
            // command-agnostic, so no interleaving with a concurrent drain
            // may leak or double-count inflight.
            let intent_writer = {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.try_send(10)) // Write-shaped intent insert
            };
            let consuming_appender = {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.try_send(11)) // Append-shaped consume
            };
            let drainer = {
                let channel = Arc::clone(&channel);
                thread::spawn(move || channel.drain())
            };
            let _ = intent_writer.join();
            let _ = consuming_appender.join();
            let _ = drainer.join();
            channel.drain();
            assert_eq!(
                channel.inflight.load(Ordering::SeqCst),
                0,
                "inflight must be zero after every accepted intent and consume drains"
            );
            assert_eq!(channel.backlog_started.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn append_and_rotate_preserve_inflight_accounting() {
        loom::model(|| {
            let channel = Arc::new(Channel::new());
            let appender = {
                let channel = Arc::clone(&channel);
                thread::spawn(move || {
                    let _ = channel.try_send(1); // Append-shaped
                })
            };
            let rotator = {
                let channel = Arc::clone(&channel);
                thread::spawn(move || {
                    let _ = channel.try_send(2); // Rotate-shaped
                })
            };
            // Single consumer retains each command lease through completion.
            drain_all(&channel);
            appender.join().ok();
            rotator.join().ok();
            drain_all(&channel);
            // No leaked or double-counted inflight, regardless of interleaving.
            assert_eq!(channel.inflight.load(Ordering::SeqCst), 0);
            assert_eq!(channel.backlog_started.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn duplicate_release_cannot_consume_another_commands_count() {
        loom::model(|| {
            let inflight = Arc::new(AtomicU64::new(0));
            let backlog_started = Arc::new(AtomicU64::new(0));
            let transition = Arc::new(Mutex::new(()));
            let (first_lease, first_release, first_previous) =
                InflightLease::acquire(&inflight, &backlog_started, &transition);
            let (second_lease, _second_release, second_previous) =
                InflightLease::acquire(&inflight, &backlog_started, &transition);
            assert_eq!(first_previous, 0);
            assert_eq!(second_previous, 1);
            assert_eq!(inflight.load(Ordering::SeqCst), 2);

            let actor_release = thread::spawn(move || first_lease.release());
            let caller_release = thread::spawn(move || first_release.release());
            let _ = actor_release.join();
            let _ = caller_release.join();

            assert_eq!(
                inflight.load(Ordering::SeqCst),
                1,
                "duplicate release must leave the second command counted"
            );
            assert_eq!(backlog_started.load(Ordering::SeqCst), 1);
            second_lease.release();
            assert_eq!(inflight.load(Ordering::SeqCst), 0);
            assert_eq!(backlog_started.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn rejected_prev_zero_reservation_preserves_later_accepted_backlog() {
        loom::model(|| {
            let inflight = Arc::new(AtomicU64::new(0));
            let backlog_started = Arc::new(AtomicU64::new(0));
            let transition = Arc::new(Mutex::new(()));

            // The first producer reserves the 0 -> 1 transition, then stalls.
            // A later producer reserves behind it and is accepted first.
            let (rejected_lease, rejected_release, rejected_previous) =
                InflightLease::acquire(&inflight, &backlog_started, &transition);
            let (accepted_lease, _accepted_release, accepted_previous) =
                InflightLease::acquire(&inflight, &backlog_started, &transition);
            assert_eq!(rejected_previous, 0);
            assert_eq!(accepted_previous, 1);
            assert_eq!(inflight.load(Ordering::SeqCst), 2);
            assert_eq!(backlog_started.load(Ordering::SeqCst), 1);

            // Model the first producer's rejected `try_send`. Its command drop
            // and caller compensation race through the same release-once bit.
            let command_drop = thread::spawn(move || drop(rejected_lease));
            let caller_release = thread::spawn(move || rejected_release.release());
            let _ = command_drop.join();
            let _ = caller_release.join();

            assert_eq!(inflight.load(Ordering::SeqCst), 1);
            assert_eq!(
                backlog_started.load(Ordering::SeqCst),
                1,
                "the rejected first reservation must not erase accepted work's anchor"
            );
            accepted_lease.release();
            assert_eq!(inflight.load(Ordering::SeqCst), 0);
            assert_eq!(backlog_started.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn final_release_cannot_clear_a_concurrent_fresh_reservations_anchor() {
        loom::model(|| {
            let inflight = Arc::new(AtomicU64::new(0));
            let backlog_started = Arc::new(AtomicU64::new(0));
            let transition = Arc::new(Mutex::new(()));
            let (old_lease, _old_release, old_previous) =
                InflightLease::acquire(&inflight, &backlog_started, &transition);
            assert_eq!(old_previous, 0);

            let release = thread::spawn(move || old_lease.release());
            let reserve = {
                let inflight = Arc::clone(&inflight);
                let backlog_started = Arc::clone(&backlog_started);
                let transition = Arc::clone(&transition);
                thread::spawn(move || {
                    InflightLease::acquire(&inflight, &backlog_started, &transition).0
                })
            };
            let _ = release.join();
            let fresh_lease = match reserve.join() {
                Ok(lease) => lease,
                Err(_) => panic!("fresh reservation thread panicked"),
            };

            assert_eq!(inflight.load(Ordering::SeqCst), 1);
            assert_eq!(
                backlog_started.load(Ordering::SeqCst),
                1,
                "a prior final release must not clear a concurrent reservation's anchor"
            );
            fresh_lease.release();
            assert_eq!(inflight.load(Ordering::SeqCst), 0);
            assert_eq!(backlog_started.load(Ordering::SeqCst), 0);
        });
    }

    #[derive(Clone)]
    struct TimeoutReleaseHandle {
        state: Arc<TimeoutReleaseState>,
    }

    struct TimeoutReleaseState {
        transition: Mutex<()>,
        released: AtomicBool,
        timeout_observed: AtomicBool,
        timeout_marked: AtomicBool,
        inflight: Arc<AtomicU64>,
        timeout_total: Arc<AtomicU64>,
        timed_out_inflight: Arc<AtomicU64>,
    }

    impl TimeoutReleaseHandle {
        fn note_timeout(&self) {
            let _transition = match self.state.transition.lock() {
                Ok(transition) => transition,
                Err(poisoned) => poisoned.into_inner(),
            };
            if self.state.timeout_observed.swap(true, Ordering::SeqCst) {
                return;
            }
            self.state.timeout_total.fetch_add(1, Ordering::SeqCst);
            if !self.state.released.load(Ordering::SeqCst) {
                self.state.timeout_marked.store(true, Ordering::SeqCst);
                self.state.timed_out_inflight.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn release(&self) {
            let _transition = match self.state.transition.lock() {
                Ok(transition) => transition,
                Err(poisoned) => poisoned.into_inner(),
            };
            if self.state.released.swap(true, Ordering::SeqCst) {
                return;
            }
            if self.state.timeout_marked.swap(false, Ordering::SeqCst) {
                let timed_out = self.state.timed_out_inflight.load(Ordering::SeqCst);
                self.state
                    .timed_out_inflight
                    .store(timed_out.saturating_sub(1), Ordering::SeqCst);
            }
            let inflight = self.state.inflight.load(Ordering::SeqCst);
            self.state
                .inflight
                .store(inflight.saturating_sub(1), Ordering::SeqCst);
        }
    }

    #[test]
    fn timeout_observation_racing_terminal_release_cannot_leak_a_marker() {
        loom::model(|| {
            let accepted = Arc::new(AtomicU64::new(1));
            let committed = Arc::new(AtomicU64::new(0));
            let inflight = Arc::new(AtomicU64::new(1));
            let timeout_total = Arc::new(AtomicU64::new(0));
            let timed_out_inflight = Arc::new(AtomicU64::new(0));
            let handle = TimeoutReleaseHandle {
                state: Arc::new(TimeoutReleaseState {
                    transition: Mutex::new(()),
                    released: AtomicBool::new(false),
                    timeout_observed: AtomicBool::new(false),
                    timeout_marked: AtomicBool::new(false),
                    inflight: Arc::clone(&inflight),
                    timeout_total: Arc::clone(&timeout_total),
                    timed_out_inflight: Arc::clone(&timed_out_inflight),
                }),
            };

            let timeout = {
                let handle = handle.clone();
                thread::spawn(move || handle.note_timeout())
            };
            let terminal = {
                let handle = handle.clone();
                let committed = Arc::clone(&committed);
                thread::spawn(move || {
                    // Terminal accounting is published before lease release.
                    committed.fetch_add(1, Ordering::SeqCst);
                    handle.release();
                })
            };
            let _ = timeout.join();
            let _ = terminal.join();

            assert_eq!(accepted.load(Ordering::SeqCst), 1);
            assert_eq!(committed.load(Ordering::SeqCst), 1);
            assert_eq!(inflight.load(Ordering::SeqCst), 0);
            assert_eq!(timeout_total.load(Ordering::SeqCst), 1);
            assert_eq!(timed_out_inflight.load(Ordering::SeqCst), 0);

            // Re-observing this command after terminal release is idempotent and
            // cannot install a stale active marker.
            handle.note_timeout();
            assert_eq!(timeout_total.load(Ordering::SeqCst), 1);
            assert_eq!(timed_out_inflight.load(Ordering::SeqCst), 0);
        });
    }
}
