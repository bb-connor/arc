//! The effect watchdog starts at TCP readiness and has an invocation owner.
use super::super::observation_owner::{cancelled, private_pair};
use super::*;
use rustix::event::Timespec;
use std::sync::mpsc::{self, TryRecvError};

impl EffectObserver {
    pub(super) fn start(control: Arc<Control>) -> io::Result<Self> {
        let (owner, cancel) = private_pair()?;
        let (ready, receiver) = mpsc::channel();
        let task = thread::spawn(move || {
            let tick = Timespec {
                tv_sec: 0,
                tv_nsec: 2_000_000,
            };
            loop {
                match receiver.try_recv() {
                    Ok(()) => break,
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        return Err(io::Error::other(
                            "provider readiness ended without dispatch",
                        ));
                    }
                }
                if cancelled(&cancel, Some(&tick))? {
                    return Err(io::Error::other(
                        "provider observation owner cancelled before readiness",
                    ));
                }
            }
            // This is the original effect observation budget, measured only
            // after the real provider connection is queued for the TLS helper.
            let deadline = Instant::now() + Duration::from_secs(10);
            while !control.effect_gate.exists() {
                assert!(
                    Instant::now() < deadline,
                    "provider effect was never observed"
                );
                if cancelled(&cancel, Some(&tick))? {
                    // The real marker can race owner closure while poll is
                    // blocked. Validate that effect before treating EOF as an
                    // unobserved cancellation; no trigger is synthesized.
                    if control.effect_gate.exists() {
                        break;
                    }
                    return Err(io::Error::other(
                        "provider observation ended without its effect",
                    ));
                }
            }
            assert_eq!(
                fs::read(&control.effect_gate).test_expect("provider effect marker"),
                b"observed"
            );
            control.kill_at(Point::ProviderEffect);
            write_private(
                &control.effect_gate.with_extension("release"),
                b"broker-dead",
            );
            Ok(())
        });
        Ok(Self {
            owner: Some(owner),
            ready: Some(ready),
            task: Some(task),
        })
    }

    pub(in super::super) fn take_ready_sender(&mut self) -> Option<mpsc::Sender<()>> {
        self.ready.take()
    }

    pub(in super::super) fn finish_after_invoke(mut self) -> TestResult {
        drop(self.ready.take());
        drop(self.owner.take());
        self.task
            .take()
            .test_expect("owned effect observation worker")
            .join()
            .map_err(|_| "provider cutpoint observer panicked")??;
        Ok(())
    }
}

impl Drop for EffectObserver {
    fn drop(&mut self) {
        drop(self.ready.take());
        drop(self.owner.take());
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}
