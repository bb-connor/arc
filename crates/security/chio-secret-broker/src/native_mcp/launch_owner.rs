//! Custody of the thread that creates a confined native process.
use std::ops::Deref;
use std::sync::mpsc;

use chio_kernel::KernelError;
use tokio::sync::{oneshot, Semaphore};

use super::refused_at;

// Bound both in-flight preparations and retained threads. This owner can never
// increase the cage's separate limit on supervised children.
static LAUNCH_THREADS: Semaphore = Semaphore::const_new(64);

pub(super) struct LaunchOwner<T> {
    // Field order matters: shutdown and terminal receipt persistence in T::drop
    // must finish before releasing the child's creating thread.
    value: T,
    _release_thread: mpsc::Sender<()>,
}

impl<T: Send + 'static> LaunchOwner<T> {
    pub(super) async fn prepare(
        prepare: impl FnOnce() -> Result<T, KernelError> + Send + 'static,
    ) -> Result<Self, KernelError> {
        Self::prepare_with_capacity(&LAUNCH_THREADS, prepare).await
    }

    async fn prepare_with_capacity(
        capacity: &'static Semaphore,
        prepare: impl FnOnce() -> Result<T, KernelError> + Send + 'static,
    ) -> Result<Self, KernelError> {
        let permit = capacity
            .try_acquire()
            .map_err(|_| refused_at("launch thread capacity"))?;
        let (result_sender, result_receiver) = oneshot::channel();
        let (release_thread, released) = mpsc::channel();
        std::thread::Builder::new()
            .name("chio-broker-native-launch".into())
            .spawn(move || {
                let _permit = permit;
                let result = prepare().map(|value| Self {
                    value,
                    _release_thread: release_thread,
                });
                if let Err(undelivered) = result_sender.send(result) {
                    // Cancellation during preparation still destroys the value
                    // on its live launch thread, including native cleanup.
                    drop(undelivered);
                    return;
                }
                // Linux PR_SET_PDEATHSIG belongs to the creating thread. A
                // pooled worker may retire while the prepared child is live.
                // This dedicated thread instead lives until its owner drops;
                // host death continues to kill the confined child in-kernel.
                let _ = released.recv();
            })
            .map_err(|_| refused_at("launch thread start"))?;
        result_receiver
            .await
            .map_err(|_| refused_at("launch thread completion"))?
    }
}

impl<T> Deref for LaunchOwner<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
