use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, LazyLock, Mutex};
use std::time::Duration;

struct Barrier {
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    released: mpsc::Receiver<()>,
    bound: Duration,
    finished: Arc<AtomicBool>,
}

static BARRIERS: LazyLock<Mutex<BTreeMap<PathBuf, Barrier>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub(crate) struct ReadPause {
    path: PathBuf,
    release: mpsc::Sender<()>,
    finished: Arc<AtomicBool>,
}

impl ReadPause {
    pub(crate) fn install(
        path: &Path,
        bound: Duration,
    ) -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let (entered, receiver) = tokio::sync::mpsc::unbounded_channel();
        let (release, released) = mpsc::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let mut barriers = BARRIERS.lock().unwrap_or_else(|error| error.into_inner());
        assert!(!barriers.contains_key(path), "read pause already installed");
        barriers.insert(
            path.to_owned(),
            Barrier {
                entered,
                released,
                bound,
                finished: Arc::clone(&finished),
            },
        );
        (
            Self {
                path: path.to_owned(),
                release,
                finished,
            },
            receiver,
        )
    }

    pub(crate) fn release(self) {
        drop(self);
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.finished.load(Ordering::SeqCst)
    }
}

impl Drop for ReadPause {
    fn drop(&mut self) {
        BARRIERS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.path);
        let _ = self.release.send(());
    }
}

pub(super) fn wait(path: &Path) {
    let barrier = BARRIERS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(path);
    if let Some(barrier) = barrier {
        let _ = barrier.entered.send(());
        let _ = barrier.released.recv_timeout(barrier.bound);
        barrier.finished.store(true, Ordering::SeqCst);
    }
}
