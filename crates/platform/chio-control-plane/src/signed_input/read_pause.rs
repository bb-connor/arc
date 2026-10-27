use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, LazyLock, Mutex};
use std::time::Duration;

struct Barrier {
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    released: mpsc::Receiver<()>,
    bound: Duration,
}

static BARRIERS: LazyLock<Mutex<BTreeMap<PathBuf, Barrier>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub(crate) struct ReadPause {
    path: PathBuf,
    release: mpsc::Sender<()>,
}

impl ReadPause {
    pub(crate) fn install(
        path: &Path,
        bound: Duration,
    ) -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let (entered, receiver) = tokio::sync::mpsc::unbounded_channel();
        let (release, released) = mpsc::channel();
        let mut barriers = BARRIERS.lock().unwrap_or_else(|error| error.into_inner());
        assert!(!barriers.contains_key(path), "read pause already installed");
        barriers.insert(
            path.to_owned(),
            Barrier {
                entered,
                released,
                bound,
            },
        );
        (
            Self {
                path: path.to_owned(),
                release,
            },
            receiver,
        )
    }

    pub(crate) fn release(self) {
        drop(self);
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
    }
}
