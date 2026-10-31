use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, LazyLock, Mutex};
use std::time::Duration;

struct Barrier {
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    released: mpsc::Receiver<()>,
    bound: Duration,
    finished: Arc<AtomicBool>,
}

static BARRIERS: LazyLock<Mutex<BTreeMap<(u64, u64), Barrier>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub(crate) struct ReadPause {
    identity: (u64, u64),
    release: mpsc::Sender<()>,
    finished: Arc<AtomicBool>,
}

impl ReadPause {
    pub(crate) fn install(
        path: &Path,
        bound: Duration,
    ) -> std::io::Result<(Self, tokio::sync::mpsc::UnboundedReceiver<()>)> {
        chio_secure_ipc::regular_file::test_support::set_read_hook(wait);
        let metadata = std::fs::metadata(path)?;
        let identity = (metadata.dev(), metadata.ino());
        let (entered, receiver) = tokio::sync::mpsc::unbounded_channel();
        let (release, released) = mpsc::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let mut barriers = BARRIERS.lock().unwrap_or_else(|error| error.into_inner());
        assert!(
            !barriers.contains_key(&identity),
            "read pause already installed"
        );
        barriers.insert(
            identity,
            Barrier {
                entered,
                released,
                bound,
                finished: Arc::clone(&finished),
            },
        );
        Ok((
            Self {
                identity,
                release,
                finished,
            },
            receiver,
        ))
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
            .remove(&self.identity);
        let _ = self.release.send(());
    }
}

fn wait(dev: u64, ino: u64) {
    let barrier = BARRIERS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&(dev, ino));
    if let Some(barrier) = barrier {
        let _ = barrier.entered.send(());
        let _ = barrier.released.recv_timeout(barrier.bound);
        barrier.finished.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn read_pause_matches_a_canonical_read_after_install_through_a_directory_alias(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let directory = chio_test_support::private_tempdir()?;
    let real = directory.path().join("real");
    std::fs::create_dir(&real)?;
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias)?;
    let file = real.join("registry.json");
    std::fs::write(&file, b"{}")?;
    let bound = Duration::from_secs(10);
    let (pause, mut entered) = ReadPause::install(&alias.join("registry.json"), bound)?;
    let canonical = file.canonicalize()?;
    let read = tokio::task::spawn_blocking(move || super::read_bounded(&canonical));
    tokio::time::timeout(bound, entered.recv())
        .await?
        .ok_or("aliased registry read did not enter pause")?;
    assert!(!pause.is_finished());
    assert!(!read.is_finished());
    pause.release();
    assert_eq!(tokio::time::timeout(bound, read).await???, b"{}");
    Ok(())
}
