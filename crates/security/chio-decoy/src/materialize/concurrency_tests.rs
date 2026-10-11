use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Mutex;
use std::time::Duration;

use std::os::unix::fs::MetadataExt;

use super::*;

const PAUSE_LIMIT: Duration = Duration::from_secs(30);

pub(super) struct PublicationPause {
    entered: SyncSender<std::fs::File>,
    resume: Mutex<Receiver<()>>,
}

impl PublicationPause {
    pub(super) fn wait(&self, staging: &std::fs::File) {
        let duplicate = staging
            .try_clone()
            .unwrap_or_else(|error| panic!("duplicate staging descriptor: {error}"));
        self.entered
            .send(duplicate)
            .unwrap_or_else(|error| panic!("announce durable stage: {error}"));
        self.resume
            .lock()
            .unwrap_or_else(|error| panic!("publication pause poisoned: {error}"))
            .recv_timeout(PAUSE_LIMIT)
            .unwrap_or_else(|error| panic!("resume publication: {error}"));
    }
}

fn identity() -> MaterializationIdentity {
    MaterializationIdentity {
        operation_id: "concurrent-materialization".into(),
        tenant_id: "tenant".into(),
        artifact_id: "artifact".into(),
        version_hash: [7; 32],
    }
}

fn materializer(root: &std::path::Path) -> FileMaterializer {
    FileMaterializer::open(root, OwnershipKey::from_bytes([23; 32]))
        .unwrap_or_else(|error| panic!("open materializer: {error}"))
}

#[test]
fn concurrent_exact_retry_cannot_replace_a_durable_stage_before_publication() {
    check_concurrent_retry(false);
}

#[test]
fn same_materializer_calls_acquire_independent_lock_descriptions() {
    check_concurrent_retry(true);
}

#[test]
fn completed_publication_unlocks_even_while_a_duplicate_descriptor_lives() {
    let root = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let mut first = materializer(root.path());
    let second = materializer(root.path());
    let identity = identity();
    let request = MaterializationRequest {
        identity: &identity,
        relative_path: std::path::Path::new("inherited.txt"),
        content: b"complete durable contents",
    };
    let (entered_tx, entered_rx) = sync_channel(1);
    let (resume_tx, resume_rx) = sync_channel(1);
    first.pause_publication_for_test(PublicationPause {
        entered: entered_tx,
        resume: Mutex::new(resume_rx),
    });
    let (receipt, inherited) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| first.materialize(&request));
        // A duplicate shares the open file description, just as an inherited
        // descriptor does between fork and exec in another host thread.
        let inherited = entered_rx
            .recv_timeout(PAUSE_LIMIT)
            .unwrap_or_else(|error| panic!("receive staging descriptor: {error}"));
        resume_tx
            .send(())
            .unwrap_or_else(|error| panic!("release publication: {error}"));
        let receipt = worker
            .join()
            .unwrap_or_else(|_| panic!("publication worker panicked"))
            .unwrap_or_else(|error| panic!("original publication: {error}"));
        (receipt, inherited)
    });
    let retry = second
        .materialize(&request)
        .unwrap_or_else(|error| panic!("retry while inherited descriptor lives: {error}"));
    assert_eq!(retry, receipt);
    drop(inherited);
}

fn check_concurrent_retry(same_instance: bool) {
    let root = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let mut first = materializer(root.path());
    let second = materializer(root.path());
    let identity = identity();
    let request = MaterializationRequest {
        identity: &identity,
        relative_path: std::path::Path::new("concurrent.txt"),
        content: b"complete durable contents",
    };
    let (entered_tx, entered_rx) = sync_channel(1);
    let (resume_tx, resume_rx) = sync_channel(1);
    first.pause_publication_for_test(PublicationPause {
        entered: entered_tx,
        resume: Mutex::new(resume_rx),
    });

    let (competing, stage_unchanged, premature_final, original) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| first.materialize(&request));
        entered_rx
            .recv_timeout(PAUSE_LIMIT)
            .unwrap_or_else(|error| panic!("wait for durable stage: {error}"));
        let stage = std::fs::read_dir(root.path().join(".chio-decoy-stage"))
            .unwrap_or_else(|error| panic!("read staging directory: {error}"))
            .next()
            .unwrap_or_else(|| panic!("durable stage is absent"))
            .unwrap_or_else(|error| panic!("read staging entry: {error}"))
            .path();
        let before = std::fs::metadata(&stage)
            .unwrap_or_else(|error| panic!("inspect original stage: {error}"));
        let competing = if same_instance {
            first.materialize(&request)
        } else {
            second.materialize(&request)
        };
        let stage_unchanged = std::fs::metadata(&stage)
            .is_ok_and(|after| before.ino() == after.ino() && before.len() == after.len());
        let premature_final = root.path().join(request.relative_path).exists();
        // Always release the worker before asserting the competing outcome.
        resume_tx
            .send(())
            .unwrap_or_else(|error| panic!("release publication: {error}"));
        let original = worker
            .join()
            .unwrap_or_else(|_| panic!("publication worker panicked"));
        (competing, stage_unchanged, premature_final, original)
    });

    assert!(
        matches!(
            competing,
            Err(MaterializeError::Io {
                kind: std::io::ErrorKind::WouldBlock,
                ..
            })
        ),
        "a live publication must exclude competing retry: {competing:?}"
    );
    assert!(
        stage_unchanged,
        "competing retry replaced the durable stage"
    );
    assert!(!premature_final, "competing retry published the final file");
    let original = original.unwrap_or_else(|error| panic!("original publication: {error}"));
    assert_eq!(
        second
            .materialize(&request)
            .unwrap_or_else(|error| panic!("retry after lock release: {error}")),
        original
    );
    assert_eq!(
        std::fs::read(root.path().join(request.relative_path))
            .unwrap_or_else(|error| panic!("read published contents: {error}")),
        request.content
    );
}

#[test]
fn dropped_lock_allows_torn_stage_recovery_and_exact_final_retry() {
    use rustix::fs::{flock, FlockOperation};

    let root = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let first = materializer(root.path());
    let second = materializer(root.path());
    let identity = identity();
    let request = MaterializationRequest {
        identity: &identity,
        relative_path: std::path::Path::new("recovered.txt"),
        content: b"complete durable contents",
    };
    first
        .stage_without_publish_for_test(&request)
        .unwrap_or_else(|error| panic!("seed interrupted stage: {error}"));
    let directory = root.path().join(".chio-decoy-stage");
    let held = std::fs::File::open(&directory)
        .unwrap_or_else(|error| panic!("open staging directory: {error}"));
    flock(&held, FlockOperation::NonBlockingLockExclusive)
        .unwrap_or_else(|error| panic!("hold staging directory: {error}"));
    let stage = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("read staging directory: {error}"))
        .next()
        .unwrap_or_else(|| panic!("staging entry is absent"))
        .unwrap_or_else(|error| panic!("read staging entry: {error}"))
        .path();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&stage)
        .unwrap_or_else(|error| panic!("open interrupted write: {error}"));
    file.set_len(3)
        .unwrap_or_else(|error| panic!("simulate interrupted write: {error}"));
    drop(file);
    assert_would_block(second.materialize(&request));
    assert_eq!(
        std::fs::read(&stage).unwrap_or_else(|error| panic!("read held stage: {error}")),
        b"com"
    );
    assert!(!root.path().join(request.relative_path).exists());
    // Closing the last descriptor releases this kernel-owned lock. No persistent
    // lease or lockfile needs repair; inherited descriptors can extend its lifetime.
    drop(held);
    let receipt = second
        .materialize(&request)
        .unwrap_or_else(|error| panic!("recover after holder exit: {error}"));
    assert_eq!(
        std::fs::read(root.path().join(request.relative_path))
            .unwrap_or_else(|error| panic!("read recovered file: {error}")),
        request.content
    );

    let held = std::fs::File::open(&directory)
        .unwrap_or_else(|error| panic!("reopen staging directory: {error}"));
    flock(&held, FlockOperation::NonBlockingLockExclusive)
        .unwrap_or_else(|error| panic!("hold exact retry: {error}"));
    assert_would_block(second.materialize(&request));
    drop(held);
    assert_eq!(
        second
            .materialize(&request)
            .unwrap_or_else(|error| panic!("exact retry after holder exit: {error}")),
        receipt
    );
}

fn assert_would_block(result: Result<MaterializationReceipt, MaterializeError>) {
    assert!(
        matches!(
            result,
            Err(MaterializeError::Io {
                operation: "lock materialization staging directory",
                kind: std::io::ErrorKind::WouldBlock,
            })
        ),
        "contended materialization must return retryable WouldBlock: {result:?}"
    );
}
