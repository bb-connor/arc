//! Deterministic ordering at the credential version check and dispatch commit.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc::sync_channel, Arc, TryLockError};
use std::time::Duration;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
fn credential() -> CredentialRef {
    CredentialRef {
        provider: "generic-https".into(),
        credential_id: "credential-race".into(),
        version: 1,
    }
}
fn mutate(backend: &EncryptedBlobSecretBackend, delete: bool) -> Result<()> {
    if delete {
        backend.delete(&credential())
    } else {
        backend.disable(&credential())
    }
}
fn assert_missing<T>(result: Result<T>) {
    assert!(matches!(result, Err(BrokerError::Storage(ref message))
        if message == "credential reference credential-race was not found"));
}

#[test]
fn disable_and_delete_before_dispatch_prevent_commit_of_materialized_credentials() -> TestResult {
    for delete in [false, true] {
        let backend = Arc::new(EncryptedBlobSecretBackend::open_in_memory_for_test(
            "tenant-race",
            [7; 32],
        )?);
        backend.provision(&credential(), b"never dispatched")?;
        let commits = Arc::new(AtomicUsize::new(0));
        let (prepared, observed) = sync_channel(1);
        let (resume, waiting) = sync_channel(1);
        let worker = std::thread::spawn({
            let backend = backend.clone();
            let commits = commits.clone();
            move || -> Result<()> {
                let (_material, version) = backend.materialize_for_dispatch(&credential())?;
                prepared
                    .send(())
                    .map_err(|_| BrokerError::Invariant("prepared barrier closed".into()))?;
                waiting
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|_| BrokerError::Invariant("resume barrier closed".into()))?;
                backend.authorize_dispatch(&credential(), &version, || {
                    commits.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            }
        });
        observed.recv_timeout(Duration::from_secs(5))?;
        mutate(&backend, delete)?;
        resume.send(())?;
        assert_missing(worker.join().map_err(|_| "dispatch thread panicked")?);
        assert_eq!(commits.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn dispatch_commit_holds_the_mutation_fence_and_later_use_is_denied() -> TestResult {
    for delete in [false, true] {
        let backend = Arc::new(EncryptedBlobSecretBackend::open_in_memory_for_test(
            "tenant-race",
            [7; 32],
        )?);
        backend.provision(&credential(), b"one captured dispatch")?;
        let (_material, version) = backend.materialize_for_dispatch(&credential())?;
        let (entered, observed) = sync_channel(1);
        let (resume, waiting) = sync_channel(1);
        let worker = std::thread::spawn({
            let backend = backend.clone();
            let version = version.clone();
            move || {
                backend.authorize_dispatch(&credential(), &version, || {
                    entered
                        .send(())
                        .map_err(|_| BrokerError::Invariant("commit barrier closed".into()))?;
                    waiting
                        .recv_timeout(Duration::from_secs(5))
                        .map_err(|_| BrokerError::Invariant("commit resume closed".into()))?;
                    Ok(1)
                })
            }
        });
        observed.recv_timeout(Duration::from_secs(5))?;
        assert!(matches!(
            backend.credential_mutations.try_write(),
            Err(TryLockError::WouldBlock)
        ));
        let mutation = std::thread::spawn({
            let backend = backend.clone();
            move || mutate(&backend, delete)
        });
        resume.send(())?;
        assert_eq!(worker.join().map_err(|_| "dispatch thread panicked")??, 1);
        mutation.join().map_err(|_| "mutation thread panicked")??;
        assert_missing(backend.authorize_dispatch(&credential(), &version, || Ok(())));
    }
    Ok(())
}
