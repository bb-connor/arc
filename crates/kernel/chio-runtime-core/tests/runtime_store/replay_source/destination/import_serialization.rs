use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use chio_core_types::StoreMutationFence;
use chio_kernel::admission_operation::{
    AdmissionOperationStoreError, RuntimeReplaySourceSnapshotV1,
};
use chio_store_sqlite::SqliteAdmissionOperationStore;

use super::*;

fn unavailable(error: impl std::fmt::Display) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Unavailable(error.to_string())
}

fn assert_busy<T: std::fmt::Debug>(result: Result<T, AdmissionOperationStoreError>) {
    match result {
        Err(AdmissionOperationStoreError::Invariant(detail)) => {
            assert!(detail.contains("runtime replay migration is already in progress"));
        }
        other => panic!("expected owner-wide migration exclusion, got {other:?}"),
    }
}

fn pin_real_source(
    store: &SqliteAdmissionOperationStore,
    source: &SqliteRuntimeOrchestrationStore,
    fence: &StoreMutationFence,
) -> TestResult<(AdmissionIdentifier, RuntimeReplayMigrationRecordV1)> {
    seed_inventory(source)?;
    let runtime = AdmissionIdentifier::try_new("runtime_authority_id", "serialized-runtime")?;
    let source_id = AdmissionIdentifier::try_new("source_id", "serialized-source")?;
    let expected =
        store.expect_runtime_replay_source(&source_id, &runtime, source, fence, now_ms()?)?;
    Ok((runtime, expected))
}

struct BlockingSource<'a> {
    inner: &'a SqliteRuntimeOrchestrationStore,
    entered: mpsc::Sender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
    seal_calls: AtomicUsize,
}

impl RuntimeReplaySourcePort for BlockingSource<'_> {
    fn preview(
        &self,
        source_id: &AdmissionIdentifier,
        runtime: &AdmissionIdentifier,
        destination: &AdmissionIdentifier,
    ) -> Result<RuntimeReplaySourceSnapshotV1, AdmissionOperationStoreError> {
        self.inner.preview(source_id, runtime, destination)
    }

    fn seal_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        if self.seal_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.send(()).map_err(unavailable)?;
            // Channels establish the ordering. This timeout only bounds a
            // broken guard's deadlock; it is not a scheduling assertion.
            self.resume
                .lock()
                .map_err(unavailable)?
                .recv_timeout(Duration::from_secs(10))
                .map_err(unavailable)?;
        }
        self.inner.seal_exact(expected)
    }

    fn verify_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.inner.verify_exact(expected)
    }
}

#[test]
fn owner_shared_import_guard_rejects_concurrency_without_blocking_destination_reads() -> TestResult
{
    let (directory, database, _lock_root, authority) = destination_fixture()?;
    let source_path = directory.path().join("concurrent-source.sqlite3");
    let inner = SqliteRuntimeOrchestrationStore::open(&source_path)?;
    // Separately constructed adapters must share the same owner's guard.
    let first = authority.admission_operation_store();
    let second = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let (runtime, expected) = pin_real_source(&first, &inner, &fence)?;
    let (entered_send, entered_recv) = mpsc::channel();
    let (resume_send, resume_recv) = mpsc::channel();
    let source = BlockingSource {
        inner: &inner,
        entered: entered_send,
        resume: Mutex::new(resume_recv),
        seal_calls: AtomicUsize::new(0),
    };
    let observed = now_ms()?;
    let imported = std::thread::scope(|scope| -> TestResult<RuntimeReplayMigrationRecordV1> {
        let worker = scope.spawn(|| {
            first.import_runtime_replay_source(
                &runtime,
                expected.expectation_id(),
                &source,
                &fence,
                observed,
            )
        });
        let while_blocked = (|| -> TestResult {
            entered_recv.recv_timeout(Duration::from_secs(10))?;
            assert_eq!(
                second.load_runtime_replay_migration(&runtime, &fence, now_ms()?)?,
                Some(expected.clone()),
                "source I/O must not hold the destination database mutex",
            );
            assert_busy(second.import_runtime_replay_source(
                &runtime,
                expected.expectation_id(),
                &source,
                &fence,
                now_ms()?,
            ));
            assert_eq!(source.seal_calls.load(Ordering::SeqCst), 1);
            assert!(!expected.imported_inactive());
            Ok(())
        })();
        // Always unblock the worker on ordinary errors. Callback timeouts also
        // bound unwinding if an assertion exposes a broken implementation.
        let resumed = resume_send.send(());
        let result = worker.join().map_err(|_| "migration worker panicked")?;
        while_blocked?;
        resumed?;
        Ok(result?)
    })?;
    assert!(imported.imported_inactive());
    assert_destination_history(&Connection::open(&database)?, &imported)?;

    // Once the first import is durable, a later invocation may only verify.
    // Removing every seal artifact must not turn it into a new pending seal.
    let raw = Connection::open(&source_path)?;
    let triggers = raw.prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'trigger' AND name GLOB 'runtime_replay_source_*'",
    )?.query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for trigger in triggers {
        raw.execute_batch(&format!("DROP TRIGGER {trigger}"))?;
    }
    raw.execute_batch("DROP TABLE runtime_replay_source_seal")?;
    let damaged = raw_snapshot(&raw)?;
    assert!(second
        .import_runtime_replay_source(
            &runtime,
            expected.expectation_id(),
            &source,
            &fence,
            now_ms()?,
        )
        .is_err());
    assert_eq!(source.seal_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        raw_snapshot(&raw)?,
        damaged,
        "an imported source must not be repaired"
    );
    assert_destination_history(&Connection::open(&database)?, &imported)?;
    Ok(())
}

struct ReentrantSource<'a> {
    inner: &'a SqliteRuntimeOrchestrationStore,
    adapter: &'a SqliteAdmissionOperationStore,
    runtime: &'a AdmissionIdentifier,
    expectation_id: &'a AdmissionIdentifier,
    fence: &'a StoreMutationFence,
    observed: u64,
    attempts: AtomicUsize,
}

impl ReentrantSource<'_> {
    fn check_reentrancy(&self) -> Result<(), AdmissionOperationStoreError> {
        // Without exclusion, fail promptly instead of recursing indefinitely.
        assert!(self.attempts.fetch_add(1, Ordering::SeqCst) < 2);
        assert_busy(self.adapter.import_runtime_replay_source(
            self.runtime,
            self.expectation_id,
            self,
            self.fence,
            self.observed,
        ));
        assert!(self
            .adapter
            .load_runtime_replay_migration(self.runtime, self.fence, self.observed,)?
            .is_some());
        Ok(())
    }
}

impl RuntimeReplaySourcePort for ReentrantSource<'_> {
    fn preview(
        &self,
        source_id: &AdmissionIdentifier,
        runtime: &AdmissionIdentifier,
        destination: &AdmissionIdentifier,
    ) -> Result<RuntimeReplaySourceSnapshotV1, AdmissionOperationStoreError> {
        self.inner.preview(source_id, runtime, destination)
    }

    fn seal_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.check_reentrancy()?;
        self.inner.seal_exact(expected)
    }

    fn verify_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.check_reentrancy()?;
        self.inner.verify_exact(expected)
    }
}

#[test]
fn owner_shared_import_guard_rejects_reentrant_seal_and_verify_callbacks() -> TestResult {
    let (directory, database, _lock_root, authority) = destination_fixture()?;
    let inner =
        SqliteRuntimeOrchestrationStore::open(directory.path().join("reentrant-source.sqlite3"))?;
    let first = authority.admission_operation_store();
    let second = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let (runtime, expected) = pin_real_source(&first, &inner, &fence)?;
    let source = ReentrantSource {
        inner: &inner,
        adapter: &second,
        runtime: &runtime,
        expectation_id: expected.expectation_id(),
        fence: &fence,
        observed: now_ms()?,
        attempts: AtomicUsize::new(0),
    };
    let imported = first.import_runtime_replay_source(
        &runtime,
        expected.expectation_id(),
        &source,
        &fence,
        now_ms()?,
    )?;
    assert_eq!(source.attempts.load(Ordering::SeqCst), 2);
    assert!(imported.imported_inactive());
    assert_eq!(
        second.import_runtime_replay_source(
            &runtime,
            expected.expectation_id(),
            &inner,
            &fence,
            now_ms()?,
        )?,
        imported,
        "the guard must be released after success"
    );
    assert_destination_history(&Connection::open(&database)?, &imported)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Failure {
    Error,
    Panic,
}

struct FailAfterSeal<'a> {
    inner: &'a SqliteRuntimeOrchestrationStore,
    failure: Failure,
    fail_once: AtomicBool,
}

impl RuntimeReplaySourcePort for FailAfterSeal<'_> {
    fn preview(
        &self,
        source_id: &AdmissionIdentifier,
        runtime: &AdmissionIdentifier,
        destination: &AdmissionIdentifier,
    ) -> Result<RuntimeReplaySourceSnapshotV1, AdmissionOperationStoreError> {
        self.inner.preview(source_id, runtime, destination)
    }

    fn seal_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.inner.seal_exact(expected)?;
        if self.fail_once.swap(false, Ordering::SeqCst) {
            match self.failure {
                Failure::Error => return Err(unavailable("injected lost seal acknowledgement")),
                Failure::Panic => panic!("injected panic after source seal commit"),
            }
        }
        Ok(())
    }

    fn verify_exact(
        &self,
        expected: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.inner.verify_exact(expected)
    }
}

fn assert_guard_released_after_failure(failure: Failure) -> TestResult {
    let (directory, database, _lock_root, authority) = destination_fixture()?;
    let inner =
        SqliteRuntimeOrchestrationStore::open(directory.path().join("failed-source.sqlite3"))?;
    let first = authority.admission_operation_store();
    let second = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let (runtime, expected) = pin_real_source(&first, &inner, &fence)?;
    let source = FailAfterSeal {
        inner: &inner,
        failure,
        fail_once: AtomicBool::new(true),
    };
    let observed = now_ms()?;
    let failed = catch_unwind(AssertUnwindSafe(|| {
        first.import_runtime_replay_source(
            &runtime,
            expected.expectation_id(),
            &source,
            &fence,
            observed,
        )
    }));
    match failure {
        Failure::Error => match failed {
            Ok(Err(AdmissionOperationStoreError::Unavailable(detail))) => {
                assert!(detail.contains("injected lost seal acknowledgement"));
            }
            other => panic!("expected injected lost acknowledgement, got {other:?}"),
        },
        Failure::Panic => assert!(failed.is_err(), "the configured source must actually panic"),
    }
    assert_eq!(
        second.load_runtime_replay_migration(&runtime, &fence, now_ms()?)?,
        Some(expected.clone())
    );
    RuntimeReplaySourcePort::verify_exact(&inner, expected.snapshot())?;
    assert_all_legacy_kinds_blocked(&inner);
    assert_destination_history(&Connection::open(&database)?, &expected)?;
    let imported = second.import_runtime_replay_source(
        &runtime,
        expected.expectation_id(),
        &source,
        &fence,
        now_ms()?,
    )?;
    assert!(imported.imported_inactive());
    assert_eq!(imported.snapshot(), expected.snapshot());
    assert_destination_history(&Connection::open(&database)?, &imported)?;
    Ok(())
}

#[test]
fn owner_shared_import_guard_releases_after_committed_source_loses_acknowledgement() -> TestResult {
    assert_guard_released_after_failure(Failure::Error)
}

#[test]
fn owner_shared_import_guard_releases_after_committed_source_panics() -> TestResult {
    assert_guard_released_after_failure(Failure::Panic)
}

#[test]
fn pending_pin_survives_owner_restart_after_real_source_seal_before_import() -> TestResult {
    let (directory, database, lock_root, authority) = destination_fixture()?;
    let source_path = directory.path().join("interrupted-source.sqlite3");
    let source = SqliteRuntimeOrchestrationStore::open(&source_path)?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let (runtime, expected) = pin_real_source(&store, &source, &fence)?;

    // Model the interruption boundary after a committed source seal but before
    // the destination receives its acknowledgment and records event 2. This
    // test uses normal drop/reopen, not a subprocess or power-loss simulation.
    RuntimeReplaySourcePort::seal_exact(&source, expected.snapshot())?;
    RuntimeReplaySourcePort::verify_exact(&source, expected.snapshot())?;
    assert_all_legacy_kinds_blocked(&source);
    assert_eq!(
        store.load_runtime_replay_migration(&runtime, &fence, now_ms()?)?,
        Some(expected.clone()),
    );
    assert_destination_history(&Connection::open(&database)?, &expected)?;
    drop(store);
    drop(authority);
    drop(source);

    let reopened_authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let reopened_fence = reopened_authority.mutation_fence();
    assert_eq!(reopened_fence.store_uuid, fence.store_uuid);
    assert!(reopened_fence.owner_epoch > fence.owner_epoch);
    let reopened_store = reopened_authority.admission_operation_store();
    let reopened_source = SqliteRuntimeOrchestrationStore::open(&source_path)?;
    let pending = reopened_store
        .load_runtime_replay_migration(&runtime, &reopened_fence, now_ms()?)?
        .ok_or("pending expectation disappeared on owner restart")?;
    assert_eq!(pending, expected);
    assert!(!pending.imported_inactive());
    assert_code(
        reopened_source.preview_legacy_replay_source(&source_binding(&pending)?),
        "runtime_replay_source_sealed",
    );
    assert_eq!(
        reopened_store.expect_runtime_replay_source(
            &AdmissionIdentifier::try_new("source_id", expected.snapshot().source_id())?,
            &runtime,
            &reopened_source,
            &reopened_fence,
            now_ms()?,
        )?,
        expected,
        "retry must retain the confirmed pin without previewing a sealed source",
    );
    let imported = reopened_store.import_runtime_replay_source(
        &runtime,
        expected.expectation_id(),
        &reopened_source,
        &reopened_fence,
        now_ms()?,
    )?;
    assert!(imported.imported_inactive());
    assert_eq!(
        imported.snapshot().canonical_bytes(),
        expected.snapshot().canonical_bytes()
    );
    assert_eq!(imported.expectation_id(), expected.expectation_id());
    RuntimeReplaySourcePort::verify_exact(&reopened_source, expected.snapshot())?;
    assert_all_legacy_kinds_blocked(&reopened_source);
    assert_destination_history(&Connection::open(&database)?, &imported)?;
    Ok(())
}
