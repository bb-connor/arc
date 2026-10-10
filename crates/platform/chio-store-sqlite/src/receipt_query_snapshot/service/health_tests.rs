use super::*;
fn ready_service() -> (tempfile::TempDir, ReceiptQuerySnapshots) {
    let directory = chio_test_support::private_tempdir().unwrap();
    let store = Arc::new(SqliteReceiptStore::open(directory.path().join("receipts.db")).unwrap());
    let service = ReceiptQuerySnapshots::start(
        store,
        ReceiptQuerySnapshotConfig {
            invalid_retry_backoff: Duration::from_secs(60),
            ..ReceiptQuerySnapshotConfig::default()
        },
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while service.status().state != ReceiptQuerySnapshotState::Ready {
        assert!(Instant::now() < deadline, "snapshot did not become ready");
        std::thread::sleep(Duration::from_millis(5));
    }
    (directory, service)
}

#[test]
fn health_uses_a_coherent_sample_while_the_database_is_held() {
    let (_directory, service) = ready_service();
    service.pause_extension_for_test(true);
    let Phase::Ready(published) = service.inner.phase() else {
        panic!("service was not ready");
    };
    let held = published.owned.lock().unwrap();
    let expected = published.watermark_of(&held.meta);
    let (sent, received) = std::sync::mpsc::channel();
    let status = std::thread::scope(|scope| {
        scope.spawn(|| sent.send(service.health_status()).unwrap());
        let status = received.recv_timeout(Duration::from_secs(5));
        drop(held);
        status
    })
    .expect("health queued behind a held database connection");
    assert_eq!(status.state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(status.tool_receipts, 0);
    assert_eq!(status.watermark, Some(expected));
    assert!(status.used_bytes > 0);
    assert_eq!(status.dimensions, 0);
    service.shutdown();
    let stopped = service.health_status();
    assert_eq!(stopped.state, ReceiptQuerySnapshotState::Stopped);
    assert_eq!(stopped.watermark, None);
}

#[test]
fn telemetry_lock_contention_returns_without_waiting_or_read_admission() {
    let (_directory, service) = ready_service();
    let Phase::Ready(published) = service.inner.phase() else {
        panic!("service was not ready");
    };
    let held_sample = published.health_sample.lock().unwrap();
    assert_eq!(
        service.health_status().state,
        ReceiptQuerySnapshotState::Unavailable {
            reason: "receipt snapshot health sample update in progress".into(),
        }
    );
    drop(held_sample);
    let held_phase = service.inner.phase.lock().unwrap();
    assert_eq!(
        service.health_status().state,
        ReceiptQuerySnapshotState::Unavailable {
            reason: "receipt snapshot health transition in progress".into(),
        }
    );
    drop(held_phase);
    assert_eq!(service.inner.readers.load(Ordering::SeqCst), 0);
    service.shutdown();
}

#[test]
fn invalidation_supersedes_a_previous_ready_health_sample() {
    let (_directory, service) = ready_service();
    service.inner.invalidate("test integrity failure");
    let status = service.health_status();
    assert_eq!(
        status.state,
        ReceiptQuerySnapshotState::Invalid {
            reason: "test integrity failure".into(),
        }
    );
    assert_eq!(status.watermark, None);
    service.shutdown();
}
