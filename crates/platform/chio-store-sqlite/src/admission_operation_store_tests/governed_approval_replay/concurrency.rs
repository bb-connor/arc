use super::*;

struct Reentrant<'a> {
    raw: &'a Source,
    store: SqliteAdmissionOperationStore,
    fence: StoreMutationFence,
    expected: &'a GovernedApprovalReplayMigrationRecordV1,
}

impl GovernedApprovalReplaySourcePort for Reentrant<'_> {
    fn preview_unsealed(
        &self,
        binding: &GovernedApprovalReplaySourceBinding,
    ) -> Result<GovernedApprovalReplaySourceSnapshot, AdmissionOperationStoreError> {
        self.raw.preview_unsealed(binding)
    }

    fn seal_exact(
        &self,
        expected: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        assert_eq!(
            self.store
                .load_governed_approval_replay_migration(
                    &identifier("authority", AUTHORITY_ID),
                    &self.fence,
                    now_ms()
                )?
                .as_ref(),
            Some(self.expected)
        );
        let error = self
            .store
            .import_governed_approval_replay_source(
                &identifier("authority", AUTHORITY_ID),
                self.expected.expectation_id(),
                self.raw,
                &self.fence,
                now_ms(),
            )
            .expect_err("reentry rejects without waiting");
        assert!(error.to_string().contains("already in progress"), "{error}");
        self.raw.seal_exact(expected)
    }

    fn verify_exact(
        &self,
        expected: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.raw.verify_exact(expected)
    }
}

#[test]
fn source_can_read_destination_but_cannot_reenter_import_through_another_adapter(
) -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    let reentrant = Reentrant {
        raw: &source,
        store: fixture.authority.admission_operation_store(),
        fence: fixture.fence.clone(),
        expected: &expected,
    };
    assert!(import(&fixture, &reentrant, &expected)?.imported_inactive());
    assert_eq!(source.calls(), ["preview", "seal", "verify"]);
    Ok(())
}

struct BlockingSource<'a> {
    source: &'a Source,
    entered: std::sync::mpsc::SyncSender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl GovernedApprovalReplaySourcePort for BlockingSource<'_> {
    fn preview_unsealed(
        &self,
        binding: &GovernedApprovalReplaySourceBinding,
    ) -> Result<GovernedApprovalReplaySourceSnapshot, AdmissionOperationStoreError> {
        self.source.preview_unsealed(binding)
    }

    fn seal_exact(
        &self,
        expected: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.entered.send(()).expect("signal callback");
        self.release
            .lock()
            .expect("release lock")
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("release source");
        self.source.seal_exact(expected)
    }

    fn verify_exact(
        &self,
        expected: &GovernedApprovalReplaySourceSnapshot,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.source.verify_exact(expected)
    }
}

#[test]
fn concurrent_import_and_runtime_source_workflows_share_nonblocking_owner_guard(
) -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let expected = pin(&fixture, &source)?;
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let blocked = BlockingSource {
        source: &source,
        entered: entered_tx,
        release: Mutex::new(release_rx),
    };
    std::thread::scope(|scope| -> AnchoredTestResult {
        let running = scope.spawn(|| import(&fixture, &blocked, &expected));
        entered_rx.recv_timeout(std::time::Duration::from_secs(20))?;
        let store = fixture.authority.admission_operation_store();
        let concurrent = store.import_governed_approval_replay_source(
            &identifier("authority", AUTHORITY_ID),
            expected.expectation_id(),
            &source,
            &fixture.fence,
            now_ms(),
        );
        let shared = store.serving_owner.begin_replay_source_migration();
        release_tx.send(())?;
        assert!(concurrent
            .expect_err("concurrent import")
            .to_string()
            .contains("already in progress"));
        assert!(
            shared.is_err(),
            "runtime and approval workflows use the same owner guard"
        );
        assert!(running.join().expect("import worker")?.imported_inactive());
        Ok(())
    })?;
    assert_eq!(counts(&fixture), [3, 2, 1]);
    Ok(())
}
