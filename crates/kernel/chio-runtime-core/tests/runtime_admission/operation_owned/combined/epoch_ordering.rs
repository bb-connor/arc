use super::*;
use chio_core_types::crypto::Ed25519Backend;
use chio_runtime_core::treaty_epoch::{
    sign_treaty_epoch_record, TreatyEpochStatusV1, VerifiedTreatyEpochUpdate,
};
use chio_runtime_core::{RuntimeAdmissionAuthorityCommit, RuntimeTreatyAuthorizationBinding};
use std::sync::atomic::AtomicBool;

struct OrderedEpochStore {
    inner: SqliteRuntimeOrchestrationStore,
    updater: SqliteRuntimeOrchestrationStore,
    update: VerifiedTreatyEpochUpdate,
    before_commit: bool,
    changed: Arc<AtomicBool>,
}

impl OrderedEpochStore {
    fn advance(&self) -> Result<(), ChioRuntimeError> {
        self.updater.apply_treaty_epoch_update(
            self.update.body().previous_record_sha256.as_ref(),
            &self.update,
        )?;
        self.changed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

impl RuntimeAdmissionStore for OrderedEpochStore {
    fn commit_runtime_admission_authority(
        &self,
        request: &RuntimeAdmissionAuthorityCommit,
    ) -> Result<(), ChioRuntimeError> {
        assert!(request.treaty().is_some());
        if self.before_commit {
            self.advance()?;
        }
        self.inner.commit_runtime_admission_authority(request)?;
        if !self.before_commit {
            self.advance()?;
        }
        Ok(())
    }
    fn verify_retained_runtime_treaty_authorization(
        &self,
        binding: &RuntimeTreatyAuthorizationBinding,
    ) -> Result<(), ChioRuntimeError> {
        self.inner
            .verify_retained_runtime_treaty_authorization(binding)
    }
    fn verify_operation_owned_runtime_source(
        &self,
        expected: &chio_kernel::admission_operation::RuntimeSourceQualificationV1,
    ) -> Result<(), ChioRuntimeError> {
        self.inner.verify_operation_owned_runtime_source(expected)
    }
    fn bundle(&self, id: &str) -> Result<Option<RuntimeAdmissionBundle>, ChioRuntimeError> {
        self.inner.bundle(id)
    }
    fn treaty_runtime_artifact(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Option<runtime_api::TreatyRuntimeArtifactRecord>, ChioRuntimeError> {
        self.inner.treaty_runtime_artifact(kind, id)
    }
    fn runtime_trust_floor(
        &self,
        verifier: &str,
        key: &str,
    ) -> Result<Option<RuntimeTrustFloorEntry>, ChioRuntimeError> {
        RuntimeAdmissionStore::runtime_trust_floor(&self.inner, verifier, key)
    }
    fn record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
    ) -> Result<(), ChioRuntimeError> {
        RuntimeAdmissionStore::record_runtime_trust_floor(&self.inner, entry)
    }
    fn validate_and_record_runtime_trust_floor(
        &self,
        entry: RuntimeTrustFloorEntry,
        previous: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        RuntimeAdmissionStore::validate_and_record_runtime_trust_floor(&self.inner, entry, previous)
    }
}

#[test]
fn prepared_treaty_admission_observes_epoch_commit_order_and_preserves_custody() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    for before_commit in [true, false] {
        let mut epoch = None;
        let fixture = CombinedFixture::with_treaty_input(|treaty, _, _| {
            let mut body = treaty.epoch_update.body().clone();
            body.sequence += 1;
            body.previous_record_sha256 = Some(treaty.epoch_update.body_digest().clone());
            body.status = TreatyEpochStatusV1::Revoked;
            epoch = Some(sign_treaty_epoch_record(
                body,
                &Ed25519Backend::new(treaty.epoch_key.clone()),
                &treaty.epoch_authority,
            )?);
            Ok(())
        })?;
        let changed = Arc::new(AtomicBool::new(false));
        let path = fixture.inner._directory.path().join("runtime.sqlite3");
        let store = OrderedEpochStore {
            inner: SqliteRuntimeOrchestrationStore::open_with_clock(
                &path,
                chio_test_support::clock::clock(),
            )?,
            updater: SqliteRuntimeOrchestrationStore::open_with_clock(
                &path,
                chio_test_support::clock::clock(),
            )?,
            update: epoch.ok_or("signed next epoch")?,
            before_commit,
            changed: changed.clone(),
        };
        let (trust, keys, report, policy, weights) = signed_policy_inputs(0.1)?;
        let hook = ChioRuntimeAdmissionHook::new(profile(), store, fixture.inner.binding.clone())
            .with_runtime_trust_input(trust, keys)
            .with_pheromone_query_report(report)
            .with_runtime_pheromone_policy(policy, weights)
            .with_swarm_graph_source(Arc::new(IssuedGraphs(
                fixture.inner.authority.work_graph_store(),
            )))
            .with_swarm_witness_keys(trusted_swarm_witness_keys());
        let kernel = fixture.kernel(hook)?;
        let response = kernel.evaluate_tool_call_blocking_with_metadata(
            &fixture.inner.request,
            Some(swarm_route_metadata()),
        )?;
        assert!(changed.load(Ordering::SeqCst));
        assert!(response.receipt.verify_signature()?);
        let history = faults::history(&fixture.inner)?;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].intent.resources().len(), 3);
        let (operation, _) = fixture.history(&history[0].reference)?;
        if before_commit {
            assert_eq!(response.verdict, Verdict::Deny, "{response:#?}");
            assert_eq!(
                response
                    .receipt
                    .metadata
                    .as_ref()
                    .ok_or("denial metadata")?["chio_runtime"]["failure_code"],
                "treaty_revoked"
            );
            assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 0);
            assert!(operation.dispatch_commit().is_none());
            assert_eq!(
                history[0].disposition,
                RuntimeParticipantDisposition::ReleasedBeforeDispatch
            );
        } else {
            assert_eq!(response.verdict, Verdict::Allow, "{response:#?}");
            assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
            assert!(operation.dispatch_commit().is_some());
            assert_eq!(
                history[0].disposition,
                RuntimeParticipantDisposition::RetainedAfterDispatchCommit
            );
        }
    }
    Ok(())
}
