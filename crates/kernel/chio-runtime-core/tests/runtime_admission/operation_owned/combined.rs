//! Live composed admission with signed treaty/swarm evidence and physical
//! replay custody. Fixture signatures are genuine; no verifier is bypassed.

use super::*;
use chio_federation::bilateral::InProcessCoSigner;
use chio_federation::trust_establishment::{KernelTrustExchange, PeerHandshakeEnvelope};
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantClaimHistoryV1, RuntimeParticipantClaimReferenceV1,
};
use chio_kernel::admission_operation::{AdmissionOperationV1, RuntimeParticipantKind};
use chio_store_sqlite::SqliteReceiptStore;

#[path = "combined/lifecycle.rs"]
mod lifecycle;

#[path = "combined/contention.rs"]
mod contention;

#[path = "combined/crash.rs"]
mod crash;

#[path = "combined/native_validity.rs"]
mod native_validity;

struct CombinedFixture {
    inner: Fixture,
    origin_key: Keypair,
    local_key: Keypair,
}

impl CombinedFixture {
    fn new() -> TestResult<Self> {
        Self::with_treaty_input(|_, _, _| Ok(()))
    }

    fn with_treaty_input(
        prepare: impl FnOnce(&mut TreatyRuntimeFixture, &Keypair, &Keypair) -> TestResult,
    ) -> TestResult<Self> {
        Self::with_swarm_input(prepare, runtime_swarm_bundle(false)?)
    }

    fn with_swarm_input(
        prepare: impl FnOnce(&mut TreatyRuntimeFixture, &Keypair, &Keypair) -> TestResult,
        swarm: SwarmAuthorityBundle,
    ) -> TestResult<Self> {
        let origin_key = Keypair::generate();
        let local_key = Keypair::generate();
        let mut treaty = treaty_runtime_fixture_with_signers(
            allow_policy_evaluation_summary(),
            origin_key.clone(),
            local_key.clone(),
        )?;
        prepare(&mut treaty, &origin_key, &local_key)?;
        let inner = Fixture::with_request(true, |source, authority| {
            let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
            let mut admission = bundle();
            admission.binding.tool_args_sha256 = tool_args_sha256(&args)?;
            let hash = runtime_admission_bundle_sha256(&admission)?;
            source.insert_bundle(admission)?;
            insert_treaty_runtime_fixture(source, &treaty)?;
            issue_root(authority, &swarm)?;
            let mut request =
                chio_swarm_runtime_request(args, hash, swarm_runtime_context(&swarm)?)?;
            request.federated_origin_kernel_id = Some("kernel.buyer".into());
            request
                .governed_intent
                .as_mut()
                .and_then(|intent| intent.context.as_mut())
                .and_then(serde_json::Value::as_object_mut)
                .ok_or("combined governed context")?
                .insert("chioTreaty".into(), treaty_runtime_context(&treaty));
            Ok(request)
        })?;
        Ok(Self {
            inner,
            origin_key,
            local_key,
        })
    }

    fn hook(&self) -> TestResult<ChioRuntimeAdmissionHook<SqliteRuntimeOrchestrationStore>> {
        Ok(self
            .inner
            .hook()?
            .with_swarm_witness_keys(trusted_swarm_witness_keys()))
    }

    fn reopen(self) -> TestResult<Self> {
        let Self {
            inner,
            origin_key,
            local_key,
        } = self;
        let Fixture {
            _directory,
            authority,
            source,
            binding,
            request,
            invocations,
        } = inner;
        drop(source);
        drop(authority);
        let authority = SqliteAuthorityStore::open_serving_with_clock(
            _directory.path().join("authority.sqlite3"),
            _directory.path().join("locks"),
            chio_test_support::clock::clock(),
        )?;
        let source =
            SqliteRuntimeOrchestrationStore::open(_directory.path().join("runtime.sqlite3"))?;
        Ok(Self {
            inner: Fixture {
                _directory,
                authority,
                source,
                binding,
                request,
                invocations,
            },
            origin_key,
            local_key,
        })
    }

    fn kernel(&self, hook: impl RuntimeAdmissionHook + 'static) -> TestResult<ChioKernel> {
        let trust = KernelTrustExchange::new("kernel.vendor-b", self.local_key.clone())
            .with_trusted_peer("kernel.buyer", self.origin_key.public_key());
        let envelope = PeerHandshakeEnvelope::sign(
            "kernel.buyer",
            "kernel.vendor-b",
            "combined-runtime-handshake",
            NOW / 1000,
            &self.origin_key,
        )?;
        let peer = trust.accept_envelope(&envelope, "kernel.buyer", NOW / 1000)?;
        let mut kernel = self
            .inner
            .kernel_with_key(hook, true, false, self.local_key.clone())?
            .with_federation_peers(vec![peer]);
        kernel.require_swarm_admission();
        let receipts =
            SqliteReceiptStore::open(self.inner._directory.path().join("receipts.sqlite3"))?;
        receipts.flush_receipt_writes()?;
        kernel.set_receipt_store(Box::new(receipts))?;
        kernel.set_federation_cosigner(Arc::new(InProcessCoSigner::new(
            "kernel.buyer",
            self.origin_key.clone(),
            self.local_key.public_key(),
        )));
        Ok(kernel)
    }

    fn history(
        &self,
        reference: &RuntimeParticipantClaimReferenceV1,
    ) -> TestResult<(AdmissionOperationV1, Vec<RuntimeParticipantClaimHistoryV1>)> {
        self.inner
            .authority
            .admission_operation_store()
            .load_runtime_participant_history(
                reference.operation_id(),
                &self.inner.authority.mutation_fence(),
                NOW,
            )?
            .ok_or_else(|| "combined physical runtime history".into())
    }
}

#[test]
fn combined_owned_dispatch_retains_all_three_resources_and_replays_without_reacquisition(
) -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let fixture = CombinedFixture::new()?;
    let kernel = fixture.kernel(fixture.hook()?)?;
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(response.verdict, Verdict::Allow, "{response:#?}");
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    assert!(response.receipt.verify_integrity_embedded_key()?);
    assert!(kernel
        .federation_dsse_envelope(&response.receipt.id)
        .is_some());
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or("combined receipt metadata")?;
    let reference: RuntimeParticipantClaimReferenceV1 = serde_json::from_value(
        metadata["chio_runtime"]["operation_owned_replay"]["reference"].clone(),
    )?;
    let (operation, history) = fixture.history(&reference)?;
    assert!(operation.dispatch_commit().is_some());
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].reference, reference);
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::RetainedAfterDispatchCommit
    );
    let kinds = history[0]
        .intent
        .resources()
        .iter()
        .map(|resource| resource.kind())
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            RuntimeParticipantKind::DestructiveLease,
            RuntimeParticipantKind::TreatyContinuation,
            RuntimeParticipantKind::SwarmContinuation,
        ]
    );
    let repeated = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(repeated.verdict, Verdict::Allow, "{repeated:#?}");
    assert_eq!(
        chio_core_types::canonical::canonical_json_bytes(&repeated.receipt)?,
        chio_core_types::canonical::canonical_json_bytes(&response.receipt)?,
    );
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.history(&reference)?,
        (operation.clone(), history.clone())
    );
    let old_fence = fixture.inner.authority.mutation_fence();
    drop(kernel);
    let fixture = fixture.reopen()?;
    assert!(fixture
        .inner
        .authority
        .admission_operation_store()
        .load_runtime_participant_history(reference.operation_id(), &old_fence, NOW)
        .is_err());
    let kernel = fixture.kernel(fixture.hook()?)?;
    let restarted = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(restarted.verdict, Verdict::Allow, "{restarted:#?}");
    assert_eq!(
        chio_core_types::canonical::canonical_json_bytes(&restarted.receipt)?,
        chio_core_types::canonical::canonical_json_bytes(&response.receipt)?
    );
    assert_eq!(fixture.history(&reference)?, (operation, history));
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn combined_owned_denial_panic_and_source_loss_release_every_resource() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    for fault in [
        faults::Fault::Deny,
        faults::Fault::Panic,
        faults::Fault::SourcePathMoved,
    ] {
        let fixture = CombinedFixture::new()?;
        let moves_source = matches!(fault, faults::Fault::SourcePathMoved);
        let kernel = fixture.kernel(faults::FaultHook::new(
            fixture.hook()?,
            fixture.inner._directory.path().join("runtime.sqlite3"),
            fault,
        ))?;
        let response = kernel.evaluate_tool_call_blocking_with_metadata(
            &fixture.inner.request,
            Some(swarm_route_metadata()),
        )?;
        assert_eq!(response.verdict, Verdict::Deny, "{response:#?}");
        assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 0);
        assert!(response.receipt.verify_integrity_embedded_key()?);
        let history = faults::history(&fixture.inner)?;
        assert_eq!(history.len(), 1, "failure must follow actual acquisition");
        assert_eq!(history[0].intent.resources().len(), 3);
        assert_eq!(
            history[0].disposition,
            RuntimeParticipantDisposition::ReleasedBeforeDispatch
        );
        let (operation, _) = fixture.history(&history[0].reference)?;
        assert!(operation.dispatch_commit().is_none());
        assert_eq!(
            operation.state(),
            chio_kernel::admission_operation::AdmissionOperationState::CompensatedBeforeDispatch
        );
        if moves_source {
            assert!(!fixture
                .inner
                ._directory
                .path()
                .join("runtime.sqlite3")
                .exists());
            assert!(fixture
                .inner
                ._directory
                .path()
                .join("runtime.moved")
                .is_file());
        }
        assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
    }
    Ok(())
}
