//! Live composed admission with signed treaty/swarm evidence and physical
//! replay custody. Fixture signatures are genuine; no verifier is bypassed.

use super::*;
use chio_federation::bilateral::InProcessCoSigner;
use chio_federation::trust_establishment::{KernelTrustExchange, PeerHandshakeEnvelope};
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantClaimHistoryV1, RuntimeParticipantClaimReferenceV1,
};
use chio_kernel::admission_operation::{AdmissionOperationV1, RuntimeReplayParticipantKind};
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
        Self::with_retired_resource(None)
    }

    fn with_retired_resource(retired: Option<RuntimeReplayParticipantKind>) -> TestResult<Self> {
        Self::with_treaty_input(retired, |_, _, _| Ok(()))
    }

    fn with_treaty_input(
        retired: Option<RuntimeReplayParticipantKind>,
        prepare: impl FnOnce(&mut TreatyRuntimeFixture, &Keypair, &Keypair) -> TestResult,
    ) -> TestResult<Self> {
        let origin_key = Keypair::generate();
        let local_key = Keypair::generate();
        let mut treaty = treaty_runtime_fixture_with_signers(
            allow_policy_evaluation_summary(),
            origin_key.clone(),
            local_key.clone(),
        )?;
        prepare(&mut treaty, &origin_key, &local_key)?;
        let swarm = runtime_swarm_bundle(false)?;
        let inner = Fixture::with_request(true, |source| {
            let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
            let mut admission = bundle();
            admission.binding.tool_args_sha256 = tool_args_sha256(&args)?;
            let hash = runtime_admission_bundle_sha256(&admission)?;
            source.insert_bundle(admission)?;
            insert_treaty_runtime_fixture(source, &treaty)?;
            source.insert_swarm_authority_bundle(swarm.clone())?;
            // Imported markers model an earlier legacy consumer. They must
            // exclude the entire new live claim, not only the colliding member.
            match retired {
                Some(RuntimeReplayParticipantKind::DestructiveLease) => {
                    source.consume_destructive_lease("lease-live-1", "earlier-legacy-admission")?
                }
                Some(RuntimeReplayParticipantKind::TreatyContinuation) => source
                    .consume_treaty_continuation(
                        "continue-runtime-1",
                        "earlier-legacy-admission",
                    )?,
                Some(RuntimeReplayParticipantKind::SwarmContinuation) => source
                    .consume_swarm_continuation(
                        "continuation-child-a",
                        "earlier-legacy-admission",
                    )?,
                None => {}
            }
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
        let authority = SqliteAuthorityStore::open_serving(
            _directory.path().join("authority.sqlite3"),
            _directory.path().join("locks"),
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
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    let fixture = CombinedFixture::new()?;
    let kernel = fixture.kernel(fixture.hook()?)?;
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(response.verdict, Verdict::Allow, "{response:#?}");
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    assert!(response.receipt.verify_signature()?);
    assert!(kernel.dual_signed_receipt(&response.receipt.id).is_some());
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
            RuntimeReplayParticipantKind::DestructiveLease,
            RuntimeReplayParticipantKind::TreatyContinuation,
            RuntimeReplayParticipantKind::SwarmContinuation,
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
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    for fault in [
        faults::Fault::Deny,
        faults::Fault::Panic,
        faults::Fault::SourceBarrier,
    ] {
        let fixture = CombinedFixture::new()?;
        let removes_barrier = matches!(fault, faults::Fault::SourceBarrier);
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
        assert!(response.receipt.verify_signature()?);
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
        if removes_barrier {
            let raw = rusqlite::Connection::open(
                fixture.inner._directory.path().join("runtime.sqlite3"),
            )?;
            let count: i64 = raw.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'trigger' AND name = 'runtime_replay_source_lease_no_insert'",
                [], |row| row.get(0),
            )?;
            assert_eq!(count, 0, "fault fixture must remove the barrier");
        }
        assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
    }
    Ok(())
}

#[test]
fn combined_owned_imported_collision_in_any_resource_rejects_without_partial_custody() -> TestResult
{
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    for kind in [
        RuntimeReplayParticipantKind::DestructiveLease,
        RuntimeReplayParticipantKind::TreatyContinuation,
        RuntimeReplayParticipantKind::SwarmContinuation,
    ] {
        let fixture = CombinedFixture::with_retired_resource(Some(kind))?;
        let kernel = fixture.kernel(fixture.hook()?)?;
        let response = kernel.evaluate_tool_call_blocking_with_metadata(
            &fixture.inner.request,
            Some(swarm_route_metadata()),
        )?;
        assert_eq!(response.verdict, Verdict::Deny, "{kind:?}: {response:#?}");
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains(
                    "runtime participant resource is already reserved or historically spent"
                )),
            "collision must reach the physical replay conflict: {response:#?}"
        );
        assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 0);
        assert!(faults::history(&fixture.inner)?.is_empty());
        let store = fixture.inner.authority.admission_operation_store();
        let migration = store
            .load_runtime_replay_migration(
                fixture.inner.binding.runtime_authority_id(),
                &fixture.inner.authority.mutation_fence(),
                NOW,
            )?
            .ok_or("retired source migration")?;
        assert!(migration.is_active());
        assert_eq!(migration.snapshot().markers().len(), 1);
        assert_eq!(migration.snapshot().markers()[0].kind(), kind);
        let raw =
            rusqlite::Connection::open(fixture.inner._directory.path().join("authority.sqlite3"))?;
        for table in [
            "runtime_replay_claim_episodes",
            "runtime_replay_claim_resources",
            "runtime_replay_claim_releases",
        ] {
            let count: i64 =
                raw.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
            assert_eq!(count, 0, "{kind:?}: partial {table}");
        }
    }
    Ok(())
}
