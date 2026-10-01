//! Real process loss at committed SQLite boundaries. These cuts do not model
//! arbitrary power failure or authenticated external caller execution.

use super::*;
use chio_core_types::StoreMutationFence;
use chio_kernel::admission_operation::AdmissionOperationState;
use chio_kernel::BudgetStore;
use std::path::{Path, PathBuf};

#[path = "crash/harness.rs"]
mod harness;
#[path = "crash/worker.rs"]
mod worker;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cut {
    ClaimBeforeDispatch,
    DispatchEntered,
    EffectBeforeReturn,
}

impl Cut {
    fn label(self) -> &'static str {
        match self {
            Self::ClaimBeforeDispatch => "claim-before-dispatch",
            Self::DispatchEntered => "dispatch-entered",
            Self::EffectBeforeReturn => "effect-before-return",
        }
    }

    fn committed(self) -> bool {
        self != Self::ClaimBeforeDispatch
    }

    fn effects(self) -> (i64, i64, bool) {
        match self {
            Self::ClaimBeforeDispatch => (0, 0, false),
            Self::DispatchEntered => (1, 0, false),
            Self::EffectBeforeReturn => (1, 1, true),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PhysicalSnapshot {
    operation: AdmissionOperationV1,
    resources: Vec<(String, String, String)>,
    episodes: i64,
    releases: i64,
    budget_invocation: String,
}

fn physical_snapshot(path: &Path) -> TestResult<PhysicalSnapshot> {
    let raw = rusqlite::Connection::open_with_flags(
        path.join("authority.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let bytes: Vec<u8> = raw.query_row(
        "SELECT operation_json FROM admission_operations",
        [],
        |row| row.get(0),
    )?;
    let operation = AdmissionOperationV1::from_persisted(serde_json::from_slice(&bytes)?)?;
    let budget_invocation = raw.query_row(
        "SELECT invocation_state FROM budget_authorization_holds
         WHERE operation_id = ?1 AND hold_id = ?2",
        rusqlite::params![
            operation.binding().operation_id().as_str(),
            operation
                .budget_hold_id()
                .ok_or("parked operation budget hold")?
                .as_str(),
        ],
        |row| row.get(0),
    )?;
    let resources = raw
        .prepare(
            "SELECT participant_kind, resource_id, artifact_digest
                  FROM runtime_replay_claim_resources ORDER BY participant_kind",
        )?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let (episodes, releases) = raw.query_row(
        "SELECT (SELECT count(*) FROM runtime_replay_claim_episodes),
                (SELECT count(*) FROM runtime_replay_claim_releases)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(PhysicalSnapshot {
        operation,
        resources,
        episodes,
        releases,
        budget_invocation,
    })
}

fn run_cut(cut: Cut, test: &str) -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    if let Some(path) = harness::child_directory(cut)? {
        return worker::run(&path, cut);
    }
    let (directory, state) = harness::RestartState::prepare()?;
    let path = directory.path();
    let mut child = harness::CrashChild::spawn(path, cut, test)?;
    let old_fence = child.wait_until_parked(path)?;
    // Independently corroborate the child's signal using physical committed
    // rows while the worker is alive. A marker alone is not phase evidence.
    let before = physical_snapshot(path)?;
    assert_eq!(before.episodes, 1);
    assert_eq!(before.releases, 0);
    assert_eq!(
        before
            .resources
            .iter()
            .map(|(kind, _, _)| kind.as_str())
            .collect::<Vec<_>>(),
        [
            "destructive_lease",
            "swarm_continuation",
            "treaty_continuation"
        ]
    );
    assert_eq!(
        before.operation.dispatch_commit().is_some(),
        cut.committed()
    );
    assert!(!before.operation.state().is_terminal());
    assert_eq!(
        before.budget_invocation,
        if cut.committed() {
            "captured"
        } else {
            "authorized"
        }
    );
    assert_eq!(worker::effects(path)?, cut.effects());
    child.kill_and_reap()?;
    assert_eq!(
        physical_snapshot(path)?,
        before,
        "process loss must not run Drop compensation"
    );
    assert_eq!(worker::effects(path)?, cut.effects());

    let fixture = state.open(path)?;
    let store = fixture.inner.authority.admission_operation_store();
    let operation_id = before.operation.binding().operation_id();
    assert!(store
        .load_runtime_participant_history(operation_id, &old_fence, NOW)
        .is_err());
    let (retained, history) = store
        .load_runtime_participant_history(
            operation_id,
            &fixture.inner.authority.mutation_fence(),
            NOW,
        )?
        .ok_or("crashed operation history")?;
    assert_eq!(retained, before.operation);
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].intent.resources().len(), 3);
    let reference = history[0].reference.clone();
    let mut kernel = fixture.kernel(fixture.hook()?)?;
    kernel.register_tool_server(Box::new(worker::DurableEffectTool {
        path: path.to_owned(),
        entered: fixture.inner.invocations.clone(),
        cut: None,
    }));
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 1);
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
    let (recovered, after) = fixture.history(&reference)?;
    let physical = physical_snapshot(path)?;
    assert_eq!(physical.operation, recovered);
    assert_eq!(physical.resources, before.resources);
    assert_eq!(physical.episodes, 1);
    assert_eq!(physical.releases, i64::from(!cut.committed()));
    assert_eq!(
        physical.budget_invocation,
        if cut.committed() {
            "captured"
        } else {
            "reversed"
        }
    );
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].intent, history[0].intent);
    assert_eq!(after[0].reference, reference);
    let usage = fixture
        .inner
        .authority
        .budget_store()
        .get_usage(&fixture.inner.request.capability.id, 0)?
        .map_or(0, |usage| usage.invocation_count);
    assert_eq!(usage, u32::from(cut.committed()));
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(worker::effects(path)?, cut.effects());
    if cut.committed() {
        assert_eq!(
            recovered.state(),
            AdmissionOperationState::OutcomeUnknownAfterDispatch
        );
        assert_eq!(after, history);
        assert_eq!(
            after[0].disposition,
            RuntimeParticipantDisposition::RetainedAfterDispatchCommit
        );
    } else {
        assert_eq!(
            recovered.state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        assert_eq!(
            after[0].disposition,
            RuntimeParticipantDisposition::ReleasedBeforeDispatch
        );
    }
    let retry = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    );
    assert!(
        !retry
            .as_ref()
            .is_ok_and(|response| response.verdict == Verdict::Allow),
        "recovery cannot give the old operation a fresh Allow: {retry:#?}"
    );
    assert_eq!(worker::effects(path)?, cut.effects());
    assert_eq!(
        fixture.history(&reference)?,
        (recovered.clone(), after.clone())
    );
    let fresh = fixture.competing_request("after-process-loss")?;
    let response =
        kernel.evaluate_tool_call_blocking_with_metadata(&fresh, Some(swarm_route_metadata()))?;
    assert!(response.receipt.verify_signature()?);
    if cut.committed() {
        assert_eq!(response.verdict, Verdict::Deny, "{response:#?}");
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains(
                    "runtime participant resource is already reserved or historically spent"
                )),
            "fresh operation must hit retained physical custody: {response:#?}"
        );
        assert_eq!(worker::effects(path)?, cut.effects());
        assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 0);
    } else {
        assert_eq!(
            response.verdict,
            Verdict::Allow,
            "released custody must be reusable: {response:#?}"
        );
        assert_eq!(worker::effects(path)?, (1, 1, true));
        assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .ok_or("fresh receipt metadata")?;
        let fresh_reference: RuntimeParticipantClaimReferenceV1 = serde_json::from_value(
            metadata["chio_runtime"]["operation_owned_replay"]["reference"].clone(),
        )?;
        assert_ne!(fresh_reference.operation_id(), reference.operation_id());
        let (_, fresh_history) = fixture.history(&fresh_reference)?;
        assert_eq!(fresh_history.len(), 1);
        let fresh_resources = fresh_history[0].intent.resources();
        let old_resources = history[0].intent.resources();
        assert_eq!(fresh_resources.len(), old_resources.len());
        for (fresh, old) in fresh_resources.iter().zip(old_resources) {
            assert_eq!(fresh.kind(), old.kind());
            assert_eq!(fresh.resource_id(), old.resource_id());
            // The destructive bundle binds the new request/admission identity;
            // the treaty and swarm artifacts themselves have not changed.
            if fresh.kind() == RuntimeReplayParticipantKind::DestructiveLease {
                assert_ne!(fresh.artifact_digest(), old.artifact_digest());
            } else {
                assert_eq!(fresh.artifact_digest(), old.artifact_digest());
            }
        }
        assert_eq!(
            fresh_history[0].disposition,
            RuntimeParticipantDisposition::RetainedAfterDispatchCommit
        );
    }
    assert_eq!(fixture.history(&reference)?, (recovered, after));
    Ok(())
}

#[test]
fn combined_owned_process_loss_before_dispatch_releases_custody() -> TestResult {
    run_cut(
        Cut::ClaimBeforeDispatch,
        "combined_owned_process_loss_before_dispatch_releases_custody",
    )
}

#[test]
fn combined_owned_process_loss_at_dispatch_retains_custody() -> TestResult {
    run_cut(
        Cut::DispatchEntered,
        "combined_owned_process_loss_at_dispatch_retains_custody",
    )
}

#[test]
fn combined_owned_process_loss_after_effect_does_not_redispatch() -> TestResult {
    run_cut(
        Cut::EffectBeforeReturn,
        "combined_owned_process_loss_after_effect_does_not_redispatch",
    )
}
