use super::*;
use crate::swarm_evolution;
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantClaimHistoryV1, RuntimeParticipantClaimReferenceV1,
};

fn history(
    fixture: &Fixture,
    reference: &RuntimeParticipantClaimReferenceV1,
) -> TestResult<Vec<RuntimeParticipantClaimHistoryV1>> {
    Ok(fixture
        .authority
        .admission_operation_store()
        .load_runtime_participant_history(
            reference.operation_id(),
            &fixture.authority.mutation_fence(),
            NOW,
        )?
        .ok_or("original operation history")?
        .1)
}

fn request(
    store: &SqliteRuntimeOrchestrationStore,
    swarm: &SwarmAuthorityBundle,
    task: &str,
    suffix: &str,
) -> TestResult<ToolCallRequest> {
    // The existing fixture selects the first referenced artifacts. Reorder only
    // these lookup lists; the signed graph and each signed artifact stay intact.
    let mut refs = swarm.clone();
    refs.continuation_tokens
        .sort_by_key(|t| t.child_task_id != task);
    refs.route_plan_receipts.sort_by_key(|r| r.task_id != task);
    refs.witness_chains.sort_by_key(|w| w.child_task_id != task);
    let mut request = chio_swarm_runtime_request(
        serde_json::json!({"record": task, "value": "closed"}),
        String::new(),
        swarm_runtime_context(&refs)?,
    )?;
    request.request_id = format!("request-{task}-{suffix}");
    request.capability = swarm_evolution::capability(task)?;
    request.agent_id = request.capability.subject.to_hex();
    let mut admission = bundle();
    admission.admission_id = format!("admission-{task}-{suffix}");
    admission.destructive = false;
    admission.lease_id = None;
    admission.governance_receipt_id = None;
    admission.binding = RuntimeRequestBinding::from_tool_call_request(&request, "kernel.vendor-b")?;
    request
        .governed_intent
        .as_mut()
        .and_then(|i| i.context.as_mut())
        .ok_or("context")?["chioAdmission"] = serde_json::json!({"admissionId": admission.admission_id, "bundleSha256": runtime_admission_bundle_sha256(&admission)?});
    store.insert_bundle(admission)?;
    Ok(request)
}

fn route(swarm: &SwarmAuthorityBundle, task: &str) -> TestResult<serde_json::Value> {
    let r = swarm
        .route_plan_receipts
        .iter()
        .find(|r| r.task_id == task)
        .ok_or("route")?;
    Ok(
        serde_json::json!({"route": {"bridge": r.bridge_id, "protocolTarget": r.protocol_target, "selectedRoute": r.selected_route}}),
    )
}

fn kernel(fixture: &Fixture, key: &Keypair) -> TestResult<ChioKernel> {
    let hook = fixture
        .hook()?
        .with_swarm_witness_keys(trusted_swarm_witness_keys());
    let mut kernel = fixture.kernel_with_key(hook, true, false, key.clone())?;
    kernel.require_swarm_admission();
    kernel.configure_durable_admission(
        chio_kernel::admission_operation::DurableAdmissionMode::All,
        false,
    )?;
    kernel.set_revocation_store(Box::new(fixture.authority.revocation_store()));
    let receipts = chio_store_sqlite::SqliteReceiptStore::open(
        fixture._directory.path().join("receipts.sqlite3"),
    )?;
    receipts.wait_for_writer_ready(std::time::Duration::from_secs(30))?;
    kernel.set_receipt_store(Box::new(receipts))?;
    kernel.reconcile_durable_admission_startup()?;
    Ok(kernel)
}

#[test]
fn native_swarm_evolution_runs_added_work_and_preserves_original_replay() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let (prior, next) = swarm_evolution::versions()?;
    let fixture = Fixture::with_request(true, |store| {
        store.insert_swarm_authority_bundle(prior.clone())?;
        request(store, &prior, "task-child-a", "original")
    })?;
    let key = Keypair::generate();
    let live = kernel(&fixture, &key)?;
    let first = live.evaluate_tool_call_blocking_with_metadata(
        &fixture.request,
        Some(route(&prior, "task-child-a")?),
    )?;
    assert_eq!(first.verdict, Verdict::Allow, "{first:#?}");
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let reference: RuntimeParticipantClaimReferenceV1 = serde_json::from_value(
        first.receipt.metadata.as_ref().ok_or("receipt metadata")?["chio_runtime"]
            ["operation_owned_replay"]["reference"]
            .clone(),
    )?;
    let original_history = history(&fixture, &reference)?;
    swarm_evolution::open(&fixture._directory.path().join("runtime.sqlite3"))?
        .extend_swarm_authority_bundle(
            &canonical_test_hash(&prior)?,
            next.clone(),
            &trusted_swarm_witness_keys(),
        )?;
    let added = request(&fixture.source, &next, "task-child-b", "added")?;
    let second = live
        .evaluate_tool_call_blocking_with_metadata(&added, Some(route(&next, "task-child-b")?))?;
    assert_eq!(second.verdict, Verdict::Allow, "{second:#?}");
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 2);
    drop(live);
    let fixture = fixture.reopen()?;
    let reopened = kernel(&fixture, &key)?;
    let replay = reopened.evaluate_tool_call_blocking_with_metadata(
        &fixture.request,
        Some(route(&prior, "task-child-a")?),
    )?;
    assert_eq!(
        canonical_json_bytes(&first.receipt)?,
        canonical_json_bytes(&replay.receipt)?
    );
    assert!(replay.receipt.verify_signature()?);
    assert_eq!(history(&fixture, &reference)?, original_history);
    let rebound = request(&fixture.source, &next, "task-child-a", "rebound")?;
    let denied = reopened
        .evaluate_tool_call_blocking_with_metadata(&rebound, Some(route(&next, "task-child-a")?))?;
    assert_eq!(denied.verdict, Verdict::Deny, "{denied:#?}");
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 2);
    assert_eq!(history(&fixture, &reference)?, original_history);
    Ok(())
}

#[test]
fn native_swarm_evolution_keeps_unstarted_original_work_executable() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let (prior, next) = swarm_evolution::versions()?;
    let fixture = Fixture::with_request(true, |store| {
        store.insert_swarm_authority_bundle(prior.clone())?;
        request(store, &prior, "task-child-a", "unstarted")
    })?;
    swarm_evolution::open(&fixture._directory.path().join("runtime.sqlite3"))?
        .extend_swarm_authority_bundle(
            &canonical_test_hash(&prior)?,
            next,
            &trusted_swarm_witness_keys(),
        )?;
    let fixture = fixture.reopen()?;
    let live = kernel(&fixture, &Keypair::generate())?;
    let response = live.evaluate_tool_call_blocking_with_metadata(
        &fixture.request,
        Some(route(&prior, "task-child-a")?),
    )?;
    assert_eq!(response.verdict, Verdict::Allow, "{response:#?}");
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
