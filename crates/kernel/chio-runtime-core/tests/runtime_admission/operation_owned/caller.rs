//! Real custody retention behind the caller codec. No external effect or
//! dispatch-start authorization is inferred from this report-path regression.

use super::*;
use chio_kernel::admission_operation::AdmissionOperationStore;
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};
use chio_kernel::CallerExecutionReport;

fn nonce_config(kernel: &mut ChioKernel) {
    let config = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 64,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&config)),
    );
}

#[test]
fn caller_context_retains_exact_runtime_episode_and_released_predecessor_after_restart(
) -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    let fixture = Fixture::new(true)?;
    let signer = Keypair::generate();
    let mut kernel = fixture.kernel_with_key(fixture.hook()?, true, false, signer.clone())?;
    nonce_config(&mut kernel);
    let reserved = kernel.reserve_caller_execution_blocking(&fixture.request)?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{reserved:#?}");
    let nonce = reserved.execution_nonce.ok_or("caller nonce")?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let selector = AdmissionIdentifier::try_new("request", &fixture.request.request_id)?;
    let (reserved_operation, _) = store
        .load_unambiguous_retained_tool_request(&selector, &fence, NOW)?
        .ok_or("reserved caller operation")?;
    let before = store
        .load_runtime_participant_history(reserved_operation.binding().operation_id(), &fence, NOW)?
        .ok_or("reserved runtime history")?;
    assert_eq!(before.1.len(), 2);
    let mut retry = fixture.request.clone();
    retry.execution_nonce = Some(nonce.as_ref().clone());
    let duplicate = kernel.reserve_caller_execution_blocking(&retry)?;
    assert_eq!(duplicate.verdict, Verdict::Allow, "{duplicate:#?}");
    assert_eq!(duplicate.execution_nonce.as_deref(), Some(nonce.as_ref()));
    assert_eq!(
        store
            .load_runtime_participant_history(
                reserved_operation.binding().operation_id(),
                &fence,
                NOW
            )?
            .ok_or("runtime history after duplicate reservation")?,
        before,
        "duplicate reservation must not reacquire or replace an episode",
    );
    let completed = kernel.reconcile_caller_execution_blocking(
        &nonce,
        &fixture.request.arguments,
        CallerExecutionReport {
            output: serde_json::json!({"closed": true}),
            realized_cost: None,
        },
    )?;
    assert_eq!(completed.verdict, Verdict::Allow, "{:?}", completed.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(&selector, &fence, NOW)?
        .ok_or("retained caller operation")?;
    let (current, history) = store
        .load_runtime_participant_history(operation.binding().operation_id(), &fence, NOW)?
        .ok_or("retained runtime history")?;
    assert_eq!(current, operation);
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(
        history[1].disposition,
        RuntimeParticipantDisposition::RetainedAfterDispatchCommit
    );
    let frame = store
        .load_caller_dispatch_context(operation.binding().operation_id(), &fence, NOW)?
        .ok_or("caller frame")?;
    let payload: serde_json::Value = serde_json::from_slice(frame.kernel_context_json())?;
    assert_eq!(payload["schema"], "chio.kernel-caller-return-context.v4");
    let selected = &payload["participant_custody"]["runtime"];
    assert_eq!(
        selected["episode_id"],
        serde_json::to_value(history[1].reference.episode_id())?
    );
    assert_eq!(
        selected["claim_digest"],
        serde_json::to_value(history[1].reference.claim_digest())?
    );
    let expected_intent = sha256_hex(&canonical_json_bytes(&(
        "chio.caller-claim-intent.v1",
        "runtime",
        &history[1].intent,
    ))?);
    assert_eq!(selected["intent_digest"], expected_intent);
    let expected_episodes: Vec<_> = history.iter().map(|claim| {
        Ok(serde_json::json!({
            "episode_id": claim.reference.episode_id(),
            "claim_digest": claim.reference.claim_digest(),
            "intent_digest": sha256_hex(&canonical_json_bytes(&(
                "chio.caller-claim-intent.v1", "runtime", &claim.intent,
            ))?),
            "released": claim.disposition == RuntimeParticipantDisposition::ReleasedBeforeDispatch,
        }))
    }).collect::<TestResult<_>>()?;
    assert_eq!(
        selected["history_digest"],
        sha256_hex(&canonical_json_bytes(&(
            "chio.caller-claim-history.v1",
            "runtime",
            expected_episodes,
        ))?)
    );
    assert!(payload["participant_custody"]["approval"].is_null());
    assert!(payload["participant_custody"]["dpop"].is_null());
    let bytes = frame.canonical_bytes().to_vec();
    drop(store);
    drop(kernel);
    let Fixture {
        _directory,
        authority,
        source,
        binding,
        request,
        invocations,
    } = fixture;
    drop(authority);
    drop(source);
    let authority = SqliteAuthorityStore::open_serving(
        _directory.path().join("authority.sqlite3"),
        _directory.path().join("locks"),
    )?;
    let source = SqliteRuntimeOrchestrationStore::open(_directory.path().join("runtime.sqlite3"))?;
    let fixture = Fixture {
        _directory,
        authority,
        source,
        binding,
        request,
        invocations,
    };
    let mut kernel = fixture.kernel_with_key(fixture.hook()?, true, false, signer)?;
    nonce_config(&mut kernel);
    let replay = kernel.reconcile_caller_execution_blocking(
        &nonce,
        &fixture.request.arguments,
        CallerExecutionReport {
            output: serde_json::json!({"closed": true}),
            realized_cost: None,
        },
    )?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(
        canonical_json_bytes(&replay.receipt)?,
        canonical_json_bytes(&completed.receipt)?
    );
    let store = fixture.authority.admission_operation_store();
    assert!(store
        .load_caller_dispatch_context(operation.binding().operation_id(), &fence, NOW)
        .is_err());
    assert_eq!(
        store
            .load_caller_dispatch_context(
                operation.binding().operation_id(),
                &fixture.authority.mutation_fence(),
                NOW,
            )?
            .ok_or("restarted caller frame")?
            .canonical_bytes(),
        bytes
    );
    assert_eq!(
        store
            .load_runtime_participant_history(
                operation.binding().operation_id(),
                &fixture.authority.mutation_fence(),
                NOW,
            )?
            .ok_or("restarted custody")?
            .1,
        history
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
