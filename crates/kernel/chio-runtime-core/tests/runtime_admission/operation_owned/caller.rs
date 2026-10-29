//! Runtime custody retention across authenticated caller start and return.

use super::*;
use chio_kernel::admission_operation::AdmissionOperationStore;
use chio_kernel::caller_delivery::{
    CallerDeliveryReportBodyV1, CallerExecutorIdentityV1, SignedCallerDeliveryReportV1,
    CALLER_DELIVERY_REPORT_SCHEMA,
};
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};

#[path = "caller/authenticated.rs"]
mod authenticated;

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
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let fixture = Fixture::new(true)?;
    let signer = Keypair::generate();
    let executor_key = Keypair::generate();
    let executor = CallerExecutorIdentityV1 {
        executor_id: AdmissionIdentifier::try_new("executor_id", "runtime-custody-executor")?,
        public_key: executor_key.public_key(),
        key_epoch: 1,
    };
    let mut kernel = fixture.kernel_with_key(fixture.hook()?, true, false, signer.clone())?;
    nonce_config(&mut kernel);
    kernel.set_caller_executor(executor.clone())?;
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
    let authorization =
        match kernel.start_caller_execution_blocking(&nonce, &fixture.request.arguments)? {
            chio_kernel::CallerStartResponse::Authorized(authorization) => *authorization,
            chio_kernel::CallerStartResponse::Denied(response) => {
                return Err(format!("caller start denied: {:?}", response.reason).into());
            }
        };
    let report = SignedCallerDeliveryReportV1::sign(
        CallerDeliveryReportBodyV1 {
            schema: CALLER_DELIVERY_REPORT_SCHEMA.into(),
            authorization_digest: authorization.verify_historical(
                &signer.public_key(),
                &executor,
                &authorization.authorization.invocation,
            )?,
            executor: executor.clone(),
            claim_id: AdmissionIdentifier::try_new("claim_id", "runtime-custody-claim")?,
            execution_started_at_unix_ms: NOW,
            completed_at_unix_ms: NOW,
            output: serde_json::json!({"closed": true}),
            realized_cost: None,
        },
        &executor_key,
    )?;
    let completed =
        kernel.reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
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
    let released = history
        .iter()
        .find(|entry| entry.disposition == RuntimeParticipantDisposition::ReleasedBeforeDispatch)
        .ok_or("released preflight claim")?;
    let retained = history
        .iter()
        .find(|entry| {
            entry.disposition == RuntimeParticipantDisposition::RetainedAfterDispatchCommit
        })
        .ok_or("retained dispatch claim")?;
    assert_ne!(released.reference, retained.reference);
    let frame = store
        .load_caller_dispatch_context(operation.binding().operation_id(), &fence, NOW)?
        .ok_or("caller frame")?;
    let payload: serde_json::Value = serde_json::from_slice(frame.kernel_context_json())?;
    assert_eq!(payload["schema"], "chio.kernel-caller-return-context.v1");
    let selected = &payload["participant_custody"]["runtime"];
    assert_eq!(
        selected["episode_id"],
        serde_json::to_value(retained.reference.episode_id())?
    );
    assert_eq!(
        selected["claim_digest"],
        serde_json::to_value(retained.reference.claim_digest())?
    );
    let expected_intent = sha256_hex(&canonical_json_bytes(&(
        "chio.caller-claim-intent.v1",
        "runtime",
        &retained.intent,
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
    let authority = SqliteAuthorityStore::open_serving_with_clock(
        _directory.path().join("authority.sqlite3"),
        _directory.path().join("locks"),
        chio_test_support::clock::clock(),
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
    kernel.set_caller_executor(executor.clone())?;
    let replay =
        kernel.reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
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
