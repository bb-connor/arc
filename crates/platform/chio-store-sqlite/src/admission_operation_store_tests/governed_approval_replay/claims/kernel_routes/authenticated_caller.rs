use super::*;
use crate::caller_execution_ledger::SqliteCallerExecutionLedger;
use chio_kernel::{CallerExecutionReport, CallerStartCredentials, CallerStartResponse};

#[test]
fn authenticated_caller_start_retains_approval_without_legacy_replay_or_reacquisition(
) -> AnchoredTestResult {
    let mut route = Route::new()?;
    let key = Keypair::generate();
    let executor = chio_kernel::caller_delivery::CallerExecutorIdentityV1 {
        executor_id: identifier("executor_id", "approval-executor"),
        public_key: key.public_key(),
        key_epoch: 7,
    };
    route.kernel.set_caller_executor(executor.clone())?;
    let config = chio_kernel::execution_nonce::ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 16,
        require_nonce: true,
    };
    route.kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&config)),
    );
    let request = route.request("authenticated-approval-caller", &[1])?;
    let reserved = route.kernel.reserve_caller_execution_blocking(&request)?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    let nonce = reserved.execution_nonce.ok_or("nonce")?;
    let (_, before) = route.history(&request)?;
    let authorization = match route
        .kernel
        .start_caller_execution_with_credentials_blocking(
            &nonce,
            &request.arguments,
            CallerStartCredentials {
                approval_token: request.approval_token.clone(),
                ..Default::default()
            },
        )? {
        CallerStartResponse::Authorized(authorization) => *authorization,
        CallerStartResponse::Denied(response) => {
            return Err(format!("{:?}", response.reason).into())
        }
    };
    let (committed, history) = route.history(&request)?;
    assert_eq!(
        committed.state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(
        history.len(),
        before.len(),
        "start cannot acquire another approval episode"
    );
    assert!(history.iter().any(|claim| claim.disposition == chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalClaimDisposition::RetainedAfterDispatchCommit));
    let ledger = SqliteCallerExecutionLedger::provision(
        &route.fixture._temp.path().join("executor.db"),
        executor.clone(),
        4,
    )?;
    let report = ledger.execute_once(
        &authorization,
        &route.signer.public_key(),
        &authorization.authorization.invocation,
        &key,
        || {
            Ok(CallerExecutionReport {
                output: serde_json::json!({"external": true}),
                realized_cost: None,
            })
        },
    )?;
    let mut reopened = kernel_recovery::kernel_with_signer(&route.fixture, route.signer.clone())?;
    reopened.set_caller_executor(executor)?;
    reopened.set_operation_owned_governed_approval_source(
        route.binding.clone(),
        route.source.clone(),
    )?;
    reopened.set_execution_nonce_store(
        config.clone(),
        Box::new(chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&config)),
    );
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(request.capability.expires_at + 1, []);
    reopened.reconcile_durable_admission_startup()?;
    let completed =
        reopened.reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(completed.verdict, Verdict::Allow, "{:?}", completed.reason);
    assert_eq!(route.calls.load(Ordering::SeqCst), 0);
    assert_eq!(route.legacy.load(Ordering::SeqCst), 0);
    Ok(())
}
