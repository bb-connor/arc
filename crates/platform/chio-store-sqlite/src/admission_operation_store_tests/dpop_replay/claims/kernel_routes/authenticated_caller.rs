use super::*;
use crate::caller_execution_ledger::SqliteCallerExecutionLedger;
use chio_kernel::{CallerExecutionReport, CallerStartCredentials, CallerStartResponse};

#[test]
fn authenticated_caller_start_retains_physical_dpop_and_reports_after_proof_expiry(
) -> AnchoredTestResult {
    let mut route = Route::new()?;
    let key = Keypair::generate();
    let executor = chio_kernel::caller_delivery::CallerExecutorIdentityV1 {
        executor_id: identifier("executor_id", "dpop-executor"),
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
    let request = route.request("authenticated-dpop-caller", &[1])?;
    let reserved = route.kernel.reserve_caller_execution_blocking(&request)?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    let nonce = reserved.execution_nonce.ok_or("nonce")?;
    let (before, history_before) = route.history(&request)?;
    assert_eq!(before.state(), AdmissionOperationState::ReadyToDispatch);
    assert!(!matches!(
        route
            .kernel
            .start_caller_execution_blocking(&nonce, &request.arguments),
        Ok(CallerStartResponse::Authorized(_))
    ));
    let mut invalid_proof = request.dpop_proof.clone().ok_or("proof")?;
    invalid_proof.body.nonce.push_str("-substituted");
    assert!(!matches!(
        route
            .kernel
            .start_caller_execution_with_credentials_blocking(
                &nonce,
                &request.arguments,
                CallerStartCredentials {
                    dpop_proof: Some(invalid_proof),
                    ..Default::default()
                },
            ),
        Ok(CallerStartResponse::Authorized(_))
    ));
    assert_eq!(
        route.history(&request)?,
        (before, history_before.clone()),
        "invalid presentation cannot alter the original dispatch claims"
    );
    let authorization = match route
        .kernel
        .start_caller_execution_with_credentials_blocking(
            &nonce,
            &request.arguments,
            CallerStartCredentials {
                dpop_proof: request.dpop_proof.clone(),
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
        history_before.len(),
        "start cannot acquire another episode"
    );
    assert!(history
        .iter()
        .any(|claim| claim.disposition == DpopReplayClaimDisposition::RetainedAfterDispatchCommit));
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
    let mut reopened = kernel(&route.fixture, route.signer.clone())?;
    reopened.set_caller_executor(executor)?;
    reopened.set_operation_owned_dpop_authority(route.domain.clone())?;
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
    Ok(())
}
