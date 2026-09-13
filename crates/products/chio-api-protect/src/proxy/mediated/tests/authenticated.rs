//! Public router acceptance: reservation, controlled start, durable executor,
//! signed delivery and exact duplicate receipt. No test-only routing bypass.
use super::*;
use chio_kernel::admission_operation::AdmissionIdentifier;
use chio_kernel::caller_delivery::{CallerExecutorIdentityV1, SignedCallerDispatchAuthorizationV1};
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_caller_routes_require_commit_and_authenticated_durable_delivery(
) -> Result<(), Box<dyn std::error::Error>> {
    let signer = Keypair::generate();
    let agent = Keypair::generate();
    let executor_key = Keypair::generate();
    let executor = CallerExecutorIdentityV1 {
        executor_id: AdmissionIdentifier::try_new("executor_id", "sidecar-test-executor")?,
        public_key: executor_key.public_key(),
        key_epoch: 42,
    };
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let kernel = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let cap = issue_invocation_capability(&kernel, &agent, "caller-server", "effect", 1);
    let state = mediated_test_state_with_durable_admission(
        signer.clone(),
        budget,
        Vec::new(),
        Some(MEDIATED_CONTROL_TOKEN.into()),
        None,
        true,
        None,
        None,
        Some(durable),
    );
    state
        .mediation_kernel
        .as_ref()
        .ok_or("kernel")?
        .lock()
        .await
        .set_caller_executor(executor.clone())?;
    let parameters = serde_json::json!({"operation": "external"});
    let (status, reserved) = post_evaluate(
        Arc::clone(&state),
        &serde_json::json!({
            "capability": cap, "tool_server": "caller-server", "tool_name": "effect",
            "parameters": parameters, "request_id": "sidecar-caller-start",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reserved}");
    assert_eq!(reserved["status"], "reserved");
    assert_eq!(reserved["execution_authorized"], false);
    assert_eq!(reserved["start_required"], true);
    let start_body = serde_json::json!({
        "protocol": "chio.caller-delivery.v1", "execution_nonce": reserved["execution_nonce"],
        "arguments": parameters,
    });
    let (unauthorized, _) = post_json(Arc::clone(&state), "/v1/caller/start", &start_body).await;
    assert_eq!(unauthorized, StatusCode::FORBIDDEN);
    let (status, started) = post_json_with_bearer(
        Arc::clone(&state),
        "/v1/caller/start",
        &start_body,
        Some(MEDIATED_CONTROL_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{started}");
    assert_eq!(started["status"], "dispatch_committed");
    let authorization: SignedCallerDispatchAuthorizationV1 =
        serde_json::from_value(started["authorization"].clone())?;
    let (_, retry) = post_json_with_bearer(
        Arc::clone(&state),
        "/v1/caller/start",
        &start_body,
        Some(MEDIATED_CONTROL_TOKEN),
    )
    .await;
    assert_eq!(started, retry);
    let ledger =
        SqliteCallerExecutionLedger::provision(&directory.path().join("executor.db"), executor, 4)?;
    let effects = AtomicUsize::new(0);
    let report = ledger.execute_once(
        &authorization,
        &signer.public_key(),
        &authorization.authorization.invocation,
        &executor_key,
        || {
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(CallerExecutionReport {
                output: serde_json::json!({"returned": true}),
                realized_cost: None,
            })
        },
    )?;
    let body = serde_json::json!({"protocol": "chio.caller-delivery.v1", "authorization": authorization, "report": report});
    let (unauthorized, _) = post_json(Arc::clone(&state), "/v1/caller/report", &body).await;
    assert_eq!(unauthorized, StatusCode::FORBIDDEN);
    let mut invalid = body.clone();
    invalid["report"]["report"]["output"] = serde_json::json!({"substituted": true});
    let (rejected, _) = post_json_with_bearer(
        Arc::clone(&state),
        "/v1/caller/report",
        &invalid,
        Some(MEDIATED_CONTROL_TOKEN),
    )
    .await;
    assert_eq!(rejected, StatusCode::CONFLICT);
    let (status, completed) = post_json_with_bearer(
        Arc::clone(&state),
        "/v1/caller/report",
        &body,
        Some(MEDIATED_CONTROL_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{completed}");
    assert_eq!(completed["status"], "reconciled", "{completed}");
    assert_eq!(completed["execution_authorized"], false);
    let (status, replay) = post_json_with_bearer(
        Arc::clone(&state),
        "/v1/caller/report",
        &body,
        Some(MEDIATED_CONTROL_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(completed, replay);
    let (legacy_status, _) = post_reconcile(
        Arc::clone(&state),
        &serde_json::json!({
            "execution_nonce": reserved["execution_nonce"], "arguments": parameters,
            "realized_cost": {"units": 0, "currency": "USD"},
        }),
    )
    .await;
    assert_eq!(legacy_status, StatusCode::BAD_REQUEST);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    Ok(())
}
