//! Invalid callers cannot allocate native work; overflow is a permanent refusal.
use super::*;
use crate::recovery::transport::admission_test_support::call_with_occupied_native_capacity;
use axum::{body::to_bytes, http::StatusCode};

fn inspect_only_capability(f: &RecoveryFixture) -> TestResult<CapabilityToken> {
    Ok(f.kernel.issue_capability(
        &f.approval_key.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "chio.recovery".into(),
                tool_name: "inspect".into(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..Default::default()
        },
        1200,
    )?)
}

#[tokio::test]
async fn malformed_recovery_requests_refuse_before_native_capacity() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    for route in [
        "/v1/recovery/commands",
        "/v1/recovery/review",
        "/v1/recovery/settle",
    ] {
        let response = call_with_occupied_native_capacity(
            f.runtime.clone(),
            route,
            b"{\"protected-canary\":".to_vec(),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{route}");
        assert_eq!(
            to_bytes(response.into_body(), 262144).await?.as_ref(),
            b"recovery.invalid_command"
        );
    }
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn settlement_requires_exact_permission_before_reserved_native_capacity() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let capability = inspect_only_capability(&f)?;
    // This is a valid signed capability for the currently assigned principal.
    // Only its exact route permission differs from an authorized settlement.
    f.kernel.authenticate_recovery_actor(
        f.runtime.scope(),
        &capability,
        RecoveryPermission::Inspect,
    )?;
    let bytes = chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&capability)?.as_str(),
        "workflow_id": WorkflowId::new("unobserved-canary")?,
    }))?;
    let response =
        call_with_occupied_native_capacity(f.runtime.clone(), "/v1/recovery/settle", bytes).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        to_bytes(response.into_body(), 262144).await?.as_ref(),
        b"recovery.authority_denied"
    );
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn recovery_controls_authenticate_before_native_capacity() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let workflow = WorkflowId::new("unobserved-canary")?;
    let capability = inspect_only_capability(&f)?;
    let command = f.command(
        "unauthorized-resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: SafeInteger::new(0)?,
        },
    )?;
    let command_bytes = chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&capability)?.as_str(),
        "command": text::<32768, _>(&command)?.as_str(),
    }))?;
    let response = call_with_occupied_native_capacity(
        f.runtime.clone(),
        "/v1/recovery/commands",
        command_bytes,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let review_bytes = chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&f.seed.capability)?.as_str(),
        "workflow_id": workflow,
    }))?;
    let response =
        call_with_occupied_native_capacity(f.runtime.clone(), "/v1/recovery/review", review_bytes)
            .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn exact_scope_invalid_signatures_refuse_before_native_capacity() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let workflow = WorkflowId::new("unobserved-canary")?;
    let mut forged = f.control.clone();
    forged.signature = f.seed.capability.signature.clone();
    // Each requested permission is present in the token. Only the real
    // cryptographic verifier can reject its replaced signature.
    for permission in [
        RecoveryPermission::Inspect,
        RecoveryPermission::Approve,
        RecoveryPermission::Settle,
    ] {
        f.kernel
            .authenticate_recovery_actor(f.runtime.scope(), &f.control, permission)?;
        assert!(f
            .kernel
            .authenticate_recovery_actor(f.runtime.scope(), &forged, permission)
            .is_err());
    }
    let command = f.command(
        "invalid-signature-inspect",
        RecoveryCommandBodyV1::InspectWorkflow {
            workflow_id: workflow.clone(),
        },
    )?;
    let command_bytes = chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&forged)?.as_str(),
        "command": text::<32768, _>(&command)?.as_str(),
    }))?;
    let review_bytes = chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&forged)?.as_str(),
        "workflow_id": workflow,
    }))?;
    for (route, bytes) in [
        ("/v1/recovery/commands", command_bytes),
        ("/v1/recovery/review", review_bytes.clone()),
        ("/v1/recovery/settle", review_bytes),
    ] {
        let response = call_with_occupied_native_capacity(f.runtime.clone(), route, bytes).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{route}");
        assert_eq!(
            to_bytes(response.into_body(), 262144).await?.as_ref(),
            b"recovery.authority_denied"
        );
    }
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}

async fn forged_recovery_token_with_authentication_backlog(
    route: &str,
    permission: RecoveryPermission,
) -> TestResult {
    use crate::recovery::transport::authentication_backlog_test_support::call_with_native_authentication_backlog;

    let f = RecoveryFixture::new(false)?;
    let workflow = WorkflowId::new("unobserved-canary")?;
    let mut forged = f.control.clone();
    forged.signature = f.seed.capability.signature.clone();
    f.kernel
        .authenticate_recovery_actor(f.runtime.scope(), &f.control, permission)?;
    assert!(f
        .kernel
        .authenticate_recovery_actor(f.runtime.scope(), &forged, permission)
        .is_err());
    let command = f.command(
        "forged-inspect-under-auth-backlog",
        RecoveryCommandBodyV1::InspectWorkflow {
            workflow_id: workflow.clone(),
        },
    )?;
    let command_bytes = chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&forged)?.as_str(),
        "command": text::<32768, _>(&command)?.as_str(),
    }))?;
    let review_bytes = chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&forged)?.as_str(),
        "workflow_id": workflow,
    }))?;
    let bytes = if route == "/v1/recovery/commands" {
        command_bytes
    } else {
        review_bytes
    };
    let response = Box::pin(call_with_native_authentication_backlog(
        f.runtime.clone(),
        &f.control,
        f.authority.admission_operation_store(),
        route,
        bytes,
    ))
    .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "{route}");
    assert_eq!(
        to_bytes(response.into_body(), 262144).await?.as_ref(),
        b"recovery.authority_denied"
    );
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn forged_commands_refuse_before_native_authentication_backlog() -> TestResult {
    Box::pin(forged_recovery_token_with_authentication_backlog(
        "/v1/recovery/commands",
        RecoveryPermission::Inspect,
    ))
    .await
}

#[tokio::test]
async fn forged_reviews_refuse_before_native_authentication_backlog() -> TestResult {
    Box::pin(forged_recovery_token_with_authentication_backlog(
        "/v1/recovery/review",
        RecoveryPermission::Approve,
    ))
    .await
}

#[tokio::test]
async fn forged_settlements_refuse_before_native_authentication_backlog() -> TestResult {
    Box::pin(forged_recovery_token_with_authentication_backlog(
        "/v1/recovery/settle",
        RecoveryPermission::Settle,
    ))
    .await
}

#[tokio::test]
async fn forged_explanation_tokens_refuse_before_native_authentication_backlog() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let service = crate::recovery::RecoveryExplanationService::new(
        f.runtime.scope().clone(),
        AuthorityDomainId::new("advisory-trust")?,
        IssuerId::new("advisory-issuer")?,
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[31; 32]))),
        ExplanationLimitsV1 {
            offers: SafeInteger::new(16)?,
            work: SafeInteger::new(4096)?,
        },
    )?;
    let mut forged = f.control.clone();
    forged.signature = f.seed.capability.signature.clone();
    f.kernel.authenticate_recovery_actor(
        f.runtime.scope(),
        &f.control,
        RecoveryPermission::Inspect,
    )?;
    assert!(f
        .kernel
        .authenticate_recovery_actor(f.runtime.scope(), &forged, RecoveryPermission::Inspect)
        .is_err());
    let bytes = chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&forged)?.as_str(),
        "workflow_id": WorkflowId::new("unobserved-canary")?,
    }))?;
    let response = Box::pin(
        crate::recovery::RecoveryExplanationService::call_with_native_authentication_backlog(
            f.runtime.clone(),
            Arc::new(service),
            &f.control,
            f.authority.admission_operation_store(),
            bytes,
        ),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        to_bytes(response.into_body(), 262144).await?.as_ref(),
        b"recovery.authority_denied"
    );
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn successful_projection_at_http_ceiling_remains_deliverable() -> TestResult {
    // Canonical JSON adds two quotation bytes to this ASCII string.
    let response = crate::recovery::transport::response(Ok("x".repeat(262142)));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(to_bytes(response.into_body(), 262144).await?.len(), 262144);
    Ok(())
}

#[tokio::test]
async fn oversized_successful_projection_has_permanent_public_refusal() -> TestResult {
    // One byte above the public response ceiling must never advertise retry.
    let response = crate::recovery::transport::response(Ok("x".repeat(262143)));
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        to_bytes(response.into_body(), 262144).await?.as_ref(),
        b"recovery.projection_too_large"
    );
    let response = crate::recovery::transport::response(Ok("protected-canary".repeat(20000)));
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        to_bytes(response.into_body(), 262144).await?.as_ref(),
        b"recovery.projection_too_large"
    );
    Ok(())
}

async fn same_router_settlement_flood(invalid_signature: bool) -> TestResult {
    use std::sync::atomic::AtomicBool;
    let f = RecoveryFixture::new(false)?;
    let workflow = Box::pin(f.ready()).await?;
    let command = f.command(
        "captured-before-flood",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: f.record(&workflow)?.revision,
        },
    )?;
    Box::pin(f.runtime.execute_command(&f.control, &command)).await?;
    assert_eq!(external_count(&f.path)?, 1);
    let charge = f.process.process("root")?.tree_calls;
    let router = crate::recovery::recovery_router(f.runtime.clone())?;
    let incapable = if invalid_signature {
        let mut forged = f.control.clone();
        forged.signature = f.seed.capability.signature.clone();
        assert!(f
            .kernel
            .authenticate_recovery_actor(f.runtime.scope(), &forged, RecoveryPermission::Settle)
            .is_err());
        forged
    } else {
        inspect_only_capability(&f)?
    };
    let refused_wire = chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&incapable)?.as_str(),
        "workflow_id": workflow,
    }))?;
    let authorized_wire = review_wire(&f, &workflow)?;
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(AtomicUsize::new(0));
    let mut attackers = Vec::new();
    for index in 0..8 {
        let router = router.clone();
        let stop = stop.clone();
        let requests = requests.clone();
        let wire = if index % 2 == 0 {
            refused_wire.clone()
        } else {
            b"{\"protected-canary\":".to_vec()
        };
        attackers.push(tokio::spawn(async move {
            let mut completed = 0;
            while !stop.load(Ordering::SeqCst) {
                let request = Request::builder()
                    .method("POST")
                    .uri("/v1/recovery/settle")
                    .body(Body::from(wire.clone()))?;
                let _response = router.clone().oneshot(request).await?;
                requests.fetch_add(1, Ordering::SeqCst);
                completed += 1;
                tokio::task::yield_now().await;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(completed)
        }));
    }
    let started = tokio::time::timeout(Duration::from_secs(2), async {
        while requests.load(Ordering::SeqCst) < 8 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let settled = if started.is_ok() {
        tokio::time::timeout(
            Duration::from_secs(2),
            router.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/recovery/settle")
                    .body(Body::from(authorized_wire))?,
            ),
        )
        .await
    } else {
        stop.store(true, Ordering::SeqCst);
        for attacker in attackers {
            let _ = attacker.await;
        }
        return Err("same-router malformed/unauthorized flood did not start".into());
    };
    // Stop and join the flood tasks before assertions or timeout propagation.
    stop.store(true, Ordering::SeqCst);
    for attacker in attackers {
        attacker
            .await?
            .map_err(|e| format!("settlement flood: {e}"))?;
    }
    let response =
        settled.map_err(|_| "authorized same-router settlement exceeded two-second deadline")??;
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value = serde_json::from_slice(&to_bytes(response.into_body(), 262144).await?)?;
    assert_eq!(result["effect"]["kind"], "complete");
    assert_eq!(external_count(&f.path)?, 1);
    assert_eq!(f.process.process("root")?.tree_calls, charge);
    Ok(())
}

#[test]
fn malformed_and_unauthorized_same_router_flood_preserves_native_settlement() -> TestResult {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    let result = runtime.block_on(Box::pin(same_router_settlement_flood(false)));
    runtime.shutdown_timeout(Duration::from_secs(5));
    result
}

#[test]
fn exact_scope_forged_same_router_flood_preserves_native_settlement() -> TestResult {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    let result = runtime.block_on(Box::pin(same_router_settlement_flood(true)));
    runtime.shutdown_timeout(Duration::from_secs(5));
    result
}

async fn explanation_authentication_with_busy_native_executor() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let service = crate::recovery::RecoveryExplanationService::new(
        f.runtime.scope().clone(),
        AuthorityDomainId::new("advisory-trust")?,
        IssuerId::new("advisory-issuer")?,
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[31; 32]))),
        ExplanationLimitsV1 {
            offers: SafeInteger::new(16)?,
            work: SafeInteger::new(4096)?,
        },
    )?;
    let router = crate::recovery::recovery_explanation_router(f.runtime.clone(), Arc::new(service));
    // The scope names Inspect, but the native cryptographic verifier must reject
    // this token. No test replaces the verifier or its current assignment check.
    let mut forged = f.control.clone();
    forged.signature = f.seed.capability.signature.clone();
    assert!(f
        .kernel
        .authenticate_recovery_actor(f.runtime.scope(), &forged, RecoveryPermission::Inspect)
        .is_err());
    let bytes = chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&forged)?.as_str(),
        "workflow_id": WorkflowId::new("unobserved-canary")?,
    }))?;
    let (started, observations) = std::sync::mpsc::channel();
    let mut releases = Vec::new();
    let mut blockers = Vec::new();
    for _ in 0..2 {
        let (release, wait) = std::sync::mpsc::channel();
        let started = started.clone();
        releases.push(release);
        blockers.push(tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            let _ = wait.recv();
        }));
    }
    observations.recv_timeout(Duration::from_secs(2))?;
    observations.recv_timeout(Duration::from_secs(2))?;
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        router.oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/recovery/explain")
                .body(Body::from(bytes))?,
        ),
    )
    .await;
    for release in releases {
        release.send(())?;
    }
    for blocker in blockers {
        blocker.await?;
    }
    let response = response
        .map_err(|_| "explanation authentication queued behind native executor capacity")??;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        to_bytes(response.into_body(), 262144).await?.as_ref(),
        b"recovery.authority_denied"
    );
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}

#[test]
fn explanation_authentication_does_not_wait_for_native_worker_capacity() -> TestResult {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .enable_all()
        .build()?;
    let result = runtime.block_on(Box::pin(
        explanation_authentication_with_busy_native_executor(),
    ));
    runtime.shutdown_timeout(Duration::from_secs(5));
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_native_work_keeps_existing_capacity_for_another_principal() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let other_key = Keypair::from_seed(&[93; 32]);
    let mut profile = f.kernel.recovery_deployment(f.runtime.scope())?;
    let mut actors = profile.actors.as_slice().to_vec();
    let mut other = actors[0].clone();
    other.subject = other_key.public_key();
    other.principal = PrincipalId::new("other-reviewer")?;
    other.permissions = BoundedList::new(vec![RecoveryPermission::Approve])?;
    actors.push(other);
    profile.actors = NonEmptyBoundedList::new(actors)?;
    profile.authority_scope = recovery_authority_scope_digest(&profile)?;
    f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&profile)?;
    let other_capability = f.kernel.issue_capability(
        &other_key.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "chio.recovery".into(),
                tool_name: "approve".into(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..Default::default()
        },
        1200,
    )?;
    let workflow = Box::pin(f.ready()).await?;
    let router = crate::recovery::recovery_router(f.runtime.clone())?;
    f.behavior.store(2, Ordering::SeqCst);
    let resume = f.command(
        "owned-native-work",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: f.record(&workflow)?.revision,
        },
    )?;
    let request = Request::builder()
        .method("POST")
        .uri("/v1/recovery/commands")
        .body(Body::from(wire(&f, &resume)?))?;
    let caller_router = router.clone();
    let caller = tokio::spawn(async move { caller_router.oneshot(request).await });
    let started = tokio::time::timeout(Duration::from_secs(30), f.started.notified()).await;
    if started.is_err() {
        f.release.notify_one();
        let _ = caller.await;
        return Err("authenticated native effect did not reach the provider".into());
    }
    let own_request = Request::builder()
        .method("POST")
        .uri("/v1/recovery/review")
        .body(Body::from(review_wire(&f, &workflow)?))?;
    let own_response =
        tokio::time::timeout(Duration::from_secs(2), router.clone().oneshot(own_request)).await;
    let other_wire = chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&other_capability)?.as_str(), "workflow_id": workflow,
    }))?;
    let other_request = Request::builder()
        .method("POST")
        .uri("/v1/recovery/review")
        .body(Body::from(other_wire))?;
    let other_response =
        tokio::time::timeout(Duration::from_secs(2), router.oneshot(other_request)).await;
    f.release.notify_one();
    let completed = tokio::time::timeout(Duration::from_secs(30), caller).await???;
    assert_eq!(completed.status(), StatusCode::OK);
    let own_response =
        own_response.map_err(|_| "same-principal review admission did not refuse promptly")??;
    assert_eq!(own_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let other_response = other_response
        .map_err(|_| "another authorized principal lost reserved existing-work capacity")??;
    assert_eq!(other_response.status(), StatusCode::OK);
    assert_eq!(external_count(&f.path)?, 1);
    Ok(())
}
