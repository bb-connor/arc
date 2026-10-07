//! Real native effects and HTTP disconnects under the declared four-worker flood.
use super::*;
use axum::{body::Body, http::Request};
use std::time::Duration;
use tower::ServiceExt;

fn wire(f: &RecoveryFixture, command: &RecoveryCommandV1) -> TestResult<Vec<u8>> {
    Ok(chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&f.control)?.as_str(),
        "command": text::<32768, _>(command)?.as_str(),
    }))?)
}
fn review_wire(f: &RecoveryFixture, workflow: &WorkflowId) -> TestResult<Vec<u8>> {
    Ok(chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768, _>(&f.control)?.as_str(),
        "workflow_id": workflow,
    }))?)
}
struct ReleaseHeldEffects(Vec<Arc<tokio::sync::Notify>>);
impl Drop for ReleaseHeldEffects {
    fn drop(&mut self) {
        for release in &self.0 {
            release.notify_one();
        }
    }
}
async fn campaign() -> TestResult<(std::path::PathBuf, tempfile::TempDir, WorkflowId, u32)> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut fixtures = Vec::new();
    let mut workflows = Vec::new();
    let mut routers = Vec::new();
    let mut endpoints = Vec::new();
    let mut servers = Vec::new();
    for _ in 0..4 {
        let f = RecoveryFixture::new(false)?;
        let router = crate::recovery::recovery_router(f.runtime.clone())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        endpoints.push(format!("http://{}", listener.local_addr()?));
        let serving = router.clone();
        servers.push(tokio::spawn(
            async move { axum::serve(listener, serving).await },
        ));
        routers.push(router);
        fixtures.push(f);
    }
    let first = &fixtures[0];
    let completed_workflow = Box::pin(first.ready()).await?;
    let original = first.command(
        "completed-before-overload",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: completed_workflow.clone(),
            expected_revision: first.record(&completed_workflow)?.revision,
        },
    )?;
    Box::pin(first.runtime.execute_command(&first.control, &original)).await?;
    assert_eq!(external_count(&first.path)?, 1);
    let held_releases = ReleaseHeldEffects(fixtures.iter().map(|f| f.release.clone()).collect());
    let mut callers = Vec::new();
    for (index, f) in fixtures.iter().enumerate() {
        // Approve each scope immediately before capture. Holding earlier
        // scopes must not age another scope's short-lived approval in setup.
        workflows.push(if index == 0 {
            Box::pin(f.ready_named("held-ticket", "held")).await?
        } else {
            Box::pin(f.ready()).await?
        });
        f.behavior.store(2, Ordering::SeqCst);
        let command = f.command(
            "held-original",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflows[index].clone(),
                expected_revision: f.record(&workflows[index])?.revision,
            },
        )?;
        let client = client.clone();
        let endpoint = endpoints[index].clone();
        let bytes = wire(f, &command)?;
        callers.push(tokio::spawn(async move {
            client
                .post(format!("{endpoint}/v1/recovery/commands"))
                .body(bytes)
                .send()
                .await
        }));
        tokio::time::timeout(Duration::from_secs(30), f.started.notified())
            .await
            .map_err(|_| format!("held native capture {index} did not arrive"))?;
        assert!(f.record(&workflows[index])?.captured);
        assert_eq!(external_count(&f.path)?, if index == 0 { 2 } else { 1 });
    }
    let charge = first.process.process("root")?.tree_calls;
    for caller in callers {
        caller.abort();
        let _ = caller.await;
    }
    // The disconnected original still owns its verified-principal permit.
    // Repeated authenticated reviews cannot occupy more existing-work slots.
    let mut reviews = Vec::new();
    for _ in 0..3 {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/recovery/review")
            .body(Body::from(review_wire(&fixtures[0], &workflows[0])?))?;
        reviews.push(
            tokio::time::timeout(Duration::from_secs(2), routers[0].clone().oneshot(request)).await,
        );
    }
    let settled = tokio::time::timeout(
        Duration::from_secs(2),
        client
            .post(format!("{}/v1/recovery/settle", endpoints[0]))
            .body(review_wire(first, &completed_workflow)?)
            .send(),
    )
    .await;
    // Release accepted provider work before inspecting the settlement result.
    drop(held_releases);
    for (index, f) in fixtures.iter().enumerate() {
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if matches!(
                    f.record(&workflows[index])?.effect,
                    EffectObservationV1::Complete { .. }
                ) {
                    return TestResult::Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await??;
        assert_eq!(external_count(&f.path)?, if index == 0 { 2 } else { 1 });
    }
    for review in reviews {
        let response =
            review.map_err(|_| "authenticated review admission queued behind effects")??;
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 262144)
                .await?
                .as_ref(),
            b"recovery.unavailable"
        );
    }
    let settled =
        settled.map_err(|_| "settlement starved beyond the declared two-second deadline")??;
    assert_eq!(settled.status(), reqwest::StatusCode::OK);
    let response: Value = settled.json().await?;
    assert_eq!(response["effect"]["kind"], "complete");
    assert_eq!(external_count(&first.path)?, 2);
    assert_eq!(first.process.process("root")?.tree_calls, charge);
    for serving in servers {
        serving.abort();
        let _ = serving.await;
    }
    drop(routers);
    let mut first = fixtures.remove(0);
    Ok((
        first.path.clone(),
        first._directory.take().ok_or("owned directory")?,
        completed_workflow,
        charge,
    ))
}

#[test]
fn overload_disconnected_intake_cannot_starve_existing_native_settlement() -> TestResult {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    let result = runtime.block_on(Box::pin(campaign()));
    runtime.shutdown_timeout(Duration::from_secs(5));
    let (path, directory, workflow, charge) = result?;
    let f = RecoveryFixture::open(path, Some(directory), false)?;
    let settled = f.runtime.settle(&f.control, &workflow)?;
    assert!(matches!(
        settled.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert_eq!(external_count(&f.path)?, 2);
    assert_eq!(f.process.process("root")?.tree_calls, charge);
    Ok(())
}

#[path = "overload/transport_admission.rs"]
mod transport_admission;
