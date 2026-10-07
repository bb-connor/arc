//! Private, public-synthetic host for the real CLI acceptance campaign.
use super::*;
use crate::recovery::protected_recovery_router;
use std::{path::Path, time::Duration};

async fn signal(exchange: &Path, name: &str) -> TestResult {
    tokio::time::timeout(Duration::from_secs(180), async {
        while !exchange.join(name).exists() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    Ok(())
}
async fn serve_until(
    exchange: &Path,
    service: Arc<RecoverySetupService>,
    port: u16,
    phase: &str,
    stop: &str,
) -> TestResult<u16> {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let port = listener.local_addr()?.port();
    let (shutdown, completion) = tokio::sync::oneshot::channel::<()>();
    let router = protected_recovery_router(service)?;
    let serving = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = completion.await;
            })
            .await
    });
    std::fs::write(exchange.join(phase), port.to_string())?;
    signal(exchange, stop).await?;
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(30), serving).await???;
    Ok(port)
}
async fn first_writer(exchange: &Path) -> TestResult<(RestartProof, u16)> {
    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let workflow = f.f.ready().await?;
    assert_eq!(f.f.process.process("root")?.tree_calls, 2);
    assert_eq!(external_count(&f.f.path)?, 0);
    let service = Arc::new(setup(&f, &workflow)?);
    std::fs::write(
        exchange.join("operator-key.json"),
        chio_core_types::canonical_json_bytes(&Keypair::from_seed(&[211; 32]).public_key())?,
    )?;
    std::fs::write(
        exchange.join("capability.json"),
        chio_core_types::canonical_json_bytes(&f.f.control)?,
    )?;
    std::fs::write(
        exchange.join("workflow.json"),
        chio_core_types::canonical_json_bytes(&workflow)?,
    )?;
    let port = serve_until(exchange, service.clone(), 20095, "first-ready", "restart").await?;
    let actor = f.actor(RecoveryPermission::Inspect)?;
    let retained =
        f.f.authority
            .admission_operation_store()
            .setup_preparation(&actor, &f.f.authority.mutation_fence(), now_ms()?)?;
    let evidence = RestartProof {
        path: f.f.path.clone(),
        directory: f.f._directory.take(),
        workflow,
        probe: retained
            .signed_probe
            .ok_or("CLI did not retain the native probe")?,
        operation: f
            .f
            .record(service.workflow())?
            .native_link
            .ok_or("native operation")?,
        tree_calls: f.f.process.process("root")?.tree_calls,
        effects: 1,
    };
    assert_eq!(external_count(&f.f.path)?, 1);
    Ok((evidence, port))
}
async fn second_writer(exchange: &Path, mut evidence: RestartProof, port: u16) -> TestResult {
    let f = KnowledgeFixture::from(RecoveryFixture::open(
        evidence.path.clone(),
        evidence.directory.take(),
        false,
    )?)?;
    let service = Arc::new(setup(&f, &evidence.workflow)?);
    std::fs::write(
        exchange.join("capability.json"),
        chio_core_types::canonical_json_bytes(&f.f.control)?,
    )?;
    serve_until(exchange, service.clone(), port, "second-ready", "finish").await?;
    let report = service.qualify(&f.f.control, &evidence.probe).await?;
    assert_eq!(report.body().benign_operation, evidence.operation);
    assert_eq!(external_count(&f.f.path)?, 1);
    assert_eq!(f.f.process.process("root")?.tree_calls, evidence.tree_calls);
    assert!(report.verify_signature()?);
    std::fs::write(
        exchange.join("native-evidence.json"),
        chio_core_types::canonical_json_bytes(
            &serde_json::json!({"effects":1,"tree_calls":evidence.tree_calls,"report":report}),
        )?,
    )?;
    Ok(())
}

#[tokio::test]
#[ignore = "private CLI host; execute with CHIO_RECOVERY_CLI_EXCHANGE and an actual CLI controller"]
async fn setup_cli_qualification_host() -> TestResult {
    let exchange = std::path::PathBuf::from(std::env::var("CHIO_RECOVERY_CLI_EXCHANGE")?);
    assert!(exchange.is_absolute() && exchange.is_dir());
    let (evidence, port) = Box::pin(first_writer(&exchange)).await?;
    Box::pin(second_writer(&exchange, evidence, port)).await
}
