//! Private native listener for actual framework qualification.
use super::*;
use crate::recovery::{protected_recovery_router, RecoverySetupService};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

pub(super) fn publish_ready(exchange: &Path, address: std::net::SocketAddr) -> std::io::Result<()> {
    use std::io::Write;

    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "native readiness requires a bound loopback address",
        ));
    }
    let pending = exchange.join("ready.pending");
    let ready = exchange.join("ready");
    if ready.try_exists()? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "native readiness is already published",
        ));
    }
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    writeln!(output, "http://{address}")?;
    output.sync_all()?;
    drop(output);
    std::fs::rename(pending, ready)?;
    #[cfg(unix)]
    std::fs::File::open(exchange)?.sync_all()?;
    Ok(())
}

struct Reopen {
    path: PathBuf,
    directory: Option<tempfile::TempDir>,
    workflow: WorkflowId,
    probe: SignedRecoverySetupProbeV1,
}
fn service(f: &KnowledgeFixture, workflow: &WorkflowId) -> TestResult<RecoverySetupService> {
    Ok(RecoverySetupService::new(
        f.f.runtime.clone(),
        Arc::new(f.f.authority.admission_operation_store()),
        f.f.authority.mutation_fence(),
        Some(Arc::new(f.runtime.clone())),
        Keypair::from_seed(&[211; 32]),
        workflow.clone(),
    )?)
}
async fn initial() -> TestResult<Reopen> {
    let mut f = KnowledgeFixture::from(super::super::semantic::native_fixture("read")?)?;
    let workflow = f.f.ready().await?;
    let setup = service(&f, &workflow)?;
    let probe = setup.probe(&f.f.control, &workflow).await?;
    Ok(Reopen {
        path: f.f.path.clone(),
        directory: f.f._directory.take(),
        workflow,
        probe,
    })
}
async fn writer(exchange: &Path, mut previous: Reopen) -> TestResult {
    let f = KnowledgeFixture::from(RecoveryFixture::open(
        previous.path,
        previous.directory.take(),
        false,
    )?)?;
    let setup = Arc::new(service(&f, &previous.workflow)?);
    let report = setup.qualify(&f.f.control, &previous.probe).await?;
    let workflow = f.f.ready_named("host-target", "host-target").await?;
    let command = f.f.command(
        "host-native-original",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: f.f.record(&workflow)?.revision,
        },
    )?;
    // Native commands and credentials are exchanged outside model/checkpoint state.
    std::fs::write(
        exchange.join("capability.json"),
        chio_core_types::canonical_json_bytes(&f.f.control)?,
    )?;
    std::fs::write(
        exchange.join("command.json"),
        chio_core_types::canonical_json_bytes(&command)?,
    )?;
    std::fs::write(
        exchange.join("profile.json"),
        chio_core_types::canonical_json_bytes(&serde_json::json!({
            "scope":f.f.runtime.scope(),"setup_report":report,"workflow":workflow,
        }))?,
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:20096").await?;
    let address = listener.local_addr()?;
    let router = protected_recovery_router(setup)?;
    let (shutdown, completed) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = completed.await;
            })
            .await
    });
    publish_ready(exchange, address)?;
    let start = std::time::Instant::now();
    let mut revoked = false;
    while !exchange.join("finish").exists() && start.elapsed() < Duration::from_secs(180) {
        if exchange.join("revoke").exists() && !revoked {
            f.f.kernel.revoke_capability(&f.f.control.id)?;
            revoked = true;
            std::fs::write(exchange.join("revoked"), b"native-revocation-committed")?;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(30), serving).await???;
    assert!(revoked, "controller must test native revoked replay");
    assert_eq!(external_count(&f.f.path)?, 2);
    let database = rusqlite::Connection::open(f.f.path.join("effects.db"))?;
    let attempts: i64 =
        database.query_row("SELECT count(DISTINCT attempt) FROM effects", [], |row| {
            row.get(0)
        })?;
    assert_eq!(attempts, 2);
    std::fs::write(
        exchange.join("native-evidence.json"),
        chio_core_types::canonical_json_bytes(&serde_json::json!({
            "effects":2,"setup_effects":1,"workload_effects":1,"distinct_attempts":attempts,
            "tree_calls":f.f.process.process("root")?.tree_calls,"revoked":revoked,
        }))?,
    )?;
    Ok(())
}
#[tokio::test]
#[ignore = "private native framework host; execute with actual pinned StateGraph and Crew controller"]
async fn native_framework_qualification_host() -> TestResult {
    let exchange = PathBuf::from(std::env::var("CHIO_RECOVERY_HOST_EXCHANGE")?);
    assert!(exchange.is_absolute() && exchange.is_dir());
    let previous = Box::pin(initial()).await?;
    Box::pin(writer(&exchange, previous)).await
}

#[tokio::test]
async fn setup_new_work_native_capture_after_real_qualified_restart() -> TestResult {
    let mut previous = Box::pin(initial()).await?;
    Box::pin(async move {
        let f = KnowledgeFixture::from(RecoveryFixture::open(
            previous.path,
            previous.directory.take(),
            false,
        )?)?;
        let setup = service(&f, &previous.workflow)?;
        setup.qualify(&f.f.control, &previous.probe).await?;
        let workflow =
            f.f.ready_named("fresh-qualified-work", "fresh-work")
                .await?;
        let command = f.f.command(
            "fresh-native-work",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: f.f.record(&workflow)?.revision,
            },
        )?;
        let result = f.f.runtime.execute_command(&f.f.control, &command).await?;
        assert!(
            matches!(result.status.effect, EffectObservationV1::Complete { .. }),
            "fresh native effect: {:?}; independent effects: {}",
            result.status.effect,
            external_count(&f.f.path)?
        );
        let original = result.original_response.ok_or("fresh original result")?;
        assert!(original.receipt.verify_signature()?);
        assert!(matches!(
            original.receipt.decision,
            Some(chio_core_types::receipt::decision::Decision::Allow)
        ));
        let charge = f.f.process.process("root")?.tree_calls;
        let replay = f.f.runtime.execute_command(&f.f.control, &command).await?;
        assert_eq!(
            chio_core_types::canonical_json_bytes(&original.receipt)?,
            chio_core_types::canonical_json_bytes(
                &replay.original_response.ok_or("replayed result")?.receipt
            )?
        );
        assert_eq!(f.f.process.process("root")?.tree_calls, charge);
        assert_eq!(external_count(&f.f.path)?, 2);
        Ok(())
    })
    .await
}
