//! Private test-only artifact bridge and actual production recovery dispatcher.
use super::*;
use crate::recovery::{RecoveryRuntimeError, RecoveryTransportRequestV1};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    routing::post,
    Router,
};
use std::{path::PathBuf, time::Duration};

async fn command(
    State(fixture): State<Arc<fixture::CaseFixture>>,
    bytes: Bytes,
) -> axum::response::Response {
    let current = tokio::runtime::Handle::current();
    let result = tokio::task::spawn_blocking(move || {
        let request: RecoveryTransportRequestV1 =
            decode_contract(&bytes).map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        let capability = decode_recovery_capability(request.capability.as_str().as_bytes())
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let command: RecoveryCommandV1 = decode_contract(request.command.as_str().as_bytes())
            .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        if chio_core_types::canonical_json_bytes(&command).ok()
            != chio_core_types::canonical_json_bytes(&fixture.command).ok()
        {
            return Err(RecoveryRuntimeError::InvalidCommand);
        }
        current.block_on(Box::pin(fixture.execute_with(&capability, &command)))
    })
    .await
    .unwrap_or(Err(RecoveryRuntimeError::Unavailable));
    super::super::super::super::transport::response(result)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    workflow: String,
    case: String,
}

#[tokio::test]
#[ignore = "actual live campaign helper, one fresh private native fixture per declared trial"]
async fn live_comparative_native_host() -> TestResult {
    let exchange = PathBuf::from(std::env::var("CHIO_RECOVERY_CAMPAIGN_EXCHANGE")?);
    assert!(exchange.is_absolute() && exchange.is_dir());
    let config: Configuration =
        serde_json::from_slice(&std::fs::read(exchange.join("configuration.json"))?)?;
    let fixture = Arc::new(prepare_case(&config.workflow, &config.case).await?);
    for (name, bytes) in [
        (
            "capability.json",
            chio_core_types::canonical_json_bytes(&fixture.f.f.control)?,
        ),
        (
            "command.json",
            chio_core_types::canonical_json_bytes(&fixture.command)?,
        ),
        (
            "authority-contract.json",
            chio_core_types::canonical_json_bytes(&fixture.authority_contract)?,
        ),
        (
            "native-before.json",
            chio_core_types::canonical_json_bytes(&fixture.facts()?)?,
        ),
    ] {
        std::fs::write(exchange.join(name), bytes)?;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    // Support calls use the ordinary native runtime. Artifact calls extend
    // Inspect in this private qualification fixture with a real mediated read;
    // this is not a production artifact HTTP protocol or an enabled new tool.
    let router = Router::new()
        .route("/v1/recovery/commands", post(command))
        .layer(DefaultBodyLimit::max(MAX_RECOVERY_WIRE_BYTES))
        .with_state(fixture.clone());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
    });
    super::super::host::publish_ready(&exchange, address)?;
    let started = std::time::Instant::now();
    while !exchange.join("finish").is_file() && started.elapsed() < Duration::from_secs(240) {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(120), serving).await???;
    std::fs::write(
        exchange.join("native-evidence.json"),
        chio_core_types::canonical_json_bytes(&fixture.facts()?)?,
    )?;
    Ok(())
}
