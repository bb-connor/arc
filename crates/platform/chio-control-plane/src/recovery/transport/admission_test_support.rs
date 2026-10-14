//! Deterministically occupy real native capacity without replacing security.
use super::*;
use std::sync::mpsc;
use std::time::Duration;

pub(crate) async fn call_with_occupied_native_capacity(
    runtime: Arc<RecoveryRuntime>,
    route: &str,
    bytes: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    let host = RecoveryHost::new(runtime)?;
    let _intake = host.native.total.clone().acquire_many_owned(4).await?;
    let (started, observations) = mpsc::channel();
    let mut releases = Vec::new();
    for _ in 0..2 {
        let started = started.clone();
        let (release, wait) = mpsc::channel();
        releases.push(release);
        drop(host.settlement.try_submit(Box::new(move || {
            let _ = started.send(());
            let _ = wait.recv();
            Err(RecoveryRuntimeError::Unavailable)
        }))?);
    }
    observations.recv_timeout(Duration::from_secs(2))?;
    observations.recv_timeout(Duration::from_secs(2))?;
    let response = match route {
        "/v1/recovery/commands" => command(State(host), Bytes::from(bytes)).await,
        "/v1/recovery/review" => review(State(host), Bytes::from(bytes)).await,
        "/v1/recovery/settle" => settle(State(host), Bytes::from(bytes)).await,
        _ => return Err("unsupported admission test route".into()),
    };
    for release in releases {
        release.send(())?;
    }
    Ok(response)
}
