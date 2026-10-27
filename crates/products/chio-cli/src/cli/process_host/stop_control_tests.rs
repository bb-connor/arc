use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

async fn exchange(control: &StopControl, request: ControlOp) -> TestResult<serde_json::Value> {
    let (server, mut client) = UnixStream::pair()?;
    let control = control.clone();
    let task = tokio::spawn(async move { handle(server, "test-token", &control).await });
    let mut bytes = serde_json::to_vec(&ControlRequest {
        token: "test-token".to_owned(),
        request,
    })?;
    bytes.push(b'\n');
    client.write_all(&bytes).await?;
    client.shutdown().await?;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await?;
    task.await??;
    Ok(serde_json::from_slice(&response)?)
}

#[tokio::test]
async fn control_socket_redacts_failed_store_appends() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let database = directory.path().join("authority.db");
    let runtime = chio_control_plane::DurableAdmissionRuntime::open(&database)?;
    let control = runtime.stop_control();
    let connection = rusqlite::Connection::open(&database)?;
    let stop = || {
        ControlOp::Stop(StopRequestBody {
            reason: "incident".to_owned(),
            allow_containment: true,
        })
    };
    let stopped = exchange(&control, stop()).await?;
    assert_eq!(stopped["ok"], true);
    let epoch = serde_json::from_value::<StopEpochId>(serde_json::json!({
        "chain_generation": stopped["status"]["head"]["chain_generation"],
        "epoch": stopped["status"]["head"]["epoch"]
    }))?;
    connection.execute_batch("CREATE TABLE stop_test_external_write (value INTEGER);")?;
    let body = exchange(
        &control,
        ControlOp::Resume(ResumeRequestBody {
            expected_epoch: epoch,
        }),
    )
    .await?;
    assert_eq!(
        body,
        serde_json::json!({"ok": false, "error": "resume_refused", "message": "Resume was refused.", "urn": "urn:chio:error:kernel:resume-refused"})
    );
    assert!(control.heads().is_stopped());
    let body = exchange(&control, stop()).await?;
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"], "stop_not_durable");
    assert_eq!(
        body["message"],
        "Stop holds in this process but could not be made durable."
    );
    assert_eq!(body["urn"], "urn:chio:error:kernel:stop-not-durable");
    assert_eq!(body["status"]["stopped"], true);
    assert_eq!(body["status"]["durability"], "process_only");
    assert!(!body.to_string().contains("authority database changed"));
    assert!(!body.to_string().contains("serving-owner"));
    Ok(())
}
