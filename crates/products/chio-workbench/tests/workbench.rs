#![cfg(unix)]

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chio_workbench::{
    provider::{Provider, Turn},
    Error, Result, Run, RunStatus, Workbench,
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
use tower::ServiceExt;

mod support;
use support::{calls, config, done, repair_script, Scripted};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_preserves_unknown_effects_without_replaying_them() -> Result<()> {
    let root = tempfile::tempdir()?;
    let workbench = Workbench::open(config(root.path())?, repair_script())?;
    let id = workbench.start("Repair addition".into(), 36)?;
    let mut run = finished(&workbench, &id).await?;
    assert_eq!(run.status, RunStatus::Succeeded, "{:#?}", run);
    workbench.shutdown().await;
    drop(workbench);
    run.status = RunStatus::Running;
    run.tasks[2].status = chio_workbench::TaskStatus::Running;
    run.tasks[2].actions[1].state = "running".into();
    let connection = rusqlite::Connection::open(root.path().join("state/runs.sqlite"))?;
    connection.execute(
        "UPDATE workbench_runs SET body=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&run)?, id],
    )?;
    drop(connection);
    let empty = Arc::new(Scripted(Mutex::new(VecDeque::new())));
    let reopened = Workbench::open(config(root.path())?, empty)?;
    let recovered = reopened.get(&id)?;
    assert_eq!(recovered.status, RunStatus::Interrupted);
    assert_eq!(recovered.tasks[2].actions[1].state, "unknown");
    assert!(std::fs::read_to_string(reopened.workspace().join("calc.py"))?.contains("a + b"));
    assert!(Workbench::open(config(root.path())?, repair_script()).is_err());
    reopened.shutdown().await;
    Ok(())
}
async fn finished(workbench: &Workbench, id: &str) -> Result<Run> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let run = workbench.get(id)?;
            if !matches!(run.status, RunStatus::Running | RunStatus::Stopping) {
                return Ok(run);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| Error::Invalid("test task timed out".into()))?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repairs_a_real_file_and_runs_checks_through_signed_delegation() -> Result<()> {
    let root = tempfile::tempdir()?;
    let workbench = Workbench::open(config(root.path())?, repair_script())?;
    let id = workbench.start("Fix add and verify the result".into(), 36)?;
    let run = finished(&workbench, &id).await?;
    assert_eq!(run.status, RunStatus::Succeeded, "{:#?}", run);
    assert!(
        std::fs::read_to_string(workbench.workspace().join("calc.py"))?.contains("return a + b")
    );
    assert_eq!(
        run.tasks[0].actions[1]
            .output
            .as_ref()
            .map(|output| output["passed"].clone()),
        Some(json!(false))
    );
    assert_eq!(
        run.tasks[2].actions[1]
            .output
            .as_ref()
            .map(|output| output["passed"].clone()),
        Some(json!(true))
    );
    assert_eq!(
        run.tasks.iter().map(|task| task.call_limit).sum::<u32>(),
        run.call_limit
    );
    let states: Vec<_> = run
        .tasks
        .iter()
        .flat_map(|task| task.actions.iter().map(|action| action.state.as_str()))
        .collect();
    assert_eq!(
        states,
        [
            "succeeded",
            "failed",
            "succeeded",
            "succeeded",
            "succeeded",
            "succeeded",
            "succeeded"
        ]
    );
    for task in &run.tasks {
        assert_eq!(
            task.capability.delegation_chain[0].capability_id,
            run.root_capability.id
        );
        assert!(task
            .capability
            .scope
            .is_subset_of(&run.root_capability.scope));
        assert!(task
            .capability
            .verify_signature()
            .map_err(|error| Error::Invalid(error.to_string()))?);
        for action in &task.actions {
            if action.tool == "read_file" {
                assert!(action.output.as_ref().is_some_and(|output| output["text"]
                    .as_str()
                    .is_some_and(|text| text.contains("def add(a, b):"))));
            }
            let receipt = action
                .receipt
                .as_ref()
                .ok_or_else(|| Error::Invalid(format!("missing receipt: {:?}", action)))?;
            assert!(receipt
                .verify_signature()
                .map_err(|error| Error::Invalid(error.to_string()))?);
            assert_eq!(receipt.capability_id, task.capability.id);
        }
    }
    workbench.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn investigator_cannot_edit_even_when_the_model_requests_it() -> Result<()> {
    let root = tempfile::tempdir()?;
    let provider = Arc::new(Scripted(Mutex::new(VecDeque::from([
        calls(&[(
            "replace_text",
            json!({"path":"calc.py","old_text":"a - b","new_text":"a + b"}),
        )]),
        done(),
        done(),
        done(),
    ]))));
    let workbench = Workbench::open(config(root.path())?, provider)?;
    let id = workbench.start("Attempt an unauthorized edit".into(), 12)?;
    let run = finished(&workbench, &id).await?;
    assert_eq!(run.tasks[0].actions[0].state, "denied");
    assert!(run.tasks[0].actions[0].receipt.is_some());
    assert!(std::fs::read_to_string(workbench.workspace().join("calc.py"))?.contains("a - b"));
    assert_eq!(run.status, RunStatus::Failed);
    workbench.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn role_allowance_stops_dispatch_before_the_next_effect() -> Result<()> {
    let root = tempfile::tempdir()?;
    let provider = Arc::new(Scripted(Mutex::new(VecDeque::from([calls(&[
        ("list_files", json!({})),
        ("read_file", json!({"path":"calc.py"})),
    ])]))));
    let workbench = Workbench::open(config(root.path())?, provider)?;
    let id = workbench.start("Exhaust allowance".into(), 6)?;
    let run = finished(&workbench, &id).await?;
    assert_eq!(run.status, RunStatus::Failed);
    assert_eq!(run.tasks[0].actions.len(), 1);
    assert_eq!(
        run.tasks[0].actions[0].output,
        Some(json!({"path":".","entries":["calc.py"]}))
    );
    assert!(run
        .error
        .as_deref()
        .is_some_and(|error| error.contains("allowance")));
    workbench.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_model_batches_cannot_partially_edit_the_workspace() -> Result<()> {
    for duplicate_id in [true, false] {
        let root = tempfile::tempdir()?;
        let mut batch = calls(&[
            (
                "replace_text",
                json!({"path":"calc.py","old_text":"a - b","new_text":"a + b"}),
            ),
            ("read_file", json!({"path":"calc.py"})),
        ]);
        if duplicate_id {
            batch.content[1]["id"] = batch.content[0]["id"].clone();
        } else {
            batch.content[1]["input"] = json!(null);
        }
        let provider = Arc::new(Scripted(Mutex::new(VecDeque::from([done(), batch]))));
        let workbench = Workbench::open(config(root.path())?, provider)?;
        let id = workbench.start("Reject an invalid edit batch".into(), 12)?;
        let run = finished(&workbench, &id).await?;
        assert_eq!(run.status, RunStatus::Failed);
        assert!(run.tasks[1].actions.is_empty());
        assert!(std::fs::read_to_string(workbench.workspace().join("calc.py"))?.contains("a - b"));
        workbench.shutdown().await;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_checks_terminates_the_process_group_and_records_the_outcome() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut settings = config(root.path())?;
    settings.check_command = vec![
        "python3".into(),
        "-I".into(),
        "-c".into(),
        "import subprocess,sys,pathlib; child=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(120)']); pathlib.Path('child.pid').write_text(str(child.pid)); child.wait()".into(),
    ];
    let provider = Arc::new(Scripted(Mutex::new(VecDeque::from([calls(&[(
        "run_checks",
        json!({}),
    )])]))));
    let workbench = Workbench::open(settings, provider)?;
    let id = workbench.start("Run a slow check".into(), 12)?;
    let pid_file = workbench.workspace().join("child.pid");
    tokio::time::timeout(Duration::from_secs(5), async {
        while !pid_file.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| Error::Invalid("check did not start".into()))?;
    let pid: u32 = std::fs::read_to_string(pid_file)?
        .parse()
        .map_err(|_| Error::Invalid("invalid child pid".into()))?;
    workbench.stop(&id)?;
    let run = finished(&workbench, &id).await?;
    assert_eq!(run.status, RunStatus::Stopped);
    assert!(run.tasks[0].actions[0].receipt.is_some());
    assert_eq!(run.tasks[0].actions[0].state, "failed");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            // A zombie is already terminated and awaiting the container's init.
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(state) if !state.contains(") Z ") => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                _ => break,
            }
        }
    })
    .await
    .map_err(|_| Error::Invalid("check descendant survived stop".into()))?;
    workbench.shutdown().await;
    Ok(())
}

struct Waiting(tokio::sync::Notify);
#[async_trait::async_trait]
impl Provider for Waiting {
    fn model(&self) -> &str {
        "waiting-test-provider"
    }
    async fn turn(&self, _system: &str, _messages: &[Value], _tools: &[Value]) -> Result<Turn> {
        self.0.notify_one();
        std::future::pending().await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_a_model_wait_revokes_work_and_releases_the_slot() -> Result<()> {
    let root = tempfile::tempdir()?;
    let provider = Arc::new(Waiting(tokio::sync::Notify::new()));
    let workbench = Workbench::open(config(root.path())?, provider.clone())?;
    let id = workbench.start("Wait for model".into(), 12)?;
    tokio::time::timeout(Duration::from_secs(5), provider.0.notified())
        .await
        .map_err(|_| Error::Invalid("provider did not start".into()))?;
    assert!(matches!(
        workbench.start("second".into(), 12),
        Err(Error::Busy)
    ));
    workbench.stop(&id)?;
    let run = finished(&workbench, &id).await?;
    assert_eq!(run.status, RunStatus::Stopped);
    assert!(run.tasks.iter().all(|task| task.actions.is_empty()));
    workbench.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_requires_operator_access_and_rejects_cross_origin_requests() -> Result<()> {
    let root = tempfile::tempdir()?;
    let workbench = Workbench::open(config(root.path())?, repair_script())?;
    let app = chio_workbench::web::router(
        workbench.clone(),
        "test-access".into(),
        "127.0.0.1:7392"
            .parse()
            .map_err(|_| Error::Invalid("address".into()))?,
    );
    for (token, host, origin, expected) in [
        (None, "127.0.0.1:7392", None, StatusCode::UNAUTHORIZED),
        (
            Some("wrong"),
            "127.0.0.1:7392",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some("test-access"),
            "evil.example",
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            Some("test-access"),
            "127.0.0.1:7392",
            Some("https://evil.example"),
            StatusCode::FORBIDDEN,
        ),
        (
            Some("test-access"),
            "127.0.0.1:7392",
            Some("http://127.0.0.1:7392"),
            StatusCode::OK,
        ),
    ] {
        let mut request = Request::builder().uri("/api/runs").header("host", host);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let response = app
            .clone()
            .oneshot(
                request
                    .body(Body::empty())
                    .map_err(|error| Error::Invalid(error.to_string()))?,
            )
            .await
            .map_err(|error| Error::Invalid(error.to_string()))?;
        assert_eq!(response.status(), expected);
    }
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/runs")
                .header("host", "127.0.0.1:7392")
                .header("origin", "https://evil.example")
                .header("authorization", "Bearer test-access")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"prompt":"do work","call_limit":12}"#))
                .map_err(|error| Error::Invalid(error.to_string()))?,
        )
        .await
        .map_err(|error| Error::Invalid(error.to_string()))?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(workbench.list()?.is_empty());
    workbench.shutdown().await;
    Ok(())
}
