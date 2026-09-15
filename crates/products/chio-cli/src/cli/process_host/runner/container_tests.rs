use super::*;
use std::os::unix::fs::PermissionsExt;

struct EngineDouble {
    root: tempfile::TempDir,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl EngineDouble {
    fn new(scenario: serde_json::Value) -> Result<Self, Box<dyn std::error::Error>> {
        let guard = ENGINE_FIXTURE
            .lock()
            .map_err(|_| "engine fixture lock poisoned")?;
        let root = tempfile::tempdir()?;
        let executable = root.path().join("docker.py");
        std::fs::write(
            &executable,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/process_host/engine_double.py"
            )),
        )?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))?;
        *ENGINE_COMMAND
            .lock()
            .map_err(|_| "engine test lock poisoned")? = Some(executable);
        let engine = Self {
            root,
            _guard: guard,
        };
        engine.scenario(scenario)?;
        Ok(engine)
    }

    fn scenario(&self, scenario: serde_json::Value) -> std::io::Result<()> {
        std::fs::write(
            self.root.path().join("scenario.json"),
            serde_json::to_vec(&scenario)?,
        )
    }

    fn host(&self) -> Result<(std::path::PathBuf, std::path::PathBuf), Box<dyn std::error::Error>> {
        let policy = self.root.path().join("policy.yaml");
        std::fs::write(&policy, "kernel:\n  max_capability_ttl: 3600\n  durable_admission_mode: all\ncapabilities:\n  default:\n    tools:\n      - server: chio-ipc\n        tool: '*'\n        operations: [invoke, delegate]\n        ttl: 3600\n")?;
        let config = self.root.path().join("config.json");
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "schema": "chio.process.host.v1", "policy": policy,
                "mailboxes": [{"id": "jobs"}],
                "limits": {"max_processes": 1, "max_depth": 0, "max_calls": 10}
            }))?,
        )?;
        let state = self.root.path().join("host");
        super::super::super::provision::init(&config, &state, None, None)?;
        let plan = self.root.path().join("plan.json");
        std::fs::write(
            &plan,
            serde_json::to_vec(&serde_json::json!({
                "schema": "chio.process.run.v1", "max_parallel": 1,
                "workers": [{"process": "root", "command": ["/usr/bin/python3"],
                    "cwd": "/work", "max_attempts": 3, "timeout_seconds": 10,
                    "container": {"image": format!("sha256:{}", "1".repeat(64))}}]
            }))?,
        )?;
        Ok((state, plan))
    }
}

impl Drop for EngineDouble {
    fn drop(&mut self) {
        if let Ok(mut transport) = ATTACHMENT_TRANSPORT.lock() {
            *transport = None;
        }
        if let Ok(mut command) = ENGINE_COMMAND.lock() {
            *command = None;
        }
    }
}

fn attachment_error_after_request(lease: &Lease) -> Result<Spawned, CliError> {
    use std::io::Write;
    // Only external request delivery is substituted. The fixture starts its
    // owned worker before reporting a lost client-supervision result. Real
    // production run/inspection/journal/cleanup decide what this error means.
    let id = lease
        .id
        .as_deref()
        .ok_or_else(|| error("missing fixture ID"))?;
    let mut client = command(&strings(&["start", "--attach", "--interactive", id]))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    client
        .stdin
        .take()
        .ok_or_else(|| error("missing fixture stdin"))?
        .write_all(b"{}\n")?;
    if !client.wait()?.success() {
        return Err(error("fixture start failed before transport fault"));
    }
    Err(std::io::Error::other("attachment transport failed after request delivery").into())
}

#[test]
fn attachment_error_preserves_authoritative_exit_and_uncertainty(
) -> Result<(), Box<dyn std::error::Error>> {
    for (scenario, completed, retained) in [
        (serde_json::json!({}), true, 0),
        (serde_json::json!({"cleanup_failure": true}), true, 1),
        (serde_json::json!({"worker_status": "running"}), false, 0),
        (serde_json::json!({"worker_status": "dead"}), false, 0),
        (serde_json::json!({"worker_status": "paused"}), false, 0),
        (
            serde_json::json!({"oom_killed": true, "worker_exit": 137}),
            false,
            0,
        ),
        (serde_json::json!({"changed_identity": true}), false, 1),
        (serde_json::json!({"inspect_failure": true}), false, 1),
    ] {
        let engine = EngineDouble::new(scenario.clone())?;
        *ATTACHMENT_TRANSPORT
            .lock()
            .map_err(|_| "attachment lock poisoned")? = Some(attachment_error_after_request);
        let (state, plan) = engine.host()?;
        if scenario.get("oom_killed").is_some() {
            let mut definition: serde_json::Value = serde_json::from_slice(&std::fs::read(&plan)?)?;
            definition["workers"][0]["max_attempts"] = serde_json::json!(1);
            std::fs::write(&plan, serde_json::to_vec(&definition)?)?;
        }
        let failure = super::super::run(&state, &plan)
            .err()
            .ok_or("client failure must fail the command")?;
        if retained == 0 {
            assert!(
                failure.to_string().contains("attachment transport failed"),
                "{failure}"
            );
        }
        let db = rusqlite::Connection::open(state.join("runner.db"))?;
        let snapshot: (String, u32, String) = db.query_row(
            "SELECT state,attempts,outcome FROM run_workers",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(
            snapshot.0,
            if completed { "completed" } else { "failed" },
            "{scenario}"
        );
        assert_eq!(snapshot.1, 1, "{scenario}");
        if completed {
            assert_eq!(snapshot.2, "exit_0");
        }
        if scenario.get("oom_killed").is_some() {
            assert_eq!(snapshot.2, "container_memory_ceiling");
        }
        if scenario
            .get("worker_status")
            .is_some_and(|status| status == "dead" || status == "paused")
        {
            assert_eq!(snapshot.2, "container_state_unknown");
        }
        assert!(
            std::fs::read_to_string(state.join("run-logs/root-1.stderr"))?
                .contains("attachment transport failed after request delivery")
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM run_containers", [], |row| row
                .get::<_, i64>(0))?,
            retained,
            "{scenario}"
        );
        engine.scenario(serde_json::json!({}))?;
        assert_eq!(super::super::run(&state, &plan).is_ok(), completed);
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM run_containers", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            db.query_row("SELECT attempts FROM run_workers", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        assert_eq!(
            std::fs::read_to_string(engine.root.path().join("starts"))?,
            "1"
        );
    }
    Ok(())
}

#[test]
fn completion_survives_cleanup_debt_and_restart() -> Result<(), Box<dyn std::error::Error>> {
    let engine = EngineDouble::new(serde_json::json!({"cleanup_failure": true}))?;
    let (state, plan) = engine.host()?;
    assert!(
        super::super::run(&state, &plan).is_err(),
        "cleanup debt cannot report a complete run"
    );
    let db = rusqlite::Connection::open(state.join("runner.db"))?;
    let snapshot: (String, u32, String) =
        db.query_row("SELECT state,attempts,outcome FROM run_workers", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    assert_eq!(snapshot, ("completed".into(), 1, "exit_0".into()));
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM run_containers", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    assert!(
        super::super::super::relocation::export(&state).is_err(),
        "owned container debt must fence export"
    );
    engine.scenario(serde_json::json!({}))?;
    super::super::run(&state, &plan)?;
    assert_eq!(
        std::fs::read_to_string(engine.root.path().join("starts"))?,
        "1"
    );
    assert_eq!(
        db.query_row("SELECT attempts FROM run_workers", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM run_containers", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    Ok(())
}

#[test]
fn create_rejection_requires_positive_empty_inventory() -> Result<(), Box<dyn std::error::Error>> {
    for (create, retained) in [("rejected", 0), ("unconfirmed", 1), ("response_lost", 1)] {
        let engine = EngineDouble::new(serde_json::json!({"create": create}))?;
        let (state, plan) = engine.host()?;
        assert!(super::super::run(&state, &plan).is_err());
        let db = rusqlite::Connection::open(state.join("runner.db"))?;
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM run_containers", [], |r| r
                .get::<_, i64>(0))?,
            retained,
            "{create}"
        );
        assert!(!engine.root.path().join("starts").exists());
    }
    Ok(())
}

#[test]
fn diagnostic_failure_does_not_erase_completed_exit() -> Result<(), Box<dyn std::error::Error>> {
    let engine = EngineDouble::new(serde_json::json!({"start_output": 3 * 1024 * 1024}))?;
    let (state, plan) = engine.host()?;
    assert!(
        super::super::run(&state, &plan).is_err(),
        "output diagnostic must fail the command"
    );
    let db = rusqlite::Connection::open(state.join("runner.db"))?;
    assert_eq!(
        db.query_row("SELECT state FROM run_workers", [], |r| r
            .get::<_, String>(0))?,
        "completed"
    );
    engine.scenario(serde_json::json!({}))?;
    super::super::run(&state, &plan)?;
    assert_eq!(
        std::fs::read_to_string(engine.root.path().join("starts"))?,
        "1"
    );
    Ok(())
}

#[test]
fn controlled_limits_retain_worker_restart_budget() -> Result<(), Box<dyn std::error::Error>> {
    for (scenario, reason) in [
        (
            serde_json::json!({"worker_status": "running", "start_sleep": 3}),
            "timeout",
        ),
        (
            serde_json::json!({"worker_status": "running", "start_output": 3 * 1024 * 1024}),
            "output_ceiling",
        ),
    ] {
        let engine = EngineDouble::new(scenario)?;
        let (state, plan) = engine.host()?;
        let mut definition: serde_json::Value = serde_json::from_slice(&std::fs::read(&plan)?)?;
        definition["workers"][0]["timeout_seconds"] = serde_json::json!(1);
        definition["workers"][0]["max_attempts"] = serde_json::json!(2);
        std::fs::write(&plan, serde_json::to_vec(&definition)?)?;
        assert!(super::super::run(&state, &plan).is_err());
        let db = rusqlite::Connection::open(state.join("runner.db"))?;
        let snapshot: (String, u32, String) = db.query_row(
            "SELECT state,attempts,outcome FROM run_workers",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(snapshot, ("failed".into(), 2, reason.into()));
        assert_eq!(
            std::fs::read_to_string(engine.root.path().join("starts"))?,
            "2"
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM run_containers", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
    }
    Ok(())
}

#[test]
fn ready_completion_is_durable_before_interruption() -> Result<(), Box<dyn std::error::Error>> {
    let engine = EngineDouble::new(serde_json::json!({}))?;
    let (state, path) = engine.host()?;
    let host = super::super::super::state::Host::open(&state, true)?;
    let plan: super::super::plan::Plan = serde_json::from_slice(&std::fs::read(path)?)?;
    let mut journal = Journal::open(&host, &plan)?;
    let worker = journal.workers[0].clone();
    let attempt = journal.start(&worker)?;
    let logs = chio_control_plane::prepare_private_directory(&state.join("run-logs"))?;
    let service = chio_process::worker::WorkerService::new(host.runtime.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut active = tokio::task::JoinSet::new();
        let done = active.spawn(async move {
            super::super::Attempt {
                index: 0,
                attempt,
                secret: "test-only-secret".into(),
                cleanup: None,
                diagnostics: None,
                result: Ok(Outcome {
                    success: true,
                    reason: "exit_0".into(),
                    usage: Usage::default(),
                    stdout: vec![],
                    stderr: vec![],
                    diagnostic: None,
                }),
            }
        });
        while !done.is_finished() {
            tokio::task::yield_now().await;
        }
        match super::super::next_event(&mut active, std::future::ready(())).await {
            super::super::Event::Completed(result) => {
                super::super::record_attempt(&host, &mut journal, &logs, &service, &result?)?;
            }
            _ => return Err("completion was lost to a ready interruption".into()),
        }
        let snapshot = journal.snapshots()?;
        assert_eq!(
            (snapshot[0].state.as_str(), snapshot[0].attempts),
            ("completed", 1)
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

#[test]
fn legacy_create_intent_migrates_without_rejection_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let engine = EngineDouble::new(serde_json::json!({"create": "response_lost"}))?;
    let (state, plan) = engine.host()?;
    assert!(super::super::run(&state, &plan).is_err());
    let db = rusqlite::Connection::open(state.join("runner.db"))?;
    db.execute_batch("ALTER TABLE run_containers DROP COLUMN create_rejected")?;
    assert!(super::super::run(&state, &plan).is_err());
    assert_eq!(
        db.query_row("SELECT create_rejected FROM run_containers", [], |row| row
            .get::<_, i64>(
            0
        ))?,
        0
    );
    assert_eq!(
        db.query_row("SELECT attempts FROM run_workers", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    assert!(!engine.root.path().join("starts").exists());
    Ok(())
}

#[test]
fn observed_container_states() -> Result<(), Box<dyn std::error::Error>> {
    for (status, running, started, reason, expected, success) in [
        (
            "created",
            false,
            "0001-01-01T00:00:00Z",
            "exit_1",
            "container_never_started",
            false,
        ),
        (
            "running",
            true,
            "2026-01-01T00:00:00Z",
            "exit_1",
            "container_attachment_lost",
            false,
        ),
        (
            "running",
            true,
            "2026-01-01T00:00:00Z",
            "timeout",
            "timeout",
            false,
        ),
        (
            "running",
            true,
            "2026-01-01T00:00:00Z",
            "output_ceiling",
            "output_ceiling",
            false,
        ),
        (
            "unknown",
            false,
            "2026-01-01T00:00:00Z",
            "exit_0",
            "container_state_unknown",
            false,
        ),
        (
            "exited",
            true,
            "2026-01-01T00:00:00Z",
            "exit_0",
            "container_attachment_lost",
            false,
        ),
        (
            "exited",
            false,
            "0001-01-01T00:00:00Z",
            "exit_0",
            "container_state_unknown",
            false,
        ),
        (
            "exited",
            false,
            "not-a-timestamp",
            "exit_0",
            "container_state_unknown",
            false,
        ),
        (
            "exited",
            false,
            "2026-01-01T00:00:00Z",
            "exit_1",
            "exit_0",
            true,
        ),
        (
            "exited",
            false,
            "2026-01-01T00:00:00Z",
            "output_ceiling",
            "exit_0",
            true,
        ),
    ] {
        let record: Record = serde_json::from_value(serde_json::json!({
            "id": "a".repeat(64), "name": "/chio-run-test", "labels": {},
            "running": running, "status": status, "started_at": started,
            "exit_code": 0, "oom_killed": false,
        }))?;
        let mut outcome = Outcome {
            success: reason == "exit_0",
            reason: reason.into(),
            usage: Usage::default(),
            stdout: vec![],
            stderr: vec![],
            diagnostic: None,
        };
        classify(&record, &mut outcome);
        assert_eq!(
            (outcome.success, outcome.reason.as_str()),
            (success, expected),
            "{status}/{started}/{reason}"
        );
    }
    Ok(())
}
