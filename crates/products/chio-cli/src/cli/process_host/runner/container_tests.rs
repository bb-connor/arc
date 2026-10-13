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
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
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

    fn artifacts(&self, name: &str) -> std::io::Result<Vec<std::path::PathBuf>> {
        let containers = self.root.path().join("containers");
        let mut artifacts = Vec::new();
        if containers.try_exists()? {
            for entry in std::fs::read_dir(containers)? {
                let path = entry?.path().join(name);
                if path.try_exists()? {
                    artifacts.push(path);
                }
            }
        }
        Ok(artifacts)
    }

    fn starts(&self) -> Result<u32, Box<dyn std::error::Error>> {
        let mut count = 0;
        for path in self.artifacts("starts")? {
            count += std::fs::read_to_string(path)?.parse::<u32>()?;
        }
        Ok(count)
    }

    fn host(
        &self,
        processes: &[&str],
    ) -> Result<(std::path::PathBuf, std::path::PathBuf), Box<dyn std::error::Error>> {
        let policy = self.root.path().join("policy.yaml");
        std::fs::write(&policy, "kernel:\n  max_capability_ttl: 3600\n  delegation_depth_limit: 1\n  durable_admission_mode: all\ncapabilities:\n  default:\n    tools:\n      - server: chio-ipc\n        tool: '*'\n        operations: [invoke, delegate]\n        ttl: 3600\n")?;
        let children: Vec<_> = processes
            .iter()
            .filter(|process| **process != "root")
            .map(|process| {
                serde_json::json!({
                    "id": process, "parent": "root", "budget_share_bps": 4000,
                    "tools": [{"server_id": "chio-ipc", "tool_name": "send_jobs"}]
                })
            })
            .collect();
        let config = self.root.path().join("config.json");
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "schema": "chio.process.host.v1", "policy": policy,
                "mailboxes": [{"id": "jobs"}],
                "limits": {"max_processes": children.len() + 1, "max_depth": 1, "max_calls": 10},
                "children": children,
            }))?,
        )?;
        let state = self.root.path().join("host");
        super::super::super::provision::init(&config, &state, None, None)?;
        let workers: Vec<_> = processes
            .iter()
            .map(|process| {
                serde_json::json!({
                    "process": process, "command": ["/usr/bin/python3", process],
                    "cwd": "/work", "max_attempts": 3, "timeout_seconds": 10,
                    "container": {"image": format!("sha256:{}", "1".repeat(64))}
                })
            })
            .collect();
        let plan = self.root.path().join("plan.json");
        std::fs::write(
            &plan,
            serde_json::to_vec(&serde_json::json!({
                "schema": "chio.process.run.v1", "max_parallel": processes.len(),
                "workers": workers,
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

fn await_engine_artifact(
    state: &Path,
    fixture: &Path,
    process: &str,
    artifact: &str,
) -> Result<std::path::PathBuf, String> {
    use rusqlite::OptionalExtension;
    for _ in 0..3000 {
        let path = state.join("runner.db");
        if path.try_exists().map_err(|error| error.to_string())? {
            let db = rusqlite::Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(|error| error.to_string())?;
            let initialized: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='run_containers')",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if !initialized {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            let owner: Option<String> = db
                .query_row(
                    "SELECT owner FROM run_containers WHERE process=?1",
                    [process],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            if let Some(owner) = owner {
                let directory = fixture
                    .join("containers")
                    .join(chio_core_types::crypto::sha256_hex(owner.as_bytes()));
                if directory
                    .join(artifact)
                    .try_exists()
                    .map_err(|error| error.to_string())?
                {
                    return Ok(directory);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(format!("{process} did not reach {artifact}"))
}

fn worker_frame(
    socket: &Path,
    credential: &serde_json::Value,
    operation: &str,
) -> Result<serde_json::Value, String> {
    use std::io::{BufRead, Read, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(socket)
        .map_err(|error| error.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    let mut request = serde_json::to_vec(&serde_json::json!({
        "protocol": chio_process::worker::PROTOCOL,
        "credential": credential,
        "operation": {"op": operation},
    })).map_err(|error| error.to_string())?;
    request.push(b'\n');
    stream.write_all(&request).map_err(|error| error.to_string())?;
    let mut response = String::new();
    std::io::BufReader::new(stream.take(65_536))
        .read_line(&mut response).map_err(|error| error.to_string())?;
    serde_json::from_str(&response).map_err(|error| error.to_string())
}

fn cancel_worker(
    state: &Path,
    bootstrap: &serde_json::Value,
    socket: &Path,
    expected: &[(&str, &str)],
) -> Result<(), String> {
    let connection = &bootstrap["connection"];
    let inspected = worker_frame(socket, &connection["credential"], "inspect")?;
    if inspected["ok"] != true
        || inspected["result"]["process_id"] != connection["process_id"]
    {
        return Err("worker credential did not authenticate its process".into());
    }
    let response = worker_frame(socket, &connection["credential"], "cancel");
    let db = rusqlite::Connection::open_with_flags(
        state.join("process.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ).map_err(|error| error.to_string())?;
    let rows = db.prepare("SELECT id,state FROM processes ORDER BY id")
        .map_err(|error| error.to_string())?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?;
    if rows != expected.iter().map(|(id, state)| ((*id).to_owned(), (*state).to_owned())).collect::<Vec<_>>() {
        return Err(format!("worker cancellation committed unexpected process states: {rows:?}"));
    }
    if let Ok(response) = response {
        let count = expected.iter().filter(|(_, state)| *state == "cancelled").count();
        if response != serde_json::json!({"protocol": chio_process::worker::PROTOCOL, "ok": true, "result": {"cancelled_processes": count}})
            && response != serde_json::json!({"protocol": chio_process::worker::PROTOCOL, "ok": false, "error": {"code": "unauthenticated"}})
        {
            return Err(format!("unexpected cancellation response: {response}"));
        }
    }
    Ok(())
}

#[test]
fn container_cancellation_keeps_independent_attachment_running(
) -> Result<(), Box<dyn std::error::Error>> {
    let engine = EngineDouble::new(serde_json::json!({
        "worker_status": "running", "gates": ["attachment"]
    }))?;
    let (state, plan) = engine.host(&["A", "B"])?;
    let mut definition: serde_json::Value = serde_json::from_slice(&std::fs::read(&plan)?)?;
    for worker in definition["workers"]
        .as_array_mut()
        .ok_or("missing worker array")?
    {
        worker["timeout_seconds"] = serde_json::json!(60);
    }
    std::fs::write(&plan, serde_json::to_vec(&definition)?)?;
    let (result, checked) = std::thread::scope(|scope| {
        let observer = scope.spawn(|| -> Result<(), String> {
            let target =
                await_engine_artifact(&state, engine.root.path(), "A", "attachment.ready")?;
            let independent =
                await_engine_artifact(&state, engine.root.path(), "B", "attachment.ready")?;
            let retained = std::fs::read(independent.join("record.json"))
                .map_err(|error| error.to_string())?;
            let bootstrap = serde_json::from_slice(&std::fs::read(target.join("bootstrapped"))
                .map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
            let arguments: Vec<String> = serde_json::from_slice(&std::fs::read(target.join("create_args.json"))
                .map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
            let mount = arguments.windows(2).find(|pair| pair[0] == "--mount")
                .ok_or("container mount argument missing")?;
            let socket = mount[1].split(',').find_map(|part| part.strip_prefix("src="))
                .ok_or("container socket source missing")?;
            cancel_worker(&state, &bootstrap, Path::new(socket), &[
                ("A", "cancelled"), ("B", "running"), ("root", "running"),
            ])?;
            for _ in 0..3000 {
                if target
                    .join("removed")
                    .try_exists()
                    .map_err(|error| error.to_string())?
                {
                    let current = std::fs::read(independent.join("record.json"))
                        .map_err(|error| error.to_string())?;
                    if current != retained
                        || independent
                            .join("removed")
                            .try_exists()
                            .map_err(|error| error.to_string())?
                    {
                        return Err(
                            "selected cancellation changed the independent container".into()
                        );
                    }
                    std::fs::write(independent.join("attachment.release"), b"release")
                        .map_err(|error| error.to_string())?;
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err("selected container was not removed".into())
        });
        let result = super::super::run(&state, &plan);
        let checked = observer
            .join()
            .map_err(|_| "container observer panicked".to_owned());
        (result, checked)
    });
    checked?.map_err(|failure| format!("{failure}; runner result: {result:?}"))?;
    let failure = result
        .err()
        .ok_or("cancelled work must deny complete run publication")?;
    let db = rusqlite::Connection::open(state.join("runner.db"))?;
    let rows = db
        .prepare("SELECT process,state,attempts,outcome,peak_resident_bytes,cpu_ms FROM run_workers ORDER BY process")?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, u32>(2)?, row.get::<_, String>(3)?, row.get::<_, i64>(4)?, row.get::<_, i64>(5)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        rows,
        vec![
            (
                "A".into(),
                "failed".into(),
                1,
                "process_cancelled".into(),
                0,
                0
            ),
            ("B".into(), "completed".into(), 1, "exit_0".into(), 0, 0),
        ]
    );
    assert_eq!(
        failure.to_string(),
        error("run worker was cancelled").to_string()
    );
    assert_eq!(engine.starts()?, 2);
    assert_eq!(engine.artifacts("bootstrapped")?.len(), 2);
    assert_eq!(engine.artifacts("removed")?.len(), 2);
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM run_containers", [], |row| row
            .get::<_, u32>(0))?,
        0
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM run_container_launches", [], |row| row
            .get::<_, u32>(0))?,
        2
    );
    Ok(())
}

#[test]
fn container_cancellation_retains_custody_at_each_launch_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    for (phase, starts, bootstraps, retained, launches) in [
        ("create_before", 0, 0, 1, 0),
        ("create_after", 0, 0, 0, 0),
        ("confirm", 1, 0, 0, 0),
        ("attachment", 1, 1, 0, 1),
    ] {
        let engine = EngineDouble::new(serde_json::json!({
            "worker_status": "running", "gates": [phase]
        }))?;
        let (state, plan) = engine.host(&["root", "A"])?;
        let bootstrap_path = engine.root.path().join("root-bootstrap.json");
        let mut definition: serde_json::Value = serde_json::from_slice(&std::fs::read(&plan)?)?;
        definition["workers"][0] = serde_json::json!({
            "process": "root",
            "command": ["/usr/bin/python3", "-c", "import json,os,sys,time; from pathlib import Path; b=json.load(sys.stdin); b['pid']=os.getpid(); p=Path(sys.argv[1]); t=p.with_suffix('.tmp'); t.write_text(json.dumps(b)); t.replace(p); time.sleep(60)", bootstrap_path],
            "cwd": engine.root.path(), "max_attempts": 1, "timeout_seconds": 60,
        });
        definition["workers"][1]["timeout_seconds"] = serde_json::json!(60);
        std::fs::write(&plan, serde_json::to_vec(&definition)?)?;
        let (result, cancelled) = std::thread::scope(|scope| {
            let canceller = scope.spawn(|| -> Result<serde_json::Value, String> {
                await_engine_artifact(
                    &state,
                    engine.root.path(),
                    "A",
                    &format!("{phase}.ready"),
                )?;
                for _ in 0..3000 {
                    if bootstrap_path.try_exists().map_err(|error| error.to_string())? {
                        let bootstrap: serde_json::Value = serde_json::from_slice(&std::fs::read(&bootstrap_path)
                            .map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
                        let socket = bootstrap["connection"]["socket_path"].as_str()
                            .ok_or("native worker socket missing")?;
                        cancel_worker(&state, &bootstrap, Path::new(socket), &[("A", "cancelled"), ("root", "cancelled")])?;
                        return Ok(bootstrap);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err("native controller did not receive its bootstrap".into())
            });
            let result = super::super::run(&state, &plan);
            (
                result,
                canceller.join().map_err(|_| "container canceller panicked"),
            )
        });
        let bootstrap = cancelled?.map_err(|failure| format!("{phase}: {failure}; runner result: {result:?}"))?;
        let pid = bootstrap["pid"].as_u64().ok_or("native controller PID missing")?;
        assert!(!Path::new(&format!("/proc/{pid}")).try_exists()?, "{phase}: controller remains alive");
        let failure = result
            .err()
            .ok_or("cancelled work must deny complete run publication")?;
        assert_eq!(
            failure.to_string(),
            error("run worker was cancelled").to_string(),
            "{phase}"
        );
        let db = rusqlite::Connection::open(state.join("runner.db"))?;
        let snapshot: (String, u32, String, i64, i64) = db.query_row(
            "SELECT state,attempts,outcome,peak_resident_bytes,cpu_ms FROM run_workers WHERE process='A'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        assert_eq!(
            snapshot,
            ("failed".into(), 1, "process_cancelled".into(), 0, 0),
            "{phase}"
        );
        let controller: (String, u32, String, i64) = db.query_row(
            "SELECT state,attempts,outcome,peak_resident_bytes FROM run_workers WHERE process='root'", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!((&*controller.0, controller.1, &*controller.2), ("failed", 1, "process_cancelled"), "{phase}");
        assert!(controller.3 > 0, "{phase}: native reaper usage missing");
        assert_eq!(engine.starts()?, starts, "{phase}");
        assert_eq!(
            engine.artifacts("bootstrapped")?.len(),
            bootstraps,
            "{phase}"
        );
        assert_eq!(engine.artifacts("record.json")?.len(), 0, "{phase}");
        assert_eq!(
            engine.artifacts("removed")?.len(),
            usize::from(phase != "create_before"),
            "{phase}"
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM run_containers", [], |row| row
                .get::<_, u32>(0))?,
            retained,
            "{phase}"
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM run_container_launches", [], |row| row
                .get::<_, u32>(0))?,
            launches,
            "{phase}"
        );
        if retained == 1 {
            let lease: (Option<String>, bool) = db.query_row(
                "SELECT container_id,create_rejected FROM run_containers",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(lease, (None, false));
        }
    }
    Ok(())
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
        let (state, plan) = engine.host(&["root"])?;
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
        assert_eq!(engine.starts()?, 1);
    }
    Ok(())
}

#[test]
fn completion_survives_cleanup_debt_and_restart() -> Result<(), Box<dyn std::error::Error>> {
    let engine = EngineDouble::new(serde_json::json!({"cleanup_failure": true}))?;
    let (state, plan) = engine.host(&["root"])?;
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
    assert_eq!(engine.starts()?, 1);
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
        let (state, plan) = engine.host(&["root"])?;
        assert!(super::super::run(&state, &plan).is_err());
        let db = rusqlite::Connection::open(state.join("runner.db"))?;
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM run_containers", [], |r| r
                .get::<_, i64>(0))?,
            retained,
            "{create}"
        );
        assert_eq!(engine.starts()?, 0);
    }
    Ok(())
}

#[test]
fn diagnostic_failure_does_not_erase_completed_exit() -> Result<(), Box<dyn std::error::Error>> {
    let engine = EngineDouble::new(serde_json::json!({"start_output": 3 * 1024 * 1024}))?;
    let (state, plan) = engine.host(&["root"])?;
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
    assert_eq!(engine.starts()?, 1);
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
        let (state, plan) = engine.host(&["root"])?;
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
        assert_eq!(engine.starts()?, 2);
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
    let (state, path) = engine.host(&["root"])?;
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
    let (state, plan) = engine.host(&["root"])?;
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
    assert_eq!(engine.starts()?, 0);
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

const ATTACHMENT_MARKER: &str = "chio container still running after attachment ended";

fn running_record() -> Result<Record, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
        "id": "a".repeat(64), "name": "/chio-run-test", "labels": {},
        "running": true, "status": "running", "started_at": "2026-01-01T00:00:00Z",
        "exit_code": 0, "oom_killed": false,
    }))
}

fn client_outcome(reason: &str, stderr: &[u8]) -> Outcome {
    Outcome {
        success: reason == "exit_0",
        reason: reason.into(),
        usage: Usage::default(),
        stdout: vec![],
        stderr: stderr.to_vec(),
        diagnostic: None,
    }
}

#[test]
fn attachment_loss_keeps_fixed_client_reason_in_private_log(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = b"time=\"2026-10-07T18:59:22Z\" level=error msg=\"error waiting for container: unexpected EOF\"\n";
    for (reason, client) in [
        ("exit_0", "exit_zero"),
        ("exit_1", "exit_error"),
        ("exit_125", "exit_engine"),
        ("exit_137", "exit_other"),
        ("exit_255", "exit_other"),
        ("signal", "signal"),
        ("worker_io_failed", "killed_bootstrap"),
        ("runner_interrupted", "killed_interrupt"),
        ("container_attachment_error", "unobserved"),
    ] {
        let mut outcome = client_outcome(reason, private);
        classify(&running_record()?, &mut outcome);
        assert_eq!(
            (
                outcome.success,
                outcome.reason.as_str(),
                outcome.diagnostic.as_deref()
            ),
            (false, "container_attachment_lost", None),
            "{reason}"
        );
        let mut expected =
            format!("{ATTACHMENT_MARKER}: reason {reason}, client {client}\n").into_bytes();
        expected.extend_from_slice(private);
        assert_eq!(
            String::from_utf8_lossy(&outcome.stderr),
            String::from_utf8_lossy(&expected),
            "{reason}"
        );
    }
    Ok(())
}

#[test]
fn attachment_marker_never_copies_unfixed_reason_or_stream_text(
) -> Result<(), Box<dyn std::error::Error>> {
    let credential = "chio-test-credential-7f3a91";
    let stderr = format!("--env=CHIO_TOKEN={credential} --mount src=/run/chio/private.sock\n");
    for reason in [
        format!("exit_1 {credential}"),
        format!("Error response from daemon: {credential}"),
        "exit_+1".to_owned(),
        "exit_007".to_owned(),
        "exit_256".to_owned(),
        "exit_-1".to_owned(),
        "exit_".to_owned(),
        String::new(),
    ] {
        let mut outcome = client_outcome(&reason, stderr.as_bytes());
        classify(&running_record()?, &mut outcome);
        assert_eq!(outcome.reason, "container_attachment_lost", "{reason}");
        let text = String::from_utf8(outcome.stderr)?;
        let (marker, rest) = text.split_once('\n').ok_or("missing marker line")?;
        assert_eq!(
            marker,
            format!("{ATTACHMENT_MARKER}: reason unclassified, client unclassified"),
            "{reason}"
        );
        assert_eq!(rest, stderr, "{reason}");
    }
    Ok(())
}

#[test]
fn attachment_marker_is_limited_to_the_attachment_loss_mapping(
) -> Result<(), Box<dyn std::error::Error>> {
    let private = b"worker stderr\n";
    for (status, running, started, reason, diagnostic, expected) in [
        (
            "running",
            true,
            "2026-01-01T00:00:00Z",
            "timeout",
            None,
            "timeout",
        ),
        (
            "running",
            true,
            "2026-01-01T00:00:00Z",
            "output_ceiling",
            None,
            "output_ceiling",
        ),
        (
            "running",
            true,
            "2026-01-01T00:00:00Z",
            "timeout",
            Some("output_ceiling"),
            "timeout",
        ),
        (
            "running",
            true,
            "2026-01-01T00:00:00Z",
            "exit_1",
            Some("output_ceiling"),
            "output_ceiling",
        ),
        (
            "exited",
            false,
            "2026-01-01T00:00:00Z",
            "exit_1",
            None,
            "exit_0",
        ),
        (
            "created",
            false,
            "0001-01-01T00:00:00Z",
            "exit_1",
            None,
            "container_never_started",
        ),
        (
            "unknown",
            false,
            "2026-01-01T00:00:00Z",
            "exit_1",
            None,
            "container_state_unknown",
        ),
    ] {
        let record: Record = serde_json::from_value(serde_json::json!({
            "id": "a".repeat(64), "name": "/chio-run-test", "labels": {},
            "running": running, "status": status, "started_at": started,
            "exit_code": 0, "oom_killed": false,
        }))?;
        let mut outcome = client_outcome(reason, private);
        outcome.diagnostic = diagnostic.map(str::to_owned);
        classify(&record, &mut outcome);
        assert_eq!(outcome.reason, expected, "{status}/{reason}/{diagnostic:?}");
        assert!(
            outcome.stderr.starts_with(private),
            "{status}/{reason}/{diagnostic:?}"
        );
        assert_eq!(
            String::from_utf8(outcome.stderr)?
                .matches(ATTACHMENT_MARKER)
                .count(),
            0,
            "{status}/{reason}/{diagnostic:?}"
        );
    }
    Ok(())
}

#[test]
fn attachment_loss_stays_terminal_and_names_fixed_client_reason(
) -> Result<(), Box<dyn std::error::Error>> {
    for (scenario, transport, outcome, marker) in [
        (
            serde_json::json!({"worker_status": "running", "attach_exit": 125}),
            false,
            "container_attachment_lost",
            Some("reason exit_125, client exit_engine"),
        ),
        (
            serde_json::json!({"worker_status": "running", "attach_exit": 1}),
            false,
            "container_attachment_lost",
            Some("reason exit_1, client exit_error"),
        ),
        (
            serde_json::json!({"worker_status": "running"}),
            true,
            "container_state_unknown",
            Some("reason container_attachment_error, client unobserved"),
        ),
        (serde_json::json!({}), false, "exit_0", None),
    ] {
        let engine = EngineDouble::new(scenario.clone())?;
        if transport {
            *ATTACHMENT_TRANSPORT
                .lock()
                .map_err(|_| "attachment lock poisoned")? = Some(attachment_error_after_request);
        }
        let (state, plan) = engine.host(&["root"])?;
        assert_eq!(
            super::super::run(&state, &plan).is_ok(),
            marker.is_none(),
            "{scenario}"
        );
        let db = rusqlite::Connection::open(state.join("runner.db"))?;
        let snapshot: (String, u32, String) = db.query_row(
            "SELECT state,attempts,outcome FROM run_workers",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let finished = if marker.is_some() {
            "failed"
        } else {
            "completed"
        };
        assert_eq!(snapshot, (finished.into(), 1, outcome.into()), "{scenario}");
        assert_eq!(engine.starts()?, 1, "{scenario}");
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM run_containers", [], |row| row
                .get::<_, i64>(0))?,
            0,
            "{scenario}"
        );
        let log = std::fs::read_to_string(state.join("run-logs/root-1.stderr"))?;
        match marker {
            Some(fixed) => {
                let (first, rest) = log.split_once('\n').ok_or("missing marker line")?;
                assert_eq!(first, format!("{ATTACHMENT_MARKER}: {fixed}"), "{scenario}");
                if transport {
                    assert!(
                        rest.contains("attachment transport failed after request delivery"),
                        "{scenario}"
                    );
                } else {
                    assert_eq!(rest, "", "{scenario}");
                }
            }
            None => assert_eq!(log, "", "{scenario}"),
        }
    }
    Ok(())
}

fn launch_records(
    state: &std::path::Path,
) -> Result<Vec<chio_process::ContainerLaunchRecord>, Box<dyn std::error::Error>> {
    let host = super::super::super::state::Host::open(state, true)?;
    let signer = host.authority.kernel_keypair().public_key();
    let db = rusqlite::Connection::open(state.join("runner.db"))?;
    let mut statement = db.prepare(
        "SELECT record FROM run_container_launches WHERE process='root' ORDER BY attempt",
    )?;
    let mut records = Vec::new();
    for row in statement.query_map([], |row| row.get::<_, String>(0))? {
        let signed: chio_process::SignedContainerLaunchRecord = serde_json::from_str(&row?)?;
        records.push(signed.verify(&signer)?.clone());
    }
    Ok(records)
}

#[test]
fn confirmed_launch_is_signed_before_the_bootstrap_is_released(
) -> Result<(), Box<dyn std::error::Error>> {
    let engine = EngineDouble::new(serde_json::json!({}))?;
    let (state, plan) = engine.host(&["root"])?;
    super::super::run(&state, &plan)?;
    assert_eq!(engine.artifacts("bootstrapped")?.len(), 1);
    let records = launch_records(&state)?;
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.state, CageEnforcementState::FullyEnforced);
    assert_eq!((record.process_id.as_str(), record.attempt), ("root", 1));
    assert_eq!(record.container_id.len(), 64);
    assert!(engine
        .root
        .path()
        .join("containers")
        .join(&record.container_id)
        .join("removed")
        .try_exists()?);
    assert_eq!(record.image_id, format!("sha256:{}", "1".repeat(64)));
    assert_eq!(record.engine_identity, "test-engine");
    assert_eq!(record.started_at.as_deref(), Some("2026-01-01T00:00:00Z"));
    assert_eq!(
        record.inspected_config_digest.as_deref(),
        Some(record.profile_digest.as_str())
    );
    Ok(())
}

#[test]
fn any_profile_deviation_is_rejected_before_start() -> Result<(), Box<dyn std::error::Error>> {
    for drift in [
        serde_json::json!({"CapDrop": []}),
        serde_json::json!({"CapAdd": ["NET_ADMIN"]}),
        serde_json::json!({"SecurityOpt": ["no-new-privileges:true", "seccomp=unconfined"]}),
        serde_json::json!({"Privileged": true}),
        serde_json::json!({"NetworkMode": "bridge"}),
        serde_json::json!({"ReadonlyRootfs": false}),
        serde_json::json!({"Binds": ["/:/host"]}),
        serde_json::json!({"Mounts": []}),
        serde_json::json!({"Tmpfs": {"/tmp": "rw,size=16m"}}),
        serde_json::json!({"Memory": 0}),
        serde_json::json!({"PidsLimit": null}),
        serde_json::json!({"UsernsMode": "host"}),
        serde_json::json!({"Ulimits": []}),
        serde_json::json!({"Init": false}),
    ] {
        let engine = EngineDouble::new(serde_json::json!({"config_drift": drift}))?;
        let (state, plan) = engine.host(&["root"])?;
        let failure = super::super::run(&state, &plan)
            .err()
            .ok_or("a deviating container must fail the run")?;
        assert!(
            failure
                .to_string()
                .contains("differs from the fixed worker profile"),
            "{drift}: {failure}"
        );
        assert_eq!(engine.starts()?, 0, "{drift}");
        let records = launch_records(&state)?;
        assert_eq!(records.len(), 1, "{drift}");
        let record = &records[0];
        assert_eq!(record.state, CageEnforcementState::Rejected, "{drift}");
        assert_eq!(
            record.failure_class,
            Some(chio_process::ContainerLaunchFailure::ProfileMismatch),
            "{drift}"
        );
        assert_ne!(
            record.inspected_config_digest.as_deref(),
            Some(record.profile_digest.as_str()),
            "{drift}"
        );
        let db = rusqlite::Connection::open(state.join("runner.db"))?;
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM run_containers", [], |row| row
                .get::<_, i64>(0))?,
            0,
            "{drift}"
        );
    }
    Ok(())
}

#[test]
fn unconfirmed_start_withholds_the_bootstrap() -> Result<(), Box<dyn std::error::Error>> {
    for scenario in [
        serde_json::json!({"exit_before_bootstrap": true}),
        serde_json::json!({"config_drift_after_start": {"NetworkMode": "host"}}),
    ] {
        let engine = EngineDouble::new(scenario.clone())?;
        let (state, plan) = engine.host(&["root"])?;
        assert!(super::super::run(&state, &plan).is_err(), "{scenario}");
        assert_eq!(engine.starts()?, 1, "{scenario}");
        assert_eq!(engine.artifacts("bootstrapped")?.len(), 0, "{scenario}");
        let records = launch_records(&state)?;
        assert_eq!(records.len(), 1, "{scenario}");
        assert_eq!(
            records[0].state,
            CageEnforcementState::BootstrapFailed,
            "{scenario}"
        );
        assert_eq!(
            records[0].failure_class,
            Some(chio_process::ContainerLaunchFailure::StartUnconfirmed),
            "{scenario}"
        );
        let db = rusqlite::Connection::open(state.join("runner.db"))?;
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM run_containers", [], |row| row
                .get::<_, i64>(0))?,
            0,
            "{scenario}"
        );
    }
    Ok(())
}
