use super::*;
use std::os::unix::fs::PermissionsExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<(tempfile::TempDir, Host, Plan), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let policy = directory.path().join("policy.yaml");
    std::fs::write(&policy, "kernel:\n  max_capability_ttl: 3600\n  delegation_depth_limit: 1\n  durable_admission_mode: all\ncapabilities:\n  default:\n    tools:\n      - server: chio-ipc\n        tool: '*'\n        operations: [invoke, delegate]\n        ttl: 3600\n")?;
    let config = directory.path().join("config.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "schema": "chio.process.host.v1", "policy": policy,
            "mailboxes": [{"id": "jobs"}],
            "limits": {"max_processes": 3, "max_depth": 1, "max_calls": 10},
            "children": [
                {"id": "A", "parent": "root", "budget_share_bps": 4000,
                 "tools": [{"server_id": "chio-ipc", "tool_name": "send_jobs"}]},
                {"id": "B", "parent": "root", "budget_share_bps": 4000,
                 "tools": [{"server_id": "chio-ipc", "tool_name": "send_jobs"}]}
            ]
        }))?,
    )?;
    let state = directory.path().join("host");
    super::super::super::provision::init(&config, &state, None, None)?;
    let host = Host::open(&state, true)?;
    let workers: Vec<_> = ["root", "A", "B"]
        .into_iter()
        .map(|process| {
            serde_json::json!({
                "process": process, "command": ["/bin/true"], "cwd": directory.path(),
                "max_attempts": 1, "timeout_seconds": 10,
                "depends_on": if process == "B" { vec!["A"] } else { vec![] }
            })
        })
        .collect();
    let plan = serde_json::from_value(serde_json::json!({
        "schema": "chio.process.run.v1", "max_parallel": 3,
        "failure_policy": "stop", "workers": workers
    }))?;
    Ok((directory, host, plan))
}

#[test]
fn pending_cancellation_spends_no_attempt_or_resources() -> TestResult {
    let (_directory, host, plan) = fixture()?;
    let mut journal = Journal::open(&host, &plan)?;
    let worker = journal.workers[1].clone();
    journal.cancel_pending(&worker)?;
    journal.check_publication()?;
    let snapshots = journal.snapshots()?;
    let cancelled = snapshots
        .iter()
        .find(|s| s.process == "A")
        .ok_or("missing A")?;
    assert_eq!(cancelled.state, WorkerState::Failed);
    assert_eq!(cancelled.outcome.as_deref(), Some("process_cancelled"));
    assert_eq!(
        (
            cancelled.attempts,
            cancelled.suspensions,
            cancelled.peak_resident_bytes,
            cancelled.cpu_ms
        ),
        (0, 0, 0, 0)
    );
    journal.fail_dependents()?;
    let snapshots = journal.snapshots()?;
    let blocked = snapshots
        .iter()
        .find(|s| s.process == "B")
        .ok_or("missing B")?;
    assert_eq!(
        (blocked.state, blocked.outcome.as_deref(), blocked.attempts),
        (WorkerState::Failed, Some("dependency_failed"), 0)
    );
    let root = snapshots
        .iter()
        .find(|s| s.process == "root")
        .ok_or("missing root")?;
    assert_eq!((root.state, root.attempts), (WorkerState::Pending, 0));
    assert!(!journal.completion()?.complete);
    let cancelled = BTreeSet::from(["A".to_owned()]);
    assert!(!journal.has_stop_failure(&snapshots, &cancelled)?);
    assert!(journal.has_stop_failure(&snapshots, &BTreeSet::new())?);
    let root = journal.workers[0].clone();
    journal.start(&root)?;
    journal.finish(
        &root,
        Completion::Failed("exit_68"),
        ResourceUsage::default(),
    )?;
    assert!(journal.has_stop_failure(&journal.snapshots()?, &cancelled)?);
    Ok(())
}

#[test]
fn pending_cancellation_refuses_active_and_completed_attempts_without_mutation() -> TestResult {
    let (_directory, host, plan) = fixture()?;
    let mut journal = Journal::open(&host, &plan)?;
    let worker = journal.workers[1].clone();
    journal.start(&worker)?;
    for completed in [false, true] {
        if completed {
            journal.finish(
                &worker,
                Completion::Completed("exit_0"),
                ResourceUsage {
                    peak_resident_bytes: 4096,
                    cpu_ms: 7,
                },
            )?;
        }
        let before = serde_json::to_value(journal.snapshots()?)?;
        let failure = journal
            .cancel_pending(&worker)
            .err()
            .ok_or("nonpending cancellation accepted")?;
        let CliError::Chio(failure) = failure else {
            return Err("pending cancellation returned an unregistered error".into());
        };
        assert_eq!(failure.code().as_str(), "urn:chio:error:cli:other");
        assert_eq!(
            failure.message(),
            "process host: cancellation does not match pending worker state"
        );
        assert_eq!(serde_json::to_value(journal.snapshots()?)?, before);
    }
    Ok(())
}
