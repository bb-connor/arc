#![cfg(unix)]

use chio_workbench::{Error, Result, Run, RunStatus, Workbench, WorkbenchConfig};
use std::{os::unix::fs::PermissionsExt, path::Path, process::Command, time::Duration};

mod support;

fn git(path: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=Workbench Test",
            "-c",
            "user.email=workbench@example.invalid",
        ])
        .args(args)
        .current_dir(path)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()?;
    if !output.status.success() {
        return Err(Error::Invalid("Git test setup failed".into()));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| Error::Invalid("Git test output was not UTF-8".into()))
}

fn config(root: &Path) -> Result<WorkbenchConfig> {
    let mut config = support::config(root)?;
    config.git_worktrees = true;
    git(&config.workspace, &["init", "--quiet"])?;
    git(&config.workspace, &["add", "calc.py"])?;
    git(&config.workspace, &["commit", "--quiet", "-m", "fixture"])?;
    Ok(config)
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
    .map_err(|_| Error::Invalid("Git task did not finish".into()))?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_stays_in_its_worktree_and_produces_a_verifiable_patch() -> Result<()> {
    let root = tempfile::tempdir()?;
    let settings = config(root.path())?;
    let source = settings.workspace.clone();
    let baseline = std::fs::read(source.join("calc.py"))?;
    let head = git(&source, &["rev-parse", "HEAD"])?;
    let hook = source.join(".git/hooks/post-checkout");
    std::fs::write(&hook, "#!/bin/sh\ntouch hook-executed\n")?;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700))?;
    let workbench = Workbench::open(settings, support::repair_script())?;
    let id = workbench
        .start("Repair addition in isolation".into(), 36)
        .await?;
    let run = finished(&workbench, &id).await?;
    assert_eq!(run.status, RunStatus::Succeeded, "{run:#?}");
    assert_ne!(Path::new(&run.workspace), source);
    assert_eq!(std::fs::read(source.join("calc.py"))?, baseline);
    assert_eq!(git(&source, &["rev-parse", "HEAD"])?, head);
    assert!(git(&source, &["status", "--porcelain"])?.is_empty());
    assert!(std::fs::read_to_string(Path::new(&run.workspace).join("calc.py"))?.contains("a + b"));
    assert!(!Path::new(&run.workspace).join("hook-executed").exists());
    assert!(!source.join("hook-executed").exists());
    let changes = workbench.changes(&id).await?;
    assert_eq!(changes.snapshot.base_revision, head.trim());
    assert!(changes
        .patch
        .contains("-    return a - b\n+    return a + b"));
    assert_eq!(
        changes.patch_sha256,
        chio_core::crypto::sha256_hex(changes.patch.as_bytes())
    );
    for task in &run.tasks {
        assert!(task
            .capability
            .verify_signature()
            .map_err(|error| Error::Invalid(error.to_string()))?);
        for action in &task.actions {
            let receipt = action
                .receipt
                .as_ref()
                .ok_or_else(|| Error::Invalid("missing task receipt".into()))?;
            assert!(receipt
                .verify_signature()
                .map_err(|error| Error::Invalid(error.to_string()))?);
            assert_eq!(receipt.capability_id, task.capability.id);
            let encoded = serde_json::to_value(receipt)?;
            assert_eq!(encoded["metadata"]["workbench_workspace"], run.workspace);
            assert_eq!(encoded["metadata"]["workbench_git_base"], head.trim());
        }
    }
    // Verify that the exported patch applies to the recorded source revision.
    let patch = root.path().join("change.patch");
    std::fs::write(&patch, &changes.patch)?;
    let patch = patch
        .to_str()
        .ok_or_else(|| Error::Invalid("test patch path".into()))?;
    git(&source, &["apply", "--check", patch])?;
    std::fs::write(
        Path::new(&run.workspace).join("generated.txt"),
        "check output",
    )?;
    let inspected = workbench.changes(&id).await?;
    assert_eq!(inspected.patch, changes.patch);
    assert_eq!(inspected.untracked_files, ["generated.txt"]);
    workbench.shutdown().await;
    drop(workbench);
    let mut reopened_config = support::config(root.path())?;
    reopened_config.git_worktrees = true;
    let reopened = Workbench::open(reopened_config, support::repair_script())?;
    assert_eq!(reopened.changes(&id).await?.patch, changes.patch);
    let second = reopened.start("Repair a fresh task".into(), 36).await?;
    let next = finished(&reopened, &second).await?;
    assert_eq!(next.status, RunStatus::Succeeded, "{next:#?}");
    assert_ne!(next.workspace, run.workspace);
    assert_eq!(std::fs::read(source.join("calc.py"))?, baseline);
    reopened.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn dirty_tracked_sources_are_rejected_and_the_reservation_is_released() -> Result<()> {
    let root = tempfile::tempdir()?;
    let settings = config(root.path())?;
    let source = settings.workspace.clone();
    let workbench = Workbench::open(settings, support::repair_script())?;
    std::fs::write(source.join("calc.py"), "operator work in progress")?;
    assert!(workbench
        .start("Preserve operator work".into(), 36)
        .await
        .is_err());
    assert_eq!(
        std::fs::read_to_string(source.join("calc.py"))?,
        "operator work in progress"
    );
    assert!(workbench.list()?.is_empty());
    git(&source, &["restore", "calc.py"])?;
    let id = workbench
        .start("Now use the committed version".into(), 36)
        .await?;
    assert_eq!(
        finished(&workbench, &id).await?.status,
        RunStatus::Succeeded
    );
    workbench.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn repository_subdirectories_keep_their_relative_workspace_and_patch_paths() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut settings = config(root.path())?;
    let repository = settings.workspace.clone();
    let module = repository.join("module");
    std::fs::create_dir(&module)?;
    std::fs::rename(repository.join("calc.py"), module.join("calc.py"))?;
    git(&repository, &["add", "-A"])?;
    git(
        &repository,
        &["commit", "--quiet", "-m", "subdirectory fixture"],
    )?;
    settings.workspace = module.clone();
    let workbench = Workbench::open(settings, support::repair_script())?;
    let id = workbench
        .start("Repair a repository subdirectory".into(), 36)
        .await?;
    let run = finished(&workbench, &id).await?;
    assert_eq!(run.status, RunStatus::Succeeded, "{run:#?}");
    assert!(Path::new(&run.workspace).ends_with("worktree/module"));
    assert!(workbench
        .changes(&id)
        .await?
        .patch
        .contains("a/module/calc.py"));
    assert!(std::fs::read_to_string(module.join("calc.py"))?.contains("a - b"));
    workbench.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn nested_state_and_non_git_sources_are_rejected_before_model_use() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut settings = config(root.path())?;
    settings.state_dir = settings.workspace.join(".chio-state");
    let workbench = Workbench::open(settings, support::repair_script())?;
    assert!(workbench.start("Nested state".into(), 36).await.is_err());
    assert!(workbench.list()?.is_empty());
    workbench.shutdown().await;
    let other = tempfile::tempdir()?;
    let mut settings = support::config(other.path())?;
    settings.git_worktrees = true;
    let workbench = Workbench::open(settings, support::repair_script())?;
    assert!(workbench
        .start("No Git repository".into(), 36)
        .await
        .is_err());
    assert!(workbench.list()?.is_empty());
    workbench.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_preparation_kills_git_descendants_and_releases_the_slot() -> Result<()> {
    let root = tempfile::tempdir()?;
    let settings = config(root.path())?;
    let source = settings.workspace.clone();
    std::fs::write(source.join(".gitattributes"), "calc.py filter=pause\n")?;
    git(&source, &["add", ".gitattributes"])?;
    git(
        &source,
        &["commit", "--quiet", "-m", "checkout filter fixture"],
    )?;
    let filter = root.path().join("checkout-filter");
    let ready = root.path().join("filter-ready");
    let late = root.path().join("filter-late");
    std::fs::write(&filter, format!("#!/usr/bin/env python3\nimport sys,time\nopen({},'w').write('ready')\ntime.sleep(1)\nopen({},'w').write('late')\nsys.stdout.write(sys.stdin.read())\n", serde_json::to_string(&ready)?, serde_json::to_string(&late)?))?;
    std::fs::set_permissions(&filter, std::fs::Permissions::from_mode(0o700))?;
    let filter = format!("'{}'", filter.display().to_string().replace('\'', "'\\''"));
    git(&source, &["config", "filter.pause.smudge", &filter])?;
    let workbench = Workbench::open(settings, support::repair_script())?;
    let worker = workbench.clone();
    let preparing = tokio::spawn(async move { worker.start("Cancel checkout".into(), 36).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| Error::Invalid("checkout filter did not start".into()))?;
    preparing.abort();
    assert!(preparing.await.is_err());
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!late.exists(), "a Git descendant survived cancellation");
    assert!(workbench.list()?.is_empty());
    git(&source, &["config", "filter.pause.smudge", "cat"])?;
    let id = workbench
        .start("Prepare after cancellation".into(), 36)
        .await?;
    assert_eq!(
        finished(&workbench, &id).await?.status,
        RunStatus::Succeeded
    );
    workbench.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_git_tasks_are_retained_without_replaying_or_requiring_the_worktree(
) -> Result<()> {
    let root = tempfile::tempdir()?;
    let settings = config(root.path())?;
    let source = settings.workspace.clone();
    let workbench = Workbench::open(settings, support::repair_script())?;
    let id = workbench.start("Repair a retained task".into(), 36).await?;
    let mut run = finished(&workbench, &id).await?;
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
    git(&source, &["worktree", "remove", "--force", &run.workspace])?;
    let mut settings = support::config(root.path())?;
    settings.git_worktrees = true;
    let reopened = Workbench::open(settings, support::repair_script())?;
    let recovered = reopened.get(&id)?;
    assert_eq!(recovered.status, RunStatus::Interrupted);
    assert_eq!(recovered.tasks[2].actions[1].state, "unknown");
    assert_eq!(reopened.list()?.len(), 1);
    assert!(reopened.changes(&id).await.is_err());
    assert!(std::fs::read_to_string(source.join("calc.py"))?.contains("a - b"));
    reopened.shutdown().await;
    Ok(())
}
