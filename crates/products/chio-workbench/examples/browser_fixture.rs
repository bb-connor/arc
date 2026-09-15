//! Browser smoke fixture. Only model proposals are scripted; kernel, stores,
//! file edits, check subprocesses and the HTTP/UI path execute normally.
#[path = "../tests/support/mod.rs"]
#[cfg(unix)]
mod support;

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let mut config = support::config(root.path())?;
    if std::env::args().any(|argument| argument == "--git-worktrees") {
        config.git_worktrees = true;
        for args in [
            vec!["init", "--quiet"],
            vec!["add", "calc.py"],
            vec!["commit", "--quiet", "-m", "fixture"],
        ] {
            let status = std::process::Command::new("git")
                .args([
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "user.name=Workbench Test",
                    "-c",
                    "user.email=workbench@example.invalid",
                ])
                .args(args)
                .current_dir(&config.workspace)
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .status()?;
            if !status.success() {
                return Err("Git browser fixture setup failed".into());
            }
        }
    }
    let workbench = chio_workbench::Workbench::open(config, support::repair_script())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let token = uuid::Uuid::new_v4().simple().to_string();
    println!("Browser test fixture (scripted model): http://{address}/#access={token}");
    axum::serve(
        listener,
        chio_workbench::web::router(workbench.clone(), token, address),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    workbench.shutdown().await;
    Ok(())
}

#[cfg(not(unix))]
fn main() {}
