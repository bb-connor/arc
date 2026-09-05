//! Browser smoke fixture. Only model proposals are scripted; kernel, stores,
//! file edits, check subprocesses and the HTTP/UI path execute normally.
#[path = "../tests/support/mod.rs"]
#[cfg(unix)]
mod support;

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let workbench =
        chio_workbench::Workbench::open(support::config(root.path())?, support::repair_script())?;
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
