//! Trust-control handlers run their registry, store and authority work on the
//! blocking pool, so a single-threaded runtime keeps serving other tasks while
//! that work waits on a file or a SQLite lock.
use super::*;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::Instant;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Below the stores' 5 s busy timeout, so a handler that blocked its runtime
/// still completes and the probe outcome, not a store error, fails the test.
const RELEASE_DEADLINE: Duration = Duration::from_secs(2);
const RESULT_DEADLINE: Duration = Duration::from_secs(20);

fn service_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer service-secret"),
    );
    headers
}

/// Wait on a plain thread until another runtime task has run or the deadline
/// passes, and report whether the runtime ran it first.
fn wait_for_runtime(progressed: &AtomicBool) -> bool {
    let deadline = Instant::now() + RELEASE_DEADLINE;
    while !progressed.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    progressed.load(Ordering::SeqCst)
}

/// On a current-thread runtime this task runs only while the handler under
/// test is suspended, never while it occupies the runtime's only thread.
fn spawn_progress_probe(progressed: &Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
    let progressed = Arc::clone(progressed);
    tokio::spawn(async move { progressed.store(true, Ordering::SeqCst) })
}

/// Make `path` a FIFO whose reader parks until a plain thread writes
/// `contents`, which it does once the runtime has progressed.
#[cfg(target_os = "linux")]
fn parked_registry(
    path: &Path,
    contents: Vec<u8>,
    progressed: &Arc<AtomicBool>,
) -> Result<Receiver<std::io::Result<bool>>, Box<dyn std::error::Error>> {
    let status = std::process::Command::new("mkfifo").arg(path).status()?;
    if !status.success() {
        return Err("mkfifo did not create the parked registry".into());
    }
    let (sender, receiver) = mpsc::channel();
    let path = path.to_path_buf();
    let progressed = Arc::clone(progressed);
    std::thread::spawn(move || {
        let ran_first = wait_for_runtime(&progressed);
        let _ = sender.send(std::fs::write(&path, contents).map(|()| ran_first));
    });
    Ok(receiver)
}

/// Hold an exclusive write transaction on `database` until the runtime has
/// progressed. Returns once the lock is held.
fn parked_database(
    database: &Path,
    progressed: &Arc<AtomicBool>,
) -> Result<Receiver<rusqlite::Result<bool>>, Box<dyn std::error::Error>> {
    let (locked, ready) = mpsc::channel();
    let (sender, receiver) = mpsc::channel();
    let database = database.to_path_buf();
    let progressed = Arc::clone(progressed);
    std::thread::spawn(move || {
        let held = (|| {
            let connection = rusqlite::Connection::open(&database)?;
            connection.execute_batch("BEGIN EXCLUSIVE")?;
            let _ = locked.send(());
            let ran_first = wait_for_runtime(&progressed);
            connection.execute_batch("COMMIT")?;
            Ok(ran_first)
        })();
        let _ = sender.send(held);
    });
    ready.recv_timeout(RESULT_DEADLINE)?;
    Ok(receiver)
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn enterprise_provider_registry_reads_leave_the_runtime_serving() -> TestResult {
    let directory = tempfile::tempdir()?;
    let registry = directory.path().join("enterprise-providers.json");
    let progressed = Arc::new(AtomicBool::new(false));
    let released = parked_registry(
        &registry,
        serde_json::to_vec(&EnterpriseProviderRegistry::default())?,
        &progressed,
    )?;
    let mut state = metrics_state("service-secret");
    state.config.enterprise_providers_file = Some(registry);

    let probe = spawn_progress_probe(&progressed);
    let response = handle_list_enterprise_providers(State(state), service_headers()).await;
    probe.await?;
    assert!(
        released.recv_timeout(RESULT_DEADLINE)??,
        "the runtime ran another task while the registry read was parked"
    );
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn federation_policy_registry_reads_leave_the_runtime_serving() -> TestResult {
    let directory = tempfile::tempdir()?;
    let registry = directory.path().join("federation-policies.json");
    let progressed = Arc::new(AtomicBool::new(false));
    let released = parked_registry(
        &registry,
        serde_json::to_vec(&FederationAdmissionPolicyRegistry::default())?,
        &progressed,
    )?;
    let mut state = metrics_state("service-secret");
    state.config.federation_policies_file = Some(registry);

    let probe = spawn_progress_probe(&progressed);
    let response = handle_list_federation_policies(State(state), service_headers()).await;
    probe.await?;
    assert!(
        released.recv_timeout(RESULT_DEADLINE)??,
        "the runtime ran another task while the registry read was parked"
    );
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn scim_lifecycle_registry_reads_leave_the_runtime_serving() -> TestResult {
    let directory = tempfile::tempdir()?;
    let registry = directory.path().join("scim-lifecycle.json");
    let progressed = Arc::new(AtomicBool::new(false));
    let released = parked_registry(
        &registry,
        serde_json::to_vec(&ScimLifecycleRegistry::default())?,
        &progressed,
    )?;
    let mut state = metrics_state("service-secret");
    state.config.scim_lifecycle_file = Some(registry);

    let probe = spawn_progress_probe(&progressed);
    let response = handle_scim_delete_user(
        State(state),
        AxumPath("absent-user".to_string()),
        service_headers(),
    )
    .await;
    probe.await?;
    assert!(
        released.recv_timeout(RESULT_DEADLINE)??,
        "the runtime ran another task while the registry read was parked"
    );
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn revocation_writes_leave_the_runtime_serving() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("revocations.sqlite3");
    let mut state = metrics_state("service-secret");
    state.revocation_store = Some(Arc::new(SqliteRevocationStore::open(&database)?));
    let progressed = Arc::new(AtomicBool::new(false));
    let released = parked_database(&database, &progressed)?;

    let probe = spawn_progress_probe(&progressed);
    let response = handle_revoke_capability(
        State(state.clone()),
        service_headers(),
        Json(RevokeCapabilityRequest {
            capability_id: "parked-capability".to_string(),
        }),
    )
    .await;
    probe.await?;
    assert!(
        released.recv_timeout(RESULT_DEADLINE)??,
        "the runtime ran another task while the revocation write was parked"
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert!(state
        .revocation_store()
        .map_err(|_| "revocation store")?
        .is_revoked("parked-capability")?);
    Ok(())
}

#[tokio::test]
async fn authority_rotation_leaves_the_runtime_serving() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let database = directory.path().join("authority.sqlite3");
    let before = SqliteCapabilityAuthority::open(&database)?.status()?;
    let mut state = metrics_state("service-secret");
    state.config.authority_db_path = Some(database.clone());
    let progressed = Arc::new(AtomicBool::new(false));
    let released = parked_database(&database, &progressed)?;

    let probe = spawn_progress_probe(&progressed);
    let response = handle_rotate_authority(State(state), service_headers()).await;
    probe.await?;
    assert!(
        released.recv_timeout(RESULT_DEADLINE)??,
        "the runtime ran another task while the authority rotation was parked"
    );
    assert_eq!(response.status(), StatusCode::OK);
    let after = SqliteCapabilityAuthority::open(&database)?.status()?;
    assert!(after.generation > before.generation);
    Ok(())
}
