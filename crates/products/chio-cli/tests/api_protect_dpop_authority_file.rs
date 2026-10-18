//! `chio api protect` reads its DPoP replay authority from
//! `CHIO_DPOP_REPLAY_AUTHORITY_FILE` and verifies it against the durable
//! authority store before serving.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};

const SPEC: &str = r#"{"openapi":"3.0.0","info":{"title":"dpop","version":"1"},"paths":{"/items":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#;

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn activated_descriptor(receipt_db: &Path) -> Vec<u8> {
    let mut lock_root = receipt_db.as_os_str().to_os_string();
    lock_root.push(".authority-locks");
    let lock_root = std::path::PathBuf::from(lock_root);
    private_dir(&lock_root);
    let database = lock_root.join("authority.db");
    chio_store_sqlite::SqliteAuthorityStore::provision(&database, &lock_root).unwrap();
    let clock = chio_test_support::clock::clock();
    let store = chio_store_sqlite::SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &lock_root,
        clock.clone(),
    )
    .unwrap();
    let authority = chio_control_plane::initialize_local_dpop_authority(
        &store,
        &chio_kernel::admission_operation::AdmissionIdentifier::try_new(
            "dpop_authority",
            "api-protect-dpop",
        )
        .unwrap(),
        &chio_kernel::DpopConfig::default(),
        clock,
    )
    .unwrap();
    chio_core::canonical::canonical_json_bytes(&authority).unwrap()
}

fn spawn_protect(directory: &Path, listen: &str, authority_file: &Path) -> Child {
    let spec = directory.join("openapi.json");
    std::fs::write(&spec, SPEC).unwrap();
    let seed = directory.join("authority.seed");
    std::fs::write(&seed, chio_core::crypto::Keypair::generate().seed_hex()).unwrap();
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
    Command::new(env!("CARGO_BIN_EXE_chio"))
        .env("CHIO_DPOP_REPLAY_AUTHORITY_FILE", authority_file)
        .arg("--authority-seed-file")
        .arg(&seed)
        .args([
            "api",
            "protect",
            "--upstream",
            "http://127.0.0.1:9",
            "--listen",
            listen,
        ])
        .arg("--spec")
        .arg(&spec)
        .arg("--receipt-store")
        .arg(directory.join("receipts.db"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chio api protect")
}

fn wait_for_exit_or_listen(child: &mut Child, listen: &str) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if TcpStream::connect(listen).is_ok() {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("chio api protect neither listened nor exited");
}

#[test]
fn api_protect_serves_with_an_activated_replay_authority_file() {
    if skip_when_loopback_bind_denied("api_protect_serves_with_an_activated_replay_authority_file")
    {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    private_dir(directory.path());
    let authority_file = directory.path().join("dpop-authority.json");
    std::fs::write(
        &authority_file,
        activated_descriptor(&directory.path().join("receipts.db")),
    )
    .unwrap();
    let listen = reserve_listen_addr().to_string();
    let mut child = spawn_protect(directory.path(), &listen, &authority_file);
    let exited = wait_for_exit_or_listen(&mut child, &listen);
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    assert!(
        exited.is_none(),
        "api protect exited: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn api_protect_refuses_an_invalid_replay_authority_file() {
    let directory = tempfile::tempdir().unwrap();
    private_dir(directory.path());
    let authority_file = directory.path().join("dpop-authority.json");
    std::fs::write(
        &authority_file,
        br#"{"proof_ttl_secs":300,"proof_ttl_secs":301}"#,
    )
    .unwrap();
    let listen = reserve_listen_addr().to_string();
    let mut child = spawn_protect(directory.path(), &listen, &authority_file);
    let status = wait_for_exit_or_listen(&mut child, &listen);
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        status.is_some_and(|status| !status.success()),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("urn:chio:error:attest:signed-json-invalid-input"),
        "stderr={stderr}"
    );
}
