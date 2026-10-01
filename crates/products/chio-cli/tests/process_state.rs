#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::Command;

use base64::Engine;
use chio_core_types::crypto::sha256_hex;
use serde_json::{json, Value};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn retained_state_is_read_without_launch_keys_credentials_or_migration() -> Result {
    let dir = tempfile::tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    fs::write(dir.path().join("host.lock"), b"")?;
    let record = json!({"abi": chio_process::PROCESS_ABI,
        "config": {"schema": "chio.process.host.v1",
        "servers": [{"command": ["/must/not/launch"]}], "policy": "/absent"}});
    fs::write(dir.path().join("host.json"), serde_json::to_vec(&record)?)?;
    let path = dir.path().join("process.db");
    let db = rusqlite::Connection::open(&path)?;
    db.execute_batch(
        "CREATE TABLE process_runtime(singleton INTEGER, version INTEGER);
        INSERT INTO process_runtime VALUES (1,1);
        CREATE TABLE processes(id TEXT, revision INTEGER, checkpoint TEXT);
        INSERT INTO processes VALUES ('coder',9007199254740993,'{\"complete\":true}');
        CREATE TABLE process_state_blobs(process_id TEXT, sha256 TEXT, data BLOB);",
    )?;
    let bytes = b"retained result";
    let digest = sha256_hex(bytes);
    db.execute(
        "INSERT INTO process_state_blobs VALUES ('coder',?1,?2)",
        rusqlite::params![digest, bytes.as_slice()],
    )?;
    drop(db);
    for name in ["host.lock", "host.json", "process.db"] {
        fs::set_permissions(dir.path().join(name), fs::Permissions::from_mode(0o600))?;
    }
    let before = fs::read(&path)?;
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["process", "state", "--state"])
            .arg(dir.path())
            .args(["--process", "coder"])
            .args(extra)
            .output()
    };
    let response = run(&[])?;
    assert!(
        response.status.success(),
        "{}",
        String::from_utf8_lossy(&response.stderr)
    );
    let value: Value = serde_json::from_slice(&response.stdout)?;
    assert_eq!(value["data"]["checkpoint"]["revision"], "9007199254740993");
    assert_eq!(
        value["data"]["checkpoint"]["value"],
        json!({"complete": true})
    );
    let response = run(&["--blob", &digest])?;
    assert!(response.status.success());
    let value: Value = serde_json::from_slice(&response.stdout)?;
    assert_eq!(
        value["data"]["data_base64"],
        base64::engine::general_purpose::STANDARD.encode(bytes)
    );
    assert_eq!(fs::read(&path)?, before);
    assert!(!dir.path().join("process.db-wal").exists());
    let mut legacy = record.clone();
    legacy["abi"] = json!("chio.process.abi.v1");
    fs::write(dir.path().join("host.json"), serde_json::to_vec(&legacy)?)?;
    assert!(!run(&[])?.status.success());
    assert_eq!(fs::read(&path)?, before);
    fs::write(dir.path().join("host.json"), serde_json::to_vec(&record)?)?;
    fs::rename(&path, dir.path().join("actual.db"))?;
    symlink("actual.db", &path)?;
    assert!(!run(&[])?.status.success());
    fs::remove_file(&path)?;
    assert!(!run(&[])?.status.success());
    assert!(!path.exists());
    Ok(())
}
