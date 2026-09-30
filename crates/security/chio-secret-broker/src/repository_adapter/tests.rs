use super::*;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn fixture(mode: &str) -> TestResult<(tempfile::TempDir, RepositoryAdapterConfig)> {
    let directory = crate::private_tempdir()?;
    let executable = directory.path().join("repository");
    let source = format!(
        r#"#!/usr/bin/python3
import json, pathlib, sys, time
mode = {mode:?}
digest = sys.argv[-1]
state = pathlib.Path(sys.argv[sys.argv.index('--state') + 1])
def frame(value):
    body = json.dumps(value).encode()
    sys.stdout.buffer.write(len(body).to_bytes(4, 'big') + body)
    sys.stdout.buffer.flush()
frame({{'schema':'chio.repository-adapter-ready.v1','configuration_sha256':digest}})
while prefix := sys.stdin.buffer.read(4):
    body = sys.stdin.buffer.read(int.from_bytes(prefix, 'big'))
    with (state / 'effects').open('ab') as effects:
        effects.write(body + b'\n')
    if mode == 'timeout':
        time.sleep(5)
    elif mode == 'truncated':
        sys.stdout.buffer.write(b'\x00\x00\x00\x08{{')
        sys.stdout.buffer.flush()
        sys.exit(0)
    elif mode == 'oversize':
        sys.stdout.buffer.write((524289).to_bytes(4, 'big'))
        sys.stdout.buffer.flush()
    elif mode == 'duplicate':
        raw = b'{{"workspace":{{}},"workspace":{{}}}}'
        sys.stdout.buffer.write(len(raw).to_bytes(4, 'big') + raw)
        sys.stdout.buffer.flush()
    else:
        frame({{'workspace':{{'configuration_sha256':digest if mode == 'valid' else 'b'*64}}}})
"#
    );
    std::fs::write(&executable, &source)?;
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500))?;
    let config = RepositoryAdapterConfig {
        executable,
        executable_sha256: sha256_hex(source.as_bytes()),
        state: directory.path().to_path_buf(),
        configuration_sha256: "a".repeat(64),
        timeout_ms: 1000,
    };
    Ok((directory, config))
}

fn request(configuration: &str) -> Vec<u8> {
    json!({"command":"one effect","configuration_sha256":configuration})
        .to_string()
        .into_bytes()
}

#[test]
fn mismatched_workspace_is_refused_before_child_effect() -> TestResult {
    let (directory, config) = fixture("valid")?;
    let adapter = RepositoryAdapter::start(config)?;
    assert!(matches!(
        adapter.execute_json(&request(&"b".repeat(64))),
        Err(crate::BrokerError::AuthorizationDenied(_))
    ));
    assert!(!directory.path().join("effects").exists());
    assert!(matches!(
        adapter.execute_json(&request(&"a".repeat(64))),
        Err(crate::BrokerError::Upstream(_))
    ));
    assert!(!directory.path().join("effects").exists());
    Ok(())
}

#[test]
fn original_result_is_returned_and_uncertain_children_are_never_replayed() -> TestResult {
    for mode in [
        "valid",
        "timeout",
        "truncated",
        "oversize",
        "duplicate",
        "wrong",
    ] {
        let (directory, config) = fixture(mode)?;
        let adapter = RepositoryAdapter::start(config)?;
        let command = request(&"a".repeat(64));
        let result = adapter.execute_json(&command);
        if mode == "valid" {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(crate::BrokerError::Upstream(_))));
            assert!(matches!(
                adapter.execute_json(&command),
                Err(crate::BrokerError::Upstream(_))
            ));
        }
        let effects = std::fs::read(directory.path().join("effects"))?;
        assert_eq!(effects, [command, b"\n".to_vec()].concat());
    }
    Ok(())
}

#[test]
fn changed_launcher_bytes_are_refused_before_spawn() -> TestResult {
    let (directory, mut config) = fixture("valid")?;
    config.executable_sha256 = "0".repeat(64);
    assert!(matches!(
        RepositoryAdapter::start(config),
        Err(crate::BrokerError::AuthorizationDenied(_))
    ));
    assert!(!directory.path().join("effects").exists());
    Ok(())
}

#[test]
fn captured_launcher_is_sealed_and_does_not_reopen_original_path() -> TestResult {
    use std::io::{Seek, SeekFrom};
    let directory = crate::private_tempdir()?;
    let path = directory.path().join("selected");
    let source = b"#!/bin/sh\nprintf original";
    std::fs::write(&path, source)?;
    let mut sealed = launch::capture(source)?;
    std::fs::write(&path, b"#!/bin/sh\nprintf replaced")?;
    let output = launch::command(&sealed)?.output()?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"original");
    sealed.seek(SeekFrom::Start(0))?;
    assert!(
        matches!(sealed.write_all(b"changed"), Err(error) if error.raw_os_error() == Some(libc::EPERM))
    );
    assert!(matches!(sealed.set_len(0), Err(error) if error.raw_os_error() == Some(libc::EPERM)));
    Ok(())
}
