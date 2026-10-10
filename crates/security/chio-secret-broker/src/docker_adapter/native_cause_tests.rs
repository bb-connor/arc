//! Actual pinned local socket failures, without Docker effects or syscall mocks.
use super::*;
use crate::adapter_cause_tests::{assert_public_error, native_cause, TestResult, PRIVATE};
use std::os::unix::{fs::PermissionsExt, net::UnixListener};

fn socket_fixture() -> TestResult<(tempfile::TempDir, UnixListener, DockerAdapter)> {
    let directory = crate::private_tempdir()?;
    let path = directory.path().join(format!("{PRIVATE}.sock"));
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let metadata = std::fs::symlink_metadata(&path)?;
    let adapter = DockerAdapter {
        config: DockerAdapterConfig {
            socket_path: path,
            peer: chio_secure_ipc::PeerIdentity {
                process_id: std::process::id(),
                user_id: rustix::process::geteuid().as_raw(),
                group_id: rustix::process::getegid().as_raw(),
            },
            api_version: "v1.52".into(),
            daemon_id: "engine".into(),
            container_id: "a".repeat(64),
            container_configuration_sha256: "b".repeat(64),
            container_started_at: "original-start".into(),
            timeout_ms: 1000,
            maximum_output_bytes: 1024,
        },
        socket_identity: (metadata.dev(), metadata.ino()),
    };
    Ok((directory, listener, adapter))
}

#[test]
fn broker_native_cause_docker_vanished_socket() -> TestResult {
    let (_directory, _listener, adapter) = socket_fixture()?;
    std::fs::remove_file(&adapter.config.socket_path)?;
    let error = adapter
        .connection(adapter.deadline()?)
        .err()
        .ok_or("vanished socket connected")?;
    assert_public_error(&error, "authorization_denied");
    assert_eq!(
        native_cause::<io::Error>(&error)?.kind(),
        io::ErrorKind::NotFound
    );
    let error = error.redacted();
    assert_public_error(&error, "authorization_denied");
    assert_eq!(
        native_cause::<io::Error>(&error)?.kind(),
        io::ErrorKind::NotFound
    );
    Ok(())
}

#[test]
fn broker_native_cause_docker_refused_connect() -> TestResult {
    let (_directory, listener, adapter) = socket_fixture()?;
    drop(listener);
    let error = adapter
        .connection(adapter.deadline()?)
        .err()
        .ok_or("retired listener connected")?;
    assert_public_error(&error, "upstream");
    assert_eq!(
        native_cause::<rustix::io::Errno>(&error)?.raw_os_error(),
        libc::ECONNREFUSED
    );
    let error = error.redacted();
    assert_public_error(&error, "upstream");
    assert_eq!(
        native_cause::<rustix::io::Errno>(&error)?.raw_os_error(),
        libc::ECONNREFUSED
    );
    Ok(())
}

#[test]
fn broker_native_cause_docker_peer_validation() -> TestResult {
    let (_directory, _listener, mut adapter) = socket_fixture()?;
    adapter.config.peer.process_id = 0;
    let error = DockerAdapter::new(adapter.config)
        .err()
        .ok_or("zero process ID accepted")?;
    assert_public_error(&error, "authorization_denied");
    assert!(matches!(
        native_cause::<chio_secure_ipc::SecureIpcError>(&error)?,
        chio_secure_ipc::SecureIpcError::InvalidConfig(_)
    ));
    let error = error.redacted();
    assert_public_error(&error, "authorization_denied");
    assert!(matches!(
        native_cause::<chio_secure_ipc::SecureIpcError>(&error)?,
        chio_secure_ipc::SecureIpcError::InvalidConfig(_)
    ));
    Ok(())
}

#[test]
fn broker_native_cause_docker_wrong_peer_control() -> TestResult {
    let (_directory, _listener, mut adapter) = socket_fixture()?;
    adapter.config.peer.process_id = std::process::id().checked_add(1).ok_or("PID overflow")?;
    let error = adapter
        .connection(adapter.deadline()?)
        .err()
        .ok_or("unselected peer connected")?;
    assert_public_error(&error, "authorization_denied");
    Ok(())
}

#[test]
fn broker_native_cause_docker_healthy_connection_control() -> TestResult {
    let (_directory, listener, adapter) = socket_fixture()?;
    let connection = adapter.connection(adapter.deadline()?)?;
    let (accepted, _) = listener.accept()?;
    assert_eq!(
        chio_secure_ipc::peer_identity(&connection.stream)?,
        adapter.config.peer
    );
    assert_eq!(
        chio_secure_ipc::peer_identity(&accepted)?.process_id,
        std::process::id()
    );
    Ok(())
}
