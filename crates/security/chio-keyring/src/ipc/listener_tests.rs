use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt as _;

use chio_test_support::prelude::*;

use super::bind_private_unix_listener_with;
use crate::KeyringError;

#[test]
fn a_service_socket_directory_replaced_before_bind_is_detected() {
    let directory = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .test_unwrap();
    let root = std::fs::canonicalize(directory.path()).test_unwrap();
    let run = root.join("run");
    std::fs::create_dir(&run).test_unwrap();
    std::fs::set_permissions(&run, Permissions::from_mode(0o700)).test_unwrap();
    let displaced = root.join("run.displaced");

    let result = bind_private_unix_listener_with(&run.join("witness.sock"), || {
        std::fs::rename(&run, &displaced)?;
        std::fs::create_dir(&run)?;
        std::fs::set_permissions(&run, Permissions::from_mode(0o700))
    })
    .map(drop);
    assert!(
        matches!(result, Err(KeyringError::StateInvariant(_))),
        "{result:?}"
    );
}

#[test]
fn a_peer_running_as_the_service_user_is_accepted() {
    let (client, server) = std::os::unix::net::UnixStream::pair().test_unwrap();
    super::require_service_peer(&server).test_unwrap();
    super::require_service_peer(&client).test_unwrap();
}

#[test]
fn a_peer_running_as_another_user_is_refused() {
    let (_client, server) = std::os::unix::net::UnixStream::pair().test_unwrap();
    let other_user = rustix::process::geteuid().as_raw().wrapping_add(1);
    let result = super::require_peer_uid(&server, other_user);
    assert!(
        matches!(result, Err(KeyringError::StateInvariant(_))),
        "{result:?}"
    );
}

#[test]
fn a_deadline_stream_reads_a_buffered_response_after_both_directions_close() {
    use std::io::{Read as _, Write as _};

    let (client, mut server) = std::os::unix::net::UnixStream::pair().test_unwrap();
    client.shutdown(std::net::Shutdown::Write).test_unwrap();
    server.write_all(b"response").test_unwrap();
    drop(server);
    let mut stream =
        super::DeadlineUnixStream::new(client, std::time::Duration::from_secs(5)).test_unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).test_unwrap();
    assert_eq!(response, b"response");
}
